#!/usr/bin/env python3

import email.utils
import functools
import hashlib
import io
import json
import os
import zipfile
from argparse import ArgumentParser

import boto3
from validate_email import validate_email

EXECUTABLE = os.path.basename(__file__)
CONFIG_PATH = os.path.expanduser("~/.config/lampions/config.json")

REGIONS = (
    "eu-west-1",
    "us-east-1",
    "us-west-2"
)


def die_with_message(*args):
    raise SystemExit("Error: " + "\n".join(args))


def _dict_to_formatted_json(dictionary):
    return json.dumps(dictionary, indent=2)


class Config(dict):
    REQUIRED_KEYS = ("Region", "Domain")
    VALID_KEYS = ("AccessKeyId", "SecretAccessKey", "DkimTokens")

    def __init__(self, file_path):
        super().__init__()
        self._file_path = file_path
        self._read()

    def _read(self):
        if os.path.isfile(self._file_path):
            with open(self._file_path) as f:
                try:
                    config = json.loads(f.read())
                except json.JSONDecodeError:
                    pass
                else:
                    self.update(config)
                    self.verify()

    def __setitem__(self, key, value):
        if key not in self.REQUIRED_KEYS and key not in self.VALID_KEYS:
            die_with_message(f"Invalid config key '{key}'")
        super().__setitem__(key, value)

    def __str__(self):
        return _dict_to_formatted_json(self)

    def verify(self):
        for key in self.REQUIRED_KEYS:
            if key not in self:
                die_with_message(
                    f"Lampions is not initialized yet. Call '{EXECUTABLE} "
                    "init' first.")
        for key in self.keys():
            if key not in self.REQUIRED_KEYS and key not in self.VALID_KEYS:
                die_with_message(f"Invalid key '{key}' in config")

    def save(self):
        self.verify()
        config_directory = os.path.dirname(self._file_path)
        os.makedirs(config_directory, exist_ok=True)
        with open(self._file_path, "w") as f:
            f.write(str(self))
        os.chmod(self._file_path, 0o600)


class Lampions:
    def __init__(self):
        self._config = None

    def requires_config(self, function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            if self._config is None:
                self._config = config = Config(CONFIG_PATH)
            else:
                config = self._config
            config.verify()
            return function(config, *args, **kwargs)
        return wrapper


lampions = Lampions()


def _get_account_id():
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def _create_lampions_name_prefix(domain):
    return "Lampions" + "".join(map(str.capitalize, domain.split(".")))


@lampions.requires_config
def create_s3_bucket(config, args):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    s3 = boto3.client("s3", region_name=region)
    try:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region})
    except (s3.exceptions.BucketAlreadyExists,
            s3.exceptions.BucketAlreadyOwnedByYou):
        pass
    except Exception as exception:
        die_with_message(f"Failed to create bucket '{bucket}':",
                         str(exception))

    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={
        "Status": "Enabled"
    })

    name_prefix = _create_lampions_name_prefix(domain)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"{name_prefix}SesS3Put",
                "Effect": "Allow",
                "Principal": {
                    "Service": "ses.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/inbox/*",
                "Condition": {
                    "StringEquals": {
                        "aws:Referer": _get_account_id()
                    }
                }
            }
        ]
    }
    policy_document = json.dumps(policy)
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=policy_document)
    except Exception as exception:
        die_with_message(f"Failed to attach policy to bucket '{bucket}':",
                         str(exception))
    print(f"Created S3 bucket '{bucket}")


def _create_routes_file_policy(domain, bucket):
    """Create policy for the routes file.

    Create a policy that allows reading and writing to the ``routes.json`` file
    inside the S3 bucket ``bucket``.

    Returns:
    --------
    arn : str
        The arn of the policy.
    """
    name_prefix = _create_lampions_name_prefix(domain)
    policy_name = f"{name_prefix}RoutesFilePolicy"
    name_prefix = _create_lampions_name_prefix(domain)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"{name_prefix}S3ListBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket}"
            },
            {
                "Sid": f"{name_prefix}S3GetPutRoutes",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": f"arn:aws:s3:::{bucket}/routes.json",
            }
        ]
    }
    policy_document = json.dumps(policy)
    iam = boto3.client("iam")
    try:
        policy = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document)
    except iam.exceptions.EntityAlreadyExistsException:
        account_id = _get_account_id()
        arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    except Exception as exception:
        die_with_message(f"Failed to create routes file policy:",
                         str(exception))
    else:
        arn = policy["Policy"]["Arn"]
    return arn


@lampions.requires_config
def create_route_user(config, args):
    if config.get("AccessKeyId") and config.get("SecretAccessKey"):
        print("Route user and access key already exist")
        return

    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    policy_arn = _create_routes_file_policy(domain, bucket)
    name_prefix = _create_lampions_name_prefix(domain)
    user_name = f"{name_prefix}RouteUser"
    iam = boto3.client("iam")
    try:
        iam.create_user(UserName=user_name)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    except Exception as exception:
        die_with_message(f"Failed to create route user '{user_name}':",
                         str(exception))

    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)

    try:
        access_key = iam.create_access_key(UserName=user_name)
    except Exception as exception:
        die_with_message(
            f"Failed to create access key for user '{user_name}':",
            str(exception))

    key = access_key["AccessKey"]
    config["AccessKeyId"] = key["AccessKeyId"]
    config["SecretAccessKey"] = key["SecretAccessKey"]
    config.save()

    print(f"User '{user_name}' and access keys created. To view the keys, "
          "use '{EXECUTABLE} show-config'.")


@lampions.requires_config
def verify_domain(config, args):
    region = config["Region"]
    domain = config["Domain"]

    ses = boto3.client("ses", region_name=region)
    dkim_tokens = ses.verify_domain_dkim(Domain=domain)
    del dkim_tokens["ResponseMetadata"]
    config.update(dkim_tokens)
    config.save()

    print(f"DKIM tokens for domain '{domain}' created:\n")
    for token in config["DkimTokens"]:
        print(f"  {token}")
    print()
    print("For each token, add a CNAME record of the form\n\n"
          "  Name                         Value\n"
          "  <token>._domainkey.<domain>  <token>.dkim.amazonses.com.\n\n"
          f"to the DNS settings of the domain '{domain}'.")
    print()
    print("To configure the domain for receiving, also make sure to add an MX "
          "record with\n\n"
          f"  inbound-smtp.{region}.amazonaws.com\n\n"
          "to the DNS settings.")


def _create_lambda_function_role(region, domain, bucket):
    account_id = _get_account_id()
    name_prefix = _create_lampions_name_prefix(domain)
    policy_name = f"{name_prefix}LambdaRolePolicy"
    name_prefix = _create_lampions_name_prefix(domain)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"{name_prefix}LambdaFunctionCloudwatch",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionS3ListBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket}"
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionS3GetBucket",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*"
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionSesSendMail",
                "Effect": "Allow",
                "Action": "ses:SendRawEmail",
                "Resource": f"arn:aws:ses:{region}:{account_id}:identity/*"
            }
        ]
    }
    policy_document = json.dumps(policy)

    iam = boto3.client("iam")
    try:
        policy = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document)
    except iam.exceptions.EntityAlreadyExistsException:
        policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    else:
        policy_arn = policy["Policy"]["Arn"]

    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    assume_policy_document = json.dumps(assume_policy)

    role_name = f"{name_prefix}LambdaFunctionRole"
    try:
        role = iam.create_role(RoleName=role_name,
                               AssumeRolePolicyDocument=assume_policy_document)
    except iam.exceptions.EntityAlreadyExistsException:
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    else:
        role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _put_object_zip(file_path, region, bucket):
    byte_stream = io.BytesIO()
    filename = os.path.basename(file_path)
    with zipfile.ZipFile(byte_stream, mode="a") as archive:
        with open(file_path, "rb") as f:
            info = zipfile.ZipInfo(filename)
            info.external_attr = 0o644 << 16
            archive.writestr(info, f.read())
    byte_stream.seek(0)

    zip_filename = f"{os.path.splitext(filename)[0]}.zip"
    s3 = boto3.client("s3", region_name=region)
    s3.upload_fileobj(
        byte_stream,
        Bucket=bucket,
        Key=zip_filename)
    return zip_filename


@lampions.requires_config
def create_receipt_rule(config, args):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    # Create policy for the Lambda function.
    role_arn = _create_lambda_function_role(region, domain, bucket)

    # Upload the code of the Lambda function to the Lampions bucket.
    directory = os.path.realpath(os.path.dirname(__file__))
    lambda_function_basename = "lampions_lambda_function"
    lambda_function_filename = _put_object_zip(
        os.path.join(directory, "src", f"{lambda_function_basename}.py"),
        region, bucket)

    # Create the Lambda function.
    name_prefix = _create_lampions_name_prefix(domain)
    function_name = f"{name_prefix}LambdaFunction"
    lambda_ = boto3.client("lambda", region_name=region)
    try:
        lambda_function = lambda_.create_function(
            FunctionName=function_name,
            Runtime="python3.7",
            Handler=f"{lambda_function_basename}.handler",
            Code={
                "S3Bucket": bucket,
                "S3Key": lambda_function_filename
            },
            Role=role_arn,
            Environment={
                "Variables": {
                    "LAMPIONS_DOMAIN": domain,
                    "LAMPIONS_REGION": region
                }
            },
            Timeout=30)
    except lambda_.exceptions.ResourceConflictException:
        lambda_function = lambda_.update_function_code(
            FunctionName=function_name,
            S3Bucket=bucket,
            S3Key=lambda_function_filename)
        function_arn = lambda_function["FunctionArn"]
    else:
        function_arn = lambda_function["FunctionArn"]

    # Add permission to the Lambda function, granting SES invocation
    # privileges.
    try:
        lambda_.add_permission(
            FunctionName=function_name,
            StatementId=f"{name_prefix}SesLambdaInvokeFunction",
            Action="lambda:InvokeFunction",
            Principal="ses.amazonaws.com")
    except lambda_.exceptions.ResourceConflictException:
        pass

    rule_set_name = f"{name_prefix}ReceiptRuleSet"
    ses = boto3.client("ses", region_name=region)
    try:
        ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    except ses.exceptions.AlreadyExistsException:
        pass

    rule = {
        "Name": f"{name_prefix}ReceiptRule",
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [domain],
        "ScanEnabled": False,
        "Actions": [
            {
                "S3Action": {
                    "BucketName": bucket,
                    "ObjectKeyPrefix": "inbox"
                }
            },
            {
                "LambdaAction": {
                    "FunctionArn": function_arn,
                    "InvocationType": "Event"
                }
            }
        ]
    }
    try:
        ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=rule)
    except ses.exceptions.AlreadyExistsException:
        pass
    ses.set_active_receipt_rule_set(RuleSetName=rule_set_name)

    print("Receipt rule created")


@lampions.requires_config
def configure_lampions(config, args):
    steps = [
        ("Creating S3 bucket", create_s3_bucket),
        ("Creating route user", create_route_user),
        ("Registering domain with SES", verify_domain),
        ("Creating receipt rule", create_receipt_rule)
    ]
    for i, (description, step) in enumerate(steps, start=1):
        print(f"Step {i}: {description}")
        step(args)
        print()


def initialize_config(args):
    domain = args["domain"]
    if not validate_email(f"art.vandelay@{domain}"):
        die_with_message(f"Invalid domain name '{domain}'")

    config = Config(CONFIG_PATH)
    config["Region"] = args["region"]
    config["Domain"] = domain
    config.save()


@lampions.requires_config
def print_config(config, args):
    print(str(config))


@lampions.requires_config
def add_forward_address(config, args):
    region = config["Region"]
    address = args["address"]

    if not validate_email(address):
        die_with_message(f"Invalid email address '{address}'")

    ses = boto3.client("ses", region_name=region)
    try:
        ses.verify_email_identity(EmailAddress=address)
    except ses.exceptions.ClientError as exception:
        die_with_message("Failed to add address to verification list:",
                         str(exception))
    else:
        print(f"Verification mail sent to '{address}'")


def _get_routes(config):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    s3 = boto3.client("s3", region_name=region)
    response = s3.get_object(Bucket=bucket, Key="routes.json")
    data = response["Body"].read()
    try:
        result = json.loads(data)
    except json.JSONDecodeError:
        routes = []
    else:
        routes = result["routes"]
    return routes


def _set_routes(config, routes):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    routes_string = _dict_to_formatted_json({"routes": routes})
    s3 = boto3.client("s3", region_name=region)
    s3.put_object(Bucket=bucket, Key="routes.json", Body=routes_string)


@lampions.requires_config
def list_routes(config, args):
    domain = config["Domain"]
    only_active = args["active"]
    only_inactive = args["inactive"]

    routes = _get_routes(config)
    column_widths = {
        "alias": 0,
        "forward": 0
    }
    for route in routes:
        for key in column_widths.keys():
            column_widths[key] = max(len(route[key]), column_widths[key])
    column_widths["alias"] += len(f"@{domain}")

    def pad_with_spaces(string, num_characters=-1):
        if num_characters == -1:
            num_characters = len(string)
        return string + " " * (num_characters + 4 - len(string))

    print(pad_with_spaces("Address", column_widths["alias"]) +
          pad_with_spaces("Forward", column_widths["forward"]) +
          pad_with_spaces("Active"))
    print(pad_with_spaces("-------", column_widths["alias"]) +
          pad_with_spaces("-------", column_widths["forward"]) +
          pad_with_spaces("------"))

    for route in routes:
        active = route["active"]
        if only_active and not active:
            continue
        if only_inactive and active:
            continue
        alias = route["alias"]
        forward_address = route["forward"]
        print(pad_with_spaces(f"{alias}@{domain}", column_widths["alias"]) +
              pad_with_spaces(forward_address, column_widths["forward"]) +
              pad_with_spaces(f"{'✓' if active else '✗'}"))
    print()


def _verify_forward_address(config, forward_address):
    if not validate_email(forward_address):
        die_with_message(f"Invalid email address '{forward_address}'")

    region = config["Region"]

    ses = boto3.client("ses", region_name=region)
    result = ses.list_identities()
    forward_addresses = filter(validate_email, result["Identities"])
    if forward_address not in forward_addresses:
        die_with_message(
            f"Forwarding address '{forward_address}' is not verified")


@lampions.requires_config
def add_route(config, args):
    alias = args["alias"]
    forward_address = args["forward"]
    active = not args["inactive"]
    meta = args["meta"]

    routes = _get_routes(config)
    for route in routes:
        if alias == route["alias"]:
            die_with_message(f"Route for alias '{alias}' already exists")

    _verify_forward_address(config, forward_address)

    created_at = email.utils.formatdate(usegmt=True)
    route_string = f"{alias}-{forward_address}-{created_at}"
    hash = hashlib.sha224()
    hash.update(route_string.encode("utf8"))
    id_ = hash.hexdigest()
    route = {
        "id": id_,
        "active": active,
        "alias": alias,
        "forward": forward_address,
        "createdAt": created_at,
        "meta": meta
    }
    routes.insert(0, route)
    _set_routes(config, routes)
    print(f"Route for alias '{alias}' added")


@lampions.requires_config
def update_route(config, args):
    alias = args["alias"]
    forward_address = args["forward"]
    active = args["active"]
    inactive = args["inactive"]
    meta = args["meta"]

    routes = _get_routes(config)
    for route in routes:
        if alias == route["alias"]:
            break
    else:
        die_with_message(f"No route with alias '{alias}' found")

    if not forward_address and not active and not inactive and not meta:
        raise SystemExit("Nothing to do")

    if forward_address:
        _verify_forward_address(config, forward_address)

    if active:
        new_active = True
    elif inactive:
        new_active = False
    else:
        new_active = route["active"]
    route["active"] = new_active
    route["forward"] = forward_address or route["forward"]
    route["meta"] = meta or route["meta"]
    _set_routes(config, routes)
    print(f"Route for alias '{alias}' updated")


@lampions.requires_config
def remove_route(config, args):
    alias = args["alias"]

    routes = _get_routes(config)
    for i, route in enumerate(routes):
        if alias == route["alias"]:
            break
    else:
        die_with_message(f"No route found for alias '{alias}'")

    routes.pop(i)
    _set_routes(config, routes)
    print(f"Route for alias '{alias}' removed")


def parse_arguments():
    parser = ArgumentParser()
    commands = parser.add_subparsers(title="Subcommands", dest="command",
                                     required=True)

    # Command 'init'
    init_parser = commands.add_parser(
        "init", help="Initialize the Lampion config")
    init_parser.set_defaults(command=initialize_config)
    init_parser.add_argument(
        "--region", help="The AWS region in which all resources are created",
        required=True, choices=REGIONS)
    init_parser.add_argument("--domain", help="The domain name", required=True)

    # Command 'show-config'
    show_config_parser = commands.add_parser(
        "show-config", help="Print the configuration file")
    show_config_parser.set_defaults(command=print_config)

    # Command 'configure'
    configure_parser = commands.add_parser(
        "configure", help="Configure AWS infrastructure for Lampions")
    configure_parser.set_defaults(command=configure_lampions)
    configure_command = configure_parser.add_subparsers(
        title="configure")

    # Subcommand 'configure create-bucket'
    bucket_parser = configure_command.add_parser(
        "create-bucket", help="Create an S3 bucket to store route information "
        "and incoming emails in")
    bucket_parser.set_defaults(command=create_s3_bucket)

    # Subcommand 'configure create-route-user'
    user_parser = configure_command.add_parser(
        "create-route-user", help="Create an AWS user with permission to read "
        "and write to the routes file")
    user_parser.set_defaults(command=create_route_user)

    # Subcommand 'configure verify-domain'
    domain_parser = configure_command.add_parser(
        "verify-domain", help="Add a domain to Amazon SES and begin the "
        "verification process")
    domain_parser.set_defaults(command=verify_domain)

    # Subcommand 'configure create-receipt-rule'
    receipt_rule_parser = configure_command.add_parser(
        "create-receipt-rule",
        help="Install receipt rule which saves incoming emails in S3 and "
        "triggers a Lambda function to forward emails")
    receipt_rule_parser.set_defaults(command=create_receipt_rule)

    # Command 'add-forward-address'
    forward_parser = commands.add_parser(
        "add-forward-address",
        help="Add address to the list of possible forward addresses")
    forward_parser.set_defaults(command=add_forward_address)
    forward_parser.add_argument(
        "--address", help="Email address to add to the verification list",
        required=True)

    list_routes_command = commands.add_parser(
        "list-routes", help="List defined email routes")
    list_routes_command.set_defaults(command=list_routes)
    group = list_routes_command.add_mutually_exclusive_group()
    group.add_argument("--active", help="List only active routes",
                       action="store_true")
    group.add_argument("--inactive", help="List only inactive routes",
                       action="store_true")

    add_route_command = commands.add_parser("add-route", help="Add new route")
    add_route_command.set_defaults(command=add_route)
    add_route_command.add_argument(
        "--alias", help="Alias (or username) of the new address",
        required=True)
    add_route_command.add_argument(
        "--forward",
        help="The address to forward emails to (must be a verified address)",
        required=True)
    add_route_command.add_argument(
        "--inactive", help="Make the route inactive by default",
        action="store_true", default=False)
    add_route_command.add_argument(
        "--meta",
        help="Freeform metadata (comment) to store alongside an alias",
        default="")

    update_route_command = commands.add_parser(
        "update-route", help="Modify route configuration")
    update_route_command.set_defaults(command=update_route)
    update_route_command.add_argument(
        "--alias", help="The alias of the route to modify", required=True)
    group = update_route_command.add_mutually_exclusive_group()
    group.add_argument(
        "--active", help="Make the route active", action="store_true")
    group.add_argument(
        "--inactive", help="Make the route inactive", action="store_true")
    update_route_command.add_argument(
        "--forward", help="New forwarding addresss", default="")
    update_route_command.add_argument(
        "--meta", help="New metadata information", default="")

    remove_route_command = commands.add_parser(
        "remove-route", help="Remove a route")
    remove_route_command.set_defaults(command=remove_route)
    remove_route_command.add_argument(
        "--alias", help="Alias (or username) of the route to remove",
        required=True)

    args = vars(parser.parse_args())
    return {key: value for key, value in args.items() if value is not None}


if __name__ == "__main__":
    args = parse_arguments()
    args["command"](args)
