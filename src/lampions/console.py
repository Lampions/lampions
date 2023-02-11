import email.utils
import functools
import io
import json
import zipfile
from argparse import ArgumentParser
from pathlib import Path
from pydoc import pager

import boto3
from validate_email import validate_email

from . import utils

EXECUTABLE = Path(__file__).name
CONFIG_PATH = Path("~/.config/lampions/config.json").expanduser()

REGIONS = ("eu-west-1", "us-east-1", "us-west-2")


def quit_with_message(*args, use_pager=False):
    text = "\n".join(args)
    if use_pager:
        pager(text)
    else:
        print(text)
    raise SystemExit


def die_with_message(*args):
    raise SystemExit("Error: " + "\n".join(args))


class Config(dict):
    REQUIRED_KEYS = ("Region", "Domain")
    VALID_KEYS = ("AccessKeyId", "SecretAccessKey", "DkimTokens")

    def __init__(self, file_path):
        super().__init__()
        self.file_path = Path(file_path)
        self.read()

    def read(self):
        if self.file_path.is_file():
            with open(self.file_path) as f:
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
        return utils.dict_to_formatted_json(self)

    def verify(self):
        for key in self.REQUIRED_KEYS:
            if key not in self:
                die_with_message(
                    f"Lampions is not initialized yet. Call '{EXECUTABLE} "
                    "init' first."
                )
        for key in self.keys():
            if key not in self.REQUIRED_KEYS and key not in self.VALID_KEYS:
                die_with_message(f"Invalid key '{key}' in config")

    def save(self):
        self.verify()
        config_directory = self.file_path.parent
        config_directory.mkdir(parents=True, exist_ok=True)
        self.file_path.write_text(str(self))
        self.file_path.chmod(0o600)


class Lampions:
    def __init__(self):
        self.config = None

    def requires_config(self, function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            if self.config is None:
                self.config = config = Config(CONFIG_PATH)
            else:
                config = self.config
            config.verify()
            return function(config, *args, **kwargs)

        return wrapper


lampions = Lampions()


def get_account_id():
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def create_lampions_name_prefix(domain):
    return "Lampions" + "".join(map(str.capitalize, domain.split(".")))


@lampions.requires_config
def create_s3_bucket(config, _):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    s3 = boto3.client("s3", region_name=region)
    try:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    except (
        s3.exceptions.BucketAlreadyExists,
        s3.exceptions.BucketAlreadyOwnedByYou,
    ):
        pass
    except Exception as exception:
        die_with_message(
            f"Failed to create bucket '{bucket}':", str(exception)
        )

    s3.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )

    name_prefix = create_lampions_name_prefix(domain)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"{name_prefix}SesS3Put",
                "Effect": "Allow",
                "Principal": {"Service": "ses.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/inbox/*",
                "Condition": {
                    "StringEquals": {"aws:Referer": get_account_id()}
                },
            }
        ],
    }
    policy_document = json.dumps(policy)
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=policy_document)
    except Exception as exception:
        die_with_message(
            f"Failed to attach policy to bucket '{bucket}':", str(exception)
        )
    print(f"Created S3 bucket '{bucket}")


def create_routes_and_recipients_file_policy(domain, bucket):
    """Create policy for the routes file.

    Create a policy that allows reading and writing to the ``routes.json`` and
    ``recipients.json`` files inside the S3 bucket ``bucket``.

    Returns:
    --------
    arn : str
        The arn of the policy.
    """
    name_prefix = create_lampions_name_prefix(domain)
    policy_name = f"{name_prefix}RoutesAndRecipientsFilePolicy"
    name_prefix = create_lampions_name_prefix(domain)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"{name_prefix}S3ListBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": f"{name_prefix}S3GetPutRoutes",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": [
                    f"arn:aws:s3:::{bucket}/routes.json",
                    f"arn:aws:s3:::{bucket}/recipients.json",
                ],
            },
        ],
    }
    policy_document = json.dumps(policy)
    iam = boto3.client("iam")
    try:
        policy = iam.create_policy(
            PolicyName=policy_name, PolicyDocument=policy_document
        )
    except iam.exceptions.EntityAlreadyExistsException:
        account_id = get_account_id()
        arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    except Exception as exception:
        die_with_message(
            "Failed to create routes and recipient file policy:",
            str(exception),
        )
    else:
        arn = policy["Policy"]["Arn"]
    return arn


@lampions.requires_config
def create_route_user(config, _):
    if config.get("AccessKeyId") and config.get("SecretAccessKey"):
        print("Route user and access key already exist")
        return

    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    policy_arn = create_routes_and_recipients_file_policy(domain, bucket)
    name_prefix = create_lampions_name_prefix(domain)
    user_name = f"{name_prefix}RouteUser"
    iam = boto3.client("iam")
    try:
        iam.create_user(UserName=user_name)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    except Exception as exception:
        die_with_message(
            f"Failed to create route user '{user_name}':", str(exception)
        )

    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)

    try:
        access_key = iam.create_access_key(UserName=user_name)
    except Exception as exception:
        die_with_message(
            f"Failed to create access key for user '{user_name}':",
            str(exception),
        )

    key = access_key["AccessKey"]
    config["AccessKeyId"] = key["AccessKeyId"]
    config["SecretAccessKey"] = key["SecretAccessKey"]
    config.save()

    print(
        f"User '{user_name}' and access keys created. To view the keys, "
        "use '{EXECUTABLE} show-config'."
    )


@lampions.requires_config
def verify_domain(config, _):
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
    print(
        "For each token, add a CNAME record of the form\n\n"
        "  Name                         Value\n"
        "  <token>._domainkey.<domain>  <token>.dkim.amazonses.com\n\n"
        f"to the DNS settings of the domain '{domain}'. Note that the "
        "'.<domain>' part\nneeds to be omitted with some DNS providers."
    )
    print()
    print(
        "To configure the domain for receiving, also make sure to add an MX "
        "record with\n\n"
        f"  inbound-smtp.{region}.amazonaws.com\n\n"
        "to the DNS settings."
    )


def create_lambda_function_role(region, domain, bucket):
    account_id = get_account_id()
    name_prefix = create_lampions_name_prefix(domain)
    policy_name = f"{name_prefix}LambdaRolePolicy"
    name_prefix = create_lampions_name_prefix(domain)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"{name_prefix}LambdaFunctionCloudwatch",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionS3ListBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionS3GetBucket",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionS3WriteRecipients",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/recipients.json",
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionSesListIdentities",
                "Effect": "Allow",
                "Action": "ses:ListIdentities",
                "Resource": "*",
            },
            {
                "Sid": f"{name_prefix}LambdaFunctionSesSendMail",
                "Effect": "Allow",
                "Action": "ses:SendRawEmail",
                "Resource": f"arn:aws:ses:{region}:{account_id}:identity/*",
            },
        ],
    }
    policy_document = json.dumps(policy)

    iam = boto3.client("iam")
    try:
        policy = iam.create_policy(
            PolicyName=policy_name, PolicyDocument=policy_document
        )
    except iam.exceptions.EntityAlreadyExistsException:
        policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    else:
        policy_arn = policy["Policy"]["Arn"]

    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    assume_policy_document = json.dumps(assume_policy)

    role_name = f"{name_prefix}LambdaFunctionRole"
    try:
        role = iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=assume_policy_document
        )
    except iam.exceptions.EntityAlreadyExistsException:
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    else:
        role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def put_objects_zip(file_paths, zip_filename, region, bucket):
    byte_stream = io.BytesIO()
    with zipfile.ZipFile(byte_stream, mode="a") as archive:
        for file_path in file_paths:
            filename = Path(file_path).name
            with open(file_path, "rb") as f:
                info = zipfile.ZipInfo(filename)
                info.external_attr = 0o644 << 16
                archive.writestr(info, f.read())
    byte_stream.seek(0)

    s3 = boto3.client("s3", region_name=region)
    s3.upload_fileobj(byte_stream, Bucket=bucket, Key=zip_filename)
    return zip_filename


@lampions.requires_config
def create_receipt_rule(config, _):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    # Create policy for the Lambda function.
    role_arn = create_lambda_function_role(region, domain, bucket)

    # Upload the code of the Lambda function to the Lampions bucket.
    directory = Path(__file__).resolve().parent
    lambda_function_basename = "lambda"
    lambda_files = [
        directory / "src" / filename
        for filename in [f"{lambda_function_basename}.py", "utils.py"]
    ]
    lambda_function_filename = put_objects_zip(
        lambda_files, "{lambda_function_basename}.zip", region, bucket
    )

    # Create the Lambda function.
    name_prefix = create_lampions_name_prefix(domain)
    function_name = f"{name_prefix}LambdaFunction"
    lambda_ = boto3.client("lambda", region_name=region)
    try:
        lambda_function = lambda_.create_function(
            FunctionName=function_name,
            Runtime="python3.7",
            Handler=f"{lambda_function_basename}.handler",
            Code={"S3Bucket": bucket, "S3Key": lambda_function_filename},
            Role=role_arn,
            Environment={
                "Variables": {
                    "LAMPIONS_DOMAIN": domain,
                    "LAMPIONS_REGION": region,
                }
            },
            Timeout=30,
        )
    except lambda_.exceptions.ResourceConflictException:
        lambda_function = lambda_.update_function_code(
            FunctionName=function_name,
            S3Bucket=bucket,
            S3Key=lambda_function_filename,
        )
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
            Principal="ses.amazonaws.com",
        )
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
            {"S3Action": {"BucketName": bucket, "ObjectKeyPrefix": "inbox"}},
            {
                "LambdaAction": {
                    "FunctionArn": function_arn,
                    "InvocationType": "Event",
                }
            },
        ],
    }
    try:
        ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=rule)
    except ses.exceptions.AlreadyExistsException:
        pass
    ses.set_active_receipt_rule_set(RuleSetName=rule_set_name)

    print("Receipt rule created")


@lampions.requires_config
def configure_lampions(_, args):
    steps = [
        ("Creating S3 bucket", create_s3_bucket),
        ("Creating route user", create_route_user),
        ("Registering domain with SES", verify_domain),
        ("Creating receipt rule", create_receipt_rule),
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
def print_config(config, _):
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
        die_with_message(
            "Failed to add address to verification list:", str(exception)
        )
    else:
        print(f"Verification mail sent to '{address}'")


def get_routes(config):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    s3 = boto3.client("s3", region_name=region)
    try:
        response = s3.get_object(Bucket=bucket, Key="routes.json")
    except s3.exceptions.NoSuchKey:
        quit_with_message("No routes defined yet")
    data = response["Body"].read()
    try:
        result = json.loads(data)
    except json.JSONDecodeError:
        routes = []
    else:
        routes = result["routes"]
    return routes


def set_routes(config, routes):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    routes_string = utils.dict_to_formatted_json({"routes": routes})
    s3 = boto3.client("s3", region_name=region)
    s3.put_object(Bucket=bucket, Key="routes.json", Body=routes_string)


@lampions.requires_config
def list_routes(config, args):
    domain = config["Domain"]
    only_active = args["active"]
    only_inactive = args["inactive"]

    routes = get_routes(config)
    column_widths = {"alias": 0, "forward": 0}
    for route in routes:
        for key in column_widths.keys():
            column_widths[key] = max(len(route[key]), column_widths[key])
    column_widths["alias"] += len(f"@{domain}")

    def pad_with_spaces(string, num_characters=-1):
        if num_characters == -1:
            num_characters = len(string)
        return string + " " * (num_characters + 4 - len(string))

    stream = io.StringIO()
    print(
        pad_with_spaces("Address", column_widths["alias"])
        + pad_with_spaces("Forward", column_widths["forward"])
        + pad_with_spaces("Active"),
        file=stream,
    )
    print(
        pad_with_spaces("-------", column_widths["alias"])
        + pad_with_spaces("-------", column_widths["forward"])
        + pad_with_spaces("------"),
        file=stream,
    )

    for route in routes:
        active = route["active"]
        if only_active and not active:
            continue
        if only_inactive and active:
            continue
        alias = route["alias"]
        forward_address = route["forward"]
        print(
            pad_with_spaces(f"{alias}@{domain}", column_widths["alias"])
            + pad_with_spaces(forward_address, column_widths["forward"])
            + pad_with_spaces(f"  {'✓' if active else '✗'}"),
            file=stream,
        )
    quit_with_message(stream.getvalue(), use_pager=True)


def verify_forward_address(config, forward_address):
    if not validate_email(forward_address):
        die_with_message(f"Invalid email address '{forward_address}'")

    region = config["Region"]

    ses = boto3.client("ses", region_name=region)
    result = ses.list_identities()
    forward_addresses = filter(validate_email, result["Identities"])
    if forward_address not in forward_addresses:
        die_with_message(
            f"Forwarding address '{forward_address}' is not verified"
        )


@lampions.requires_config
def add_route(config, args):
    domain = config["Domain"]
    alias = args["alias"]
    forward_address = args["forward"]
    active = not args["inactive"]
    meta = args["meta"]

    routes = get_routes(config)
    for route in routes:
        if alias == route["alias"]:
            die_with_message(f"Route for alias '{alias}' already exists")

    if " " in alias or not validate_email(f"{alias}@{domain}"):
        die_with_message(f"Invalid alias '{alias}'")
    verify_forward_address(config, forward_address)

    created_at = email.utils.formatdate(usegmt=True)
    route_string = f"{alias}-{forward_address}-{created_at}"
    id_ = utils.compute_sha224_hash(route_string)
    route = {
        "id": id_,
        "active": active,
        "alias": alias,
        "forward": forward_address,
        "createdAt": created_at,
        "meta": meta,
    }
    routes.insert(0, route)
    set_routes(config, routes)
    print(f"Route for alias '{alias}' added")


@lampions.requires_config
def update_route(config, args):
    alias = args["alias"]
    forward_address = args["forward"]
    active = args["active"]
    inactive = args["inactive"]
    meta = args["meta"]

    routes = get_routes(config)
    for route in routes:
        if alias == route["alias"]:
            break
    else:
        die_with_message(f"No route with alias '{alias}' found")

    if not forward_address and not active and not inactive and not meta:
        quit_with_message("Nothing to do")

    if forward_address:
        verify_forward_address(config, forward_address)

    if active:
        new_active = True
    elif inactive:
        new_active = False
    else:
        new_active = route["active"]
    route["active"] = new_active
    route["forward"] = forward_address or route["forward"]
    route["meta"] = meta or route["meta"]
    set_routes(config, routes)
    print(f"Route for alias '{alias}' updated")


@lampions.requires_config
def remove_route(config, args):
    alias = args["alias"]

    routes = get_routes(config)
    for route in routes:
        if alias == route["alias"]:
            break
    else:
        die_with_message(f"No route found for alias '{alias}'")

    routes.pop(routes.index(route))
    set_routes(config, routes)
    print(f"Route for alias '{alias}' removed")


def resolve_forward_addresses(hash_address_mapping, domain):
    addresses = {}
    for alias, recipients_for_alias in hash_address_mapping.items():
        recipients = {}
        for address_hash, recipient in recipients_for_alias.items():
            recipients[
                utils.format_address(alias, address_hash, domain)
            ] = recipient
        addresses[alias] = recipients
    return addresses


@lampions.requires_config
def list_recipients(config, args):
    region = config["Region"]
    domain = config["Domain"]
    bucket = f"lampions.{domain}"

    alias = args.get("alias")
    address = args.get("address")

    s3 = boto3.client("s3", region_name=region)
    try:
        response = s3.get_object(Bucket=bucket, Key="recipients.json")
    except s3.exceptions.NoSuchKey:
        quit_with_message("No recipient mapping defined yet")
    data = response["Body"].read()
    try:
        result = json.loads(data)
    except json.JSONDecodeError:
        recipients = {}
    else:
        recipients = result["recipients"]

    if alias is not None:
        recipients_for_alias = recipients.get(alias)
        if recipients_for_alias is None:
            quit_with_message(f"No recipients for alias '{alias}' defined yet")
        addresses = resolve_forward_addresses(
            {alias: recipients_for_alias}, domain
        )
        quit_with_message(
            utils.dict_to_formatted_json(addresses), use_pager=True
        )

    if address is not None:
        try:
            name, forward_domain = address.split("@")
        except ValueError:
            die_with_message(f"Invalid address '{address}'")
        if forward_domain != domain:
            die_with_message(f"Invalid domain '{forward_domain}'")

        try:
            alias, address_hash = name.split("+")
        except ValueError:
            die_with_message(
                "Invalid address. Must be of the form "
                "'<alias>+<address_hash>@<domain>'."
            )
        recipients_for_alias = recipients.get(alias)
        if recipients_for_alias is None:
            quit_with_message(f"No recipients for alias '{alias}' defined yet")
        recipient = recipients_for_alias.get(address_hash)
        if recipient is None:
            die_with_message(
                f"Failed to resolve recipient for address '{address}'"
            )
        quit_with_message(f"{address}  →  {recipient}", use_pager=True)

    # Neither alias nor address given, so print all recipients.
    addresses = resolve_forward_addresses(recipients, domain)
    quit_with_message(utils.dict_to_formatted_json(addresses), use_pager=True)


def parse_arguments():
    parser = ArgumentParser("lampions")
    commands = parser.add_subparsers(
        title="Subcommands", dest="command", required=True
    )

    # Command 'init'
    init_parser = commands.add_parser(
        "init", help="Initialize the Lampion config"
    )
    init_parser.set_defaults(command=initialize_config)
    init_parser.add_argument(
        "--region",
        help="The AWS region in which all resources are created",
        required=True,
        choices=REGIONS,
    )
    init_parser.add_argument("--domain", help="The domain name", required=True)

    # Command 'show-config'
    show_config_parser = commands.add_parser(
        "show-config", help="Print the configuration file"
    )
    show_config_parser.set_defaults(command=print_config)

    # Command 'configure'
    configure_parser = commands.add_parser(
        "configure", help="Configure AWS infrastructure for Lampions"
    )
    configure_parser.set_defaults(command=configure_lampions)
    configure_command = configure_parser.add_subparsers(title="configure")

    # Subcommand 'configure create-bucket'
    bucket_parser = configure_command.add_parser(
        "create-bucket",
        help=(
            "Create an S3 bucket to store route information "
            "and incoming emails in"
        ),
    )
    bucket_parser.set_defaults(command=create_s3_bucket)

    # Subcommand 'configure create-route-user'
    user_parser = configure_command.add_parser(
        "create-route-user",
        help=(
            "Create an AWS user with permission to read "
            "and write to the routes file"
        ),
    )
    user_parser.set_defaults(command=create_route_user)

    # Subcommand 'configure verify-domain'
    domain_parser = configure_command.add_parser(
        "verify-domain",
        help="Add a domain to Amazon SES and begin the verification process",
    )
    domain_parser.set_defaults(command=verify_domain)

    # Subcommand 'configure create-receipt-rule'
    receipt_rule_parser = configure_command.add_parser(
        "create-receipt-rule",
        help=(
            "Install receipt rule which saves incoming emails in S3 and "
            "triggers a Lambda function to forward emails"
        ),
    )
    receipt_rule_parser.set_defaults(command=create_receipt_rule)

    # Command 'add-forward-address'
    forward_parser = commands.add_parser(
        "add-forward-address",
        help="Add address to the list of possible forward addresses",
    )
    forward_parser.set_defaults(command=add_forward_address)
    forward_parser.add_argument(
        "--address",
        help="Email address to add to the verification list",
        required=True,
    )

    list_routes_command = commands.add_parser(
        "list-routes", help="List defined email routes"
    )
    list_routes_command.set_defaults(command=list_routes)
    group = list_routes_command.add_mutually_exclusive_group()
    group.add_argument(
        "--active", help="List only active routes", action="store_true"
    )
    group.add_argument(
        "--inactive", help="List only inactive routes", action="store_true"
    )

    add_route_command = commands.add_parser("add-route", help="Add new route")
    add_route_command.set_defaults(command=add_route)
    add_route_command.add_argument(
        "--alias", help="Alias (or username) of the new address", required=True
    )
    add_route_command.add_argument(
        "--forward",
        help="The address to forward emails to (must be a verified address)",
        required=True,
    )
    add_route_command.add_argument(
        "--inactive",
        help="Make the route inactive by default",
        action="store_true",
        default=False,
    )
    add_route_command.add_argument(
        "--meta",
        help="Freeform metadata (comment) to store alongside an alias",
        default="",
    )

    update_route_command = commands.add_parser(
        "update-route", help="Modify route configuration"
    )
    update_route_command.set_defaults(command=update_route)
    update_route_command.add_argument(
        "--alias", help="The alias of the route to modify", required=True
    )
    group = update_route_command.add_mutually_exclusive_group()
    group.add_argument(
        "--active", help="Make the route active", action="store_true"
    )
    group.add_argument(
        "--inactive", help="Make the route inactive", action="store_true"
    )
    update_route_command.add_argument(
        "--forward", help="New forwarding addresss", default=""
    )
    update_route_command.add_argument(
        "--meta", help="New metadata information", default=""
    )

    remove_route_command = commands.add_parser(
        "remove-route", help="Remove a route"
    )
    remove_route_command.set_defaults(command=remove_route)
    remove_route_command.add_argument(
        "--alias",
        help="Alias (or username) of the route to remove",
        required=True,
    )

    recipients_commands = commands.add_parser(
        "list-recipients", help="List recipient addresses"
    )
    recipients_commands.set_defaults(command=list_recipients)
    group = recipients_commands.add_mutually_exclusive_group()
    group.add_argument(
        "--alias", help="Limit recipient addresses to a specific alias"
    )
    group.add_argument(
        "--address",
        help=(
            "Only show the recipient for a particular forwarding address of "
            "the form '<alias>+<hash>@<domain>'"
        ),
    )

    args = vars(parser.parse_args())
    return {key: value for key, value in args.items() if value is not None}


def run():
    args = parse_arguments()
    args["command"](args)
