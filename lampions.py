#!/usr/bin/env python3

import datetime
import functools
import io
import json
import os
import zipfile
from argparse import ArgumentParser

import boto3
from validate_email import validate_email

CONFIG_PATH = os.path.expanduser("~/.config/lampions/config.json")

REGIONS = (
    "eu-west-1",
    "us-east-1",
    "us-west-2"
)


def die_with_message(*args):
    raise SystemExit("Error: " + "\n".join(args))


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
        def _json_serializer(o):
            if isinstance(o, (datetime.date, datetime.datetime)):
                return o.isoformat()

        return json.dumps(self, indent=2, default=_json_serializer)

    def verify(self):
        for key in self.REQUIRED_KEYS:
            if key not in self:
                die_with_message(
                    "Lampions is not initialized yet. Call "
                    f"'{os.path.basename(__file__)} init' first.")
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


@lampions.requires_config
def create_s3_bucket(config, args):
    region = config["region"]
    domain = config["domain"]
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

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LampionsAllowSESPut",
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


def _create_routes_file_policy(bucket):
    """Create policy for the routes file.

    Create a policy that allows reading and writing to the ``routes.json`` file
    inside the S3 bucket ``bucket``.

    Returns:
    --------
    arn : str
        The arn of the policy.
    """
    policy_name = "LampionsRoutesFilePolicy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LampionsAllowS3List",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket}"
            },
            {
                "Sid": "LampionsAllowS3GetPut",
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
        # TODO: Handle iam.exceptions.LimitExceededException when we have
        #       more than x versions of a policy.
        iam.create_policy_version(
            PolicyArn=arn,
            PolicyDocument=policy_document,
            SetAsDefault=True)
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

    domain = config["domain"]
    bucket = f"lampions.{domain}"

    arn = _create_routes_file_policy(bucket)
    user_name = "LampionsRouteUser"
    iam = boto3.client("iam")
    try:
        iam.create_user(UserName=user_name)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    except Exception as exception:
        die_with_message(f"Failed to create route user '{user_name}':",
                         str(exception))

    iam.attach_user_policy(UserName=user_name, PolicyArn=arn)

    try:
        access_key = iam.create_access_key(UserName=user_name)
    except iam.exceptions.LimitExceededException:
        die_with_message("Maximum number of access keys for user "
                         f"'{user_name}' reached. Manually delete a key in "
                         "the AWS Console or via the AWS CLI, and try again.")
    except Exception as exception:
        die_with_message(
            f"Failed to create access key for user '{user_name}':",
            str(exception))

    config["AccessKeyId"] = access_key["AccessKey"]["AccessKeyId"]
    config["SecretAccessKey"] = access_key["AccessKey"]["SecretAccessKey"]
    config.save()

    print(f"User '{user_name}' and access keys created")


@lampions.requires_config
def add_domain(config, args):
    region = config["region"]
    domain = config["domain"]

    ses = boto3.client("ses", region_name=region)
    dkim_tokens = ses.verify_domain_dkim(Domain=domain)
    del dkim_tokens["ResponseMetadata"]
    config.update(dkim_tokens)
    config.save()

    print(f"DKIM tokens for domain '{domain}' created:")
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


def _create_lambda_function_role(bucket, region):
    account_id = _get_account_id()
    policy_name = "LampionsLambdaRolePolicy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LampionsCloudWatch",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            },
            {
                "Sid": "LampionsLambdaFunctionListBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket}"
            },
            {
                "Sid": "LampionsLambdaFunctionReadBucket",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*"
            },
            {
                "Sid": "LampionsLambdaFunctionSendMail",
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

    role_name = "LampionsLambdaRole"
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
    region = config["region"]
    domain = config["domain"]
    bucket = f"lampions.{domain}"

    # Create policy for the Lambda function.
    role_arn = _create_lambda_function_role(bucket, region)

    # Upload the code of the Lambda function to the Lampions bucket.
    directory = os.path.realpath(os.path.dirname(__file__))
    lambda_function_basename = "lampions_lambda_function"
    lambda_function_filename = _put_object_zip(
        os.path.join(directory, "src", f"{lambda_function_basename}.py"),
        region, bucket)

    # Create the Lambda function.
    function_name = "LampionsLambdaFunction"
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
        print("Lambda function exists. Overwriting the function code.")
        lambda_function = lambda_.update_function_code(
            FunctionName=function_name,
            S3Bucket=bucket,
            S3Key=lambda_function_filename)
        lambda_function_arn = lambda_function["FunctionArn"]
    else:
        lambda_function_arn = lambda_function["FunctionArn"]

    # Add permission to the Lambda function, granting SES invocation
    # privileges.
    try:
        lambda_.add_permission(
            FunctionName=function_name,
            StatementId="LampionsSESInvokeLambdaFunction",
            Action="lambda:InvokeFunction",
            Principal="ses.amazonaws.com")
    except lambda_.exceptions.ResourceConflictException:
        pass

    rule_set_name = "LampionsReceiptRuleSet"
    ses = boto3.client("ses", region_name=region)
    try:
        ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    except ses.exceptions.AlreadyExistsException:
        pass

    rule = {
        "Name": "LampionsReceiptRule",
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
                    "FunctionArn": lambda_function_arn,
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

    print("Receipt rule created and activated")


@lampions.requires_config
def configure_lampions(config, args):
    steps = [
        ("Create S3 bucket", create_s3_bucket),
        ("Create route user", create_route_user),
        ("Register domain with SES", add_domain),
        ("Create receipt rule", create_receipt_rule)
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
    region = config["region"]
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
        required=True)
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

    # Subcommand 'configure register-domain'
    domain_parser = configure_command.add_parser(
        "register-domain", help="Add a domain to Amazon SES and begin the "
        "verification process")
    domain_parser.set_defaults(command=add_domain)

    # Subcommand 'configure create-receipt-rule'
    receipt_rule_parser = configure_command.add_parser(
        "create-receipt-rule",
        help="Install receipt rule which saves incoming emails in S3 and "
        "triggers a Lambda function to forward emails")
    receipt_rule_parser.set_defaults(command=create_receipt_rule)

    # Command 'add-forward-address'
    emails_parser = commands.add_parser(
        "add-forward-address",
        help="Add address to the list of possible forward addresses")
    emails_parser.set_defaults(command=add_forward_address)
    emails_parser.add_argument(
        "--region", help="The SES region in which to add the domain",
        required=True, choices=REGIONS)
    emails_parser.add_argument(
        "--address", help="Email address to add to the verification list",
        required=True)

    args = vars(parser.parse_args())
    return {key: value for key, value in args.items() if value is not None}


if __name__ == "__main__":
    args = parse_arguments()
    args["command"](args)
