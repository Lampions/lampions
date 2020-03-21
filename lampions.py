#!/usr/bin/env python3

import datetime
import io
import json
import os
import zipfile
from argparse import ArgumentParser

import boto3

REGIONS = (
    "eu-west-1",
    "us-east-1",
    "us-west-2"
)


def die_with_message(*args):
    raise SystemExit("Error: " + "\n".join(args))


def _get_account_id():
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def create_s3_bucket(args):
    domain = args["domain"]
    bucket = f"lampions.{domain}"
    region = args["region"]

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
        # TODO: Handle iam.exceptions.LimitExceededException.
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


def _get_config_directory():
    config_directory = os.path.expanduser("~/.config/lampions")
    os.makedirs(config_directory, exist_ok=True)
    return config_directory


def _write_dict_to_600_json_file(dictionary, file_path):
    def _json_serializer(o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()

    with open(file_path, "w") as f:
        json.dump(dictionary, f, indent=2, default=_json_serializer)
    os.chmod(file_path, 0o600)


def create_route_user(args):
    domain = args["domain"]
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
        die_with_message(f"Failed to access key for user '{user_name}':",
                         str(exception))
    else:
        del access_key["ResponseMetadata"]
    access_key_id = access_key["AccessKey"]["AccessKeyId"]

    config_directory = _get_config_directory()
    access_key_path = os.path.join(config_directory, f"{access_key_id}.json")
    _write_dict_to_600_json_file(access_key, access_key_path)
    print(f"Access key for route user saved at '{access_key_path}'")


def add_domain(args):
    domain = args["domain"]
    region = args["region"]

    ses = boto3.client("ses", region_name=region)
    dkim_tokens = ses.verify_domain_dkim(Domain=domain)
    del dkim_tokens["ResponseMetadata"]

    config_directory = _get_config_directory()
    dkim_tokens_path = os.path.join(config_directory, "dkim.json")
    _write_dict_to_600_json_file(dkim_tokens, dkim_tokens_path)

    print(f"DKIM tokens for domain '{domain}' saved at "
          f"'{dkim_tokens_path}'.")
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


def add_email_addresses(args):
    region = args["region"]
    addresses = args["addresses"]

    ses = boto3.client("ses", region_name=region)
    for address in addresses:
        try:
            ses.verify_email_identity(EmailAddress=address)
        except ses.exceptions.ClientError as exception:
            die_with_message("Failed to add address to verification list:",
                             str(exception))


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


def create_receipt_rule(args):
    region = args["region"]
    domain = args["domain"]
    bucket = f"lampions.{domain}"

    # Create policy for the Lambda function.
    role_arn = _create_lambda_function_role(bucket, region)

    # Upload the code of the Lambda function to the Lampions bucket.
    directory = os.path.abspath(os.path.dirname(__file__))
    lambda_function_basename = "lampions_lambda_function"
    lambda_function_filename = _put_object_zip(
        os.path.join(directory, "src", f"{lambda_function_basename}.py"),
        region,
        bucket)

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


def parse_arguments():
    parser = ArgumentParser("Configure AWS for Lampions")
    subcommands = parser.add_subparsers(title="Subcommands", dest="command",
                                        required=True)

    bucket_parser = subcommands.add_parser(
        "create-bucket", help="Create an S3 bucket to store route information "
        "and incoming emails in")
    bucket_parser.set_defaults(command=create_s3_bucket)
    bucket_parser.add_argument(
        "--domain", help="The domain name to create an S3 bucket for. The "
        "bucket name will be of the form 'lampions.{domain}'", required=True)
    bucket_parser.add_argument(
        "--region", help="The region in which to create the bucket",
        required=True, choices=REGIONS)

    user_parser = subcommands.add_parser(
        "create-route-user", help="Create an AWS user with permission to read "
        "and write to the routes file")
    user_parser.set_defaults(command=create_route_user)
    user_parser.add_argument("--domain", help="The domain name", required=True)

    domain_parser = subcommands.add_parser(
        "configure-domain", help="Add a domain to Amazon SES and begin the "
        "verification process")
    domain_parser.set_defaults(command=add_domain)
    domain_parser.add_argument("--domain", help="The domain to add to SES",
                               required=True)
    domain_parser.add_argument(
        "--region", help="The region in which to add the domain",
        required=True, choices=REGIONS)

    emails_parser = subcommands.add_parser(
        "verify-email-addresses", help="Add email addresses to the SES "
        "verification list enable forwarding of incoming emails")
    emails_parser.set_defaults(command=add_email_addresses)
    emails_parser.add_argument(
        "--region", help="The region in which to add the domain to",
        required=True, choices=REGIONS)
    emails_parser.add_argument(
        "--addresses", help="A list of email addresses to add to the "
        "verification list", required=True, nargs="*")

    receipt_rule_parser = subcommands.add_parser(
        "create-receipt-rule",
        help="Install receipt rule which saves incoming emails in S3 and "
        "triggers a Lambda function to forward emails")
    receipt_rule_parser.set_defaults(command=create_receipt_rule)
    receipt_rule_parser.add_argument(
        "--domain", help="The domain name", required=True)
    receipt_rule_parser.add_argument(
        "--region", help="The region used for SES", required=True,
        choices=REGIONS)

    args = vars(parser.parse_args())
    return {key: value for key, value in args.items() if value is not None}


def main():
    args = parse_arguments()
    args["command"](args)


if __name__ == "__main__":
    main()
