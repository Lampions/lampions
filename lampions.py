#!/usr/bin/env python3

import datetime
import json
import os
from argparse import ArgumentParser

import boto3

BUCKET_REGIONS = (
    "EU",
    "ap-northeast-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "cn-north-1",
    "eu-central-1",
    "eu-west-1",
    "sa-east-1",
    "us-west-1",
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

    s3 = boto3.client("s3")
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
                         "the AWS Console or via the AWS CLI and try again.")
    except Exception as exception:
        die_with_message(f"Failed to access key for user '{user_name}':",
                         str(exception))
    else:
        del access_key["ResponseMetadata"]

    config_directory = os.path.expanduser("~/.config/lampions")
    os.makedirs(config_directory, exist_ok=True)
    access_key_id = access_key["AccessKey"]["AccessKeyId"]
    access_key_path = os.path.join(config_directory, f"{access_key_id}.json")

    def _json_serializer(o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()

    with open(access_key_path, "w") as f:
        json.dump(access_key, f, indent=2, default=_json_serializer)
    os.chmod(access_key_path, 0o600)
    print(f"Access key for route user saved at '{access_key_path}'")


def parse_arguments():
    parser = ArgumentParser("Configure AWS for Lampions")
    subcommands = parser.add_subparsers(title="Subcommands", dest="command",
                                        required=True)

    bucket_parser = subcommands.add_parser(
        "create-bucket",
        help="Create an S3 bucket to store route information and incoming "
             "emails in")
    bucket_parser.set_defaults(command=create_s3_bucket)
    bucket_parser.add_argument(
        "--domain", help="The domain name to create an S3 bucket for. The "
        "bucket name will be of the form 'lampions.{domain}'", required=True)
    bucket_parser.add_argument("--region",
                               help="The region in which to create the bucket",
                               required=True, choices=BUCKET_REGIONS)

    user_parser = subcommands.add_parser(
        "create-route-user",
        help="Create an AWS user with permission to read and write to the "
             "routes file")
    user_parser.set_defaults(command=create_route_user)
    user_parser.add_argument("--domain", help="The domain name", required=True)

    args = vars(parser.parse_args())
    return {k: v for k, v in args.items() if v is not None}


def main():
    args = parse_arguments()
    args["command"](args)


if __name__ == "__main__":
    main()
