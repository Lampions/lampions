import email
import json
import os

import boto3


def _retrieve_message(message_id):
    domain = os.environ["LAMPIONS_DOMAIN"]
    bucket = f"lampions.{domain}"
    region = os.environ["LAMPIONS_REGION"]
    message_key = f"inbox/{message_id}"

    s3 = boto3.client("s3", region_name=region)
    message = s3.get_object(Bucket=bucket, Key=message_key)
    return message["Body"].read()


def _determine_forward_addresses(recipients):
    domain = os.environ["LAMPIONS_DOMAIN"]
    bucket = f"lampions.{domain}"

    s3 = boto3.client("s3")
    try:
        response = s3.get_object(Bucket=bucket, Key="routes.json")
    except s3.exceptions.NoSuchKey:
        return None

    data = response["Body"].read()
    try:
        dictionary = json.loads(data)
    except json.decoder.JSONDecodeError:
        routes = []
    else:
        routes = dictionary["routes"]

    forward_addresses = []
    for recipient in recipients:
        name, address = email.utils.parseaddr(recipient)
        for route in routes:
            alias = route["alias"]
            recipient = f"{alias}@{domain}"
            if address == recipient:
                if not route["active"]:
                    print(f"Not forwarding email to '{recipient}' "
                          "(route inactive)")
                else:
                    forward_addresses.append(
                        email.utils.formataddr((name, route["forward"])))
    return forward_addresses


def _send_message(message_id):
    file = _retrieve_message(message_id).decode("utf8")
    mail = email.message_from_string(file)

    recipients = mail.get_all("To")
    forward_addresses = _determine_forward_addresses(recipients)
    if not forward_addresses:
        print(f"No alias found for '{recipients}'")
        return

    domain = os.environ["LAMPIONS_DOMAIN"]
    original_sender = mail["From"]
    if mail["Reply-To"] is None:
        mail.add_header("Reply-To", original_sender)
    original_name, address = email.utils.parseaddr(original_sender)
    if original_name:
        name = f"{original_name} (via) {address}"
    else:
        name = address
    sender = email.utils.formataddr((name, f"lampions@{domain}"))
    mail.replace_header("From", sender)
    # Return-Path addresses must be verified in SES, which we cannot do. Drop
    # the header instead.
    del mail["Return-Path"]

    region = os.environ["LAMPIONS_REGION"]
    kwargs = {
        "Source": sender,
        "Destinations": forward_addresses,
        "RawMessage": {
            "Data": mail.as_string()
        }
    }
    ses = boto3.client("ses", region_name=region)
    try:
        ses.send_raw_email(**kwargs)
    except ses.exceptions.ClientError as exception:
        print(exception)


def handler(event, context):
    message_id = event["Records"][0]["ses"]["mail"]["messageId"]
    _send_message(message_id)
