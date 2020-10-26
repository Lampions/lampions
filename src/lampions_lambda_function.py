import email
import hashlib
import json
import os

import boto3

HASH_PREFIX_LENGTH = 8


def _retrieve_message(message_id):
    domain = os.environ["LAMPIONS_DOMAIN"]
    bucket = f"lampions.{domain}"
    region = os.environ["LAMPIONS_REGION"]
    message_key = f"inbox/{message_id}"

    s3 = boto3.client("s3", region_name=region)
    message = s3.get_object(Bucket=bucket, Key=message_key)
    return message["Body"].read()


def _determine_forward_address(recipients):
    region = os.environ["LAMPIONS_REGION"]
    domain = os.environ["LAMPIONS_DOMAIN"]
    bucket = f"lampions.{domain}"

    s3 = boto3.client("s3", region_name=region)
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
                    if name and name != address:
                        forward_address = email.utils.formataddr(
                            (name, route["forward"]))
                    else:
                        forward_address = route["forward"]
                    forward_addresses.append((alias, forward_address))
                    break

    if not forward_addresses:
        raise SystemExit(f"No valid alias found for '{recipients}'")
    forward_address, *_ = forward_addresses
    if len(forward_addresses) > 1:
        print("Multiple forward addresses found! Only forwarding to "
              f"'{forward_address}'.")
    return forward_address


def _get_verified_addresses():
    region = os.environ["LAMPIONS_REGION"]
    ses = boto3.client("ses", region_name=region)
    response = ses.list_identities()
    identities = response["Identities"]
    return [identity for identity in identities if "@" in identity]


def _compute_sha224_hash(string):
    hash = hashlib.sha224()
    hash.update(string.encode("utf8"))
    return hash.hexdigest()[:HASH_PREFIX_LENGTH]


def _get_recipient_relations():
    region = os.environ["LAMPIONS_REGION"]
    domain = os.environ["LAMPIONS_DOMAIN"]
    bucket = f"lampions.{domain}"
    s3 = boto3.client("s3", region_name=region)
    try:
        response = s3.get_object(Bucket=bucket, Key="recipients.json")
    except s3.exceptions.NoSuchKey:
        return {}
    data = response["Body"].read()
    try:
        dictionary = json.loads(data)
    except json.decoder.JSONDecodeError:
        return {}
    return dictionary["recipients"]


def _dict_to_formatted_json(dictionary):
    return json.dumps(dictionary, indent=2)


def _set_recipient_relations(recipients):
    region = os.environ["LAMPIONS_REGION"]
    domain = os.environ["LAMPIONS_DOMAIN"]
    bucket = f"lampions.{domain}"

    recipients_string = _dict_to_formatted_json({"recipients": recipients})
    s3 = boto3.client("s3", region_name=region)
    s3.put_object(Bucket=bucket, Key="recipients.json",
                  Body=recipients_string)


def _get_recipient_by_hash(alias, address_hash):
    recipients = _get_recipient_relations()
    recipients_for_alias = recipients.get(alias)
    if recipients_for_alias is not None:
        return recipients_for_alias.get(address_hash)
    return None


def _add_recipient_relation(alias, address, reply_to):
    address_hash = _compute_sha224_hash(address)
    recipients = _get_recipient_relations()
    recipients_for_alias = recipients.get(alias)
    if recipients_for_alias is None:
        recipients[alias] = {address_hash: reply_to}
    else:
        recipients_for_alias[address_hash] = reply_to
    _set_recipient_relations(recipients)
    domain = os.environ["LAMPIONS_DOMAIN"]
    return f"{alias}+{address_hash}@{domain}"


def _determine_reply_recipient(recipients):
    if len(recipients) > 1:
        return None
    domain = os.environ["LAMPIONS_DOMAIN"]
    recipient, = recipients
    name, address = email.utils.parseaddr(recipient)
    if "+" in address and address.endswith(domain):
        return recipient
    return None


def _send_message(message_id):
    file = _retrieve_message(message_id).decode("utf8")
    mail = email.message_from_string(file)

    original_sender = mail["From"]
    reply_to = mail["Reply-To"]
    if reply_to is None:
        reply_to = original_sender

    unwanted_headers = [
        # Return-Path addresses must be verified in SES, which we only have
        # control over if we're sending reply emails.
        "Return-Path",
        # Preexisting DKIM signature headers might trigger
        # 'InvalidParameterValue' errors in the 'SendRawEmail' endpoint.
        "DKIM-Signature",
        # We don't need to distinguish between 'From' and 'Sender' headers.
        "Sender",
        # No matter whether we're forwarding or sending a reply email, we
        # always want to use the 'From' header as 'Reply-To' header, so just
        # remove the latter.
        "Reply-To",
        # When sending reply emails, these two headers leak the original sender
        # address.
        "Received-SPF",
        "Authentication-Results"
    ]
    for header in unwanted_headers:
        del mail[header]

    origin_name, origin_address = email.utils.parseaddr(reply_to)
    verified_addresses = _get_verified_addresses()

    # Email is a reply from one of our verified addresses to the original
    # sender.
    recipients = mail.get_all("To")
    reply_recipient = _determine_reply_recipient(recipients)
    if origin_address in verified_addresses and reply_recipient is not None:
        _, address = email.utils.parseaddr(reply_recipient)
        alias, address_hash = address.split("@")[0].split("+")

        domain = os.environ["LAMPIONS_DOMAIN"]
        sender = email.utils.formataddr((origin_name, f"{alias}@{domain}"))
        mail.replace_header("From", sender)

        recipient = _get_recipient_by_hash(alias, address_hash)
        mail.replace_header("To", recipient)
        destinations = [recipient]
    else:
        if origin_name:
            name = f"{origin_name} (via) {origin_address}"
        else:
            name = origin_address
        alias, forward_address = _determine_forward_address(recipients)
        sender_address = _add_recipient_relation(
            alias, origin_address, reply_to)
        sender = email.utils.formataddr((name, sender_address))
        mail.replace_header("From", sender)
        destinations = [forward_address]

    region = os.environ["LAMPIONS_REGION"]
    kwargs = {
        "Source": sender,
        "Destinations": destinations,
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
