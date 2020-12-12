import hashlib
import json

HASH_PREFIX_LENGTH = 8


def compute_sha224_hash(string):
    hash_ = hashlib.sha224()
    hash_.update(string.encode("utf8"))
    return hash_.hexdigest()[:HASH_PREFIX_LENGTH]


def format_address(alias, hash_, domain):
    return f"{alias}+{hash_}@{domain}"


def dict_to_formatted_json(dictionary):
    return json.dumps(dictionary, indent=2)
