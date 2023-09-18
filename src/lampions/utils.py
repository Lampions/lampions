import hashlib
import json
import typing

HASH_PREFIX_LENGTH = 8


def compute_sha224_hash(string: str) -> str:
    hash_ = hashlib.sha224()
    hash_.update(string.encode("utf8"))
    return hash_.hexdigest()[:HASH_PREFIX_LENGTH]


def format_address(alias: str, hash_: str, domain: str) -> str:
    return f"{alias}+{hash_}@{domain}"


def dict_to_formatted_json(dictionary: typing.Dict[str, str]) -> str:
    return json.dumps(dictionary, indent=2)


T = typing.TypeVar("T")


def first(iterable: typing.Sequence[T]) -> T:
    if isinstance(iterable, str):
        raise TypeError("Strings not supported")
    if len(iterable) == 0:
        raise ValueError("Sequence is empty")
    head, *_ = iterable
    return head
