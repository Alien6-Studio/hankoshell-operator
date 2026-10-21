"""Shared bounded input guards for administrator commands."""

import json
import re
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler

LIMIT = 32 * 1024 * 1024


class Refused(Exception):
    """Fixed diagnostic codes only; never an API body or user-controlled string."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "AmbiguousJSON")
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= LIMIT, "ResponseTooLarge")
    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(Refused("InvalidJSON")))
    except (ValueError, TypeError, RecursionError):
        raise Refused("InvalidJSON") from None


def name(value, *, namespace=False):
    require(isinstance(value, str) and 0 < len(value) <= (63 if namespace else 253)
            and re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", value) and ".." not in value
            and (not namespace or "." not in value), "InvalidObjectName")
    return quote(value, safe="")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
