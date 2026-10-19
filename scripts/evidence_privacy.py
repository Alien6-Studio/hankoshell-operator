"""Conservative JWT detection/redaction for private qualification evidence.

Consume maximal components once. Searching an unanchored, multi-component JWT
regex repeatedly can backtrack quadratically on long attacker-controlled runs.
These functions recognize credential-shaped text; they never validate a token.
"""

from collections import deque
import re

_PART = re.compile(r"[\w-]+|\.")


def jwt_spans(text, *, json_header=True):
    """Yield nonoverlapping candidate spans with linear input traversal.

The usual evidence guard finds eyJ inside the header component, as its previous
unanchored detector did. Diagnostic redaction may also mask any header of at
least twelve characters, including non-JSON headers. Unicode word characters
remain conservatively eligible; genuine JWTs use the narrower ASCII alphabet.
"""
    components = deque(maxlen=3)
    previous_end, after_component = 0, False
    for part in _PART.finditer(text):
        if part.start() != previous_end:
            components.clear()
            after_component = False
        value = part.group()
        if value == ".":
            if not after_component:
                components.clear()
            after_component = False
        else:
            if after_component:
                components.clear()
            marker = value.find("eyJ") if json_header else 0
            eligible = marker >= 0 and (marker + 3 < len(value) if json_header else len(value) >= 12)
            components.append((part.start() + max(marker, 0), part.end(), eligible))
            if len(components) == 3 and components[0][2]:
                yield components[0][0], components[-1][1]
                components.clear()
            after_component = True
        previous_end = part.end()


def contains_jwt(text):
    return next(jwt_spans(text), None) is not None


def redact_jwts(text, *, json_header=True):
    parts, previous_end = [], 0
    for start, end in jwt_spans(text, json_header=json_header):
        parts.extend((text[previous_end:start], "[REDACTED JWT]"))
        previous_end = end
    parts.append(text[previous_end:])
    return "".join(parts)
