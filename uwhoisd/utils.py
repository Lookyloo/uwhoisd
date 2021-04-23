"""
Utilities.
"""

import re


# We only accept ASCII or ACE-encoded domain names. IDNs must be converted
# to ACE first.
FQDN_PATTERN = re.compile(r'^([-a-z0-9]{1,63})(\.[-a-z0-9]{1,63}){1,}$')


def is_well_formed_fqdn(fqdn: str) -> bool:
    """
    Check if a string looks like a well formed FQDN.
    """
    return FQDN_PATTERN.match(fqdn) is not None


def to_bool(s: str) -> bool:
    """
    Converts the given string to a boolean.
    """
    return s.lower() in ('1', 'true', 'yes', 'on')


def decode_value(s: str) -> str:
    """
    If a string is quoted, it's parsed like a python string, otherwise it's
    passed straight through as-is.

    >>> decode_value('foo')
    'foo'
    >>> decode_value('"foo"')
    'foo'
    >>> decode_value('"foo\\nbar\"')
    'foo\\nbar'
    >>> decode_value('foo\\nbar')
    'foo\\nbar'
    >>> decode_value('"foo')
    Traceback (most recent call last):
        ...
    ValueError: The trailing quote be present and match the leading quote.
    >>> decode_value("'foo")
    Traceback (most recent call last):
        ...
    ValueError: The trailing quote be present and match the leading quote.
    >>> decode_value("\\\"foo\\'")
    Traceback (most recent call last):
        ...
    ValueError: The trailing quote be present and match the leading quote.
    """
    if len(s) > 1 and s[0] in ('"', "'"):
        if s[0] != s[-1]:
            raise ValueError(
                "The trailing quote be present and match the leading quote.")
        return s[1:-1]
    return s
