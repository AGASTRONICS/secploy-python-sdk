"""
Removing secrets before anything leaves the application.

An observability SDK is a pipe out of somebody else's process, and whatever goes
into that pipe gets stored, indexed, and shown on a dashboard to whoever has
access to it. Until now nothing stood between the application's data and that
pipe: no denylist, no redaction, no hook. A password in a form dict, a bearer
token in a header, a session cookie - all of it went out verbatim.

Two rules shape what is here.

**Scrub at the boundary, not at the call site.** Every event goes through one
function on its way to the queue, and the scrubbing happens there. Redacting at
each place that builds a payload guarantees that the next payload someone adds
is the one that leaks.

**Credentials are not identifiers.** A general error tracker turns personal data
off by default, because it does not need to know who you are. This one does: the
identity, the session and the IP address are the signal - impossible travel,
actor correlation and every control action are built on them. So they stay, and
what gets removed is the class of thing that grants access rather than describes
a person: passwords, tokens, keys, cookies, card numbers. The session identifier
is kept but hashed, because the product needs to recognise a session, not to be
able to replay it.
"""

import hashlib
import re
from typing import Any, Dict, Iterable, Optional, Set

REDACTED = "[secploy:redacted]"

# Key names whose value is never sent.
#
# Compared after normalising the key - lowercased, with separators removed - so
# "API-Key", "api_key" and "apiKey" are one entry rather than three.
DEFAULT_DENY_KEYS: Set[str] = {
    "password", "passwd", "pwd", "passphrase",
    "secret", "clientsecret", "appsecret",
    "token", "accesstoken", "refreshtoken", "idtoken", "bearertoken",
    "apikey", "apisecret", "apitoken", "xapikey",
    "auth", "authorization", "proxyauthorization",
    "cookie", "cookies", "setcookie",
    "sessionkey", "sessiontoken", "sessid", "sid",
    "csrf", "csrftoken", "xsrftoken",
    "privatekey", "publickey", "signingkey", "encryptionkey", "signature",
    "credentials", "credential",
    "creditcard", "cardnumber", "cardnum", "cvv", "cvc", "pin",
    "ssn", "socialsecurity", "socialsecuritynumber", "taxid",
    "otp", "mfacode", "totp", "twofactorcode",
    "dbpassword", "databaseurl", "connectionstring", "dsn",
}

# Keys the SDK produces itself and has already made safe.
#
# ``session_id`` normalises to "sessionid", which would otherwise be caught by
# the denylist above - and it must not be, because it is how a session is
# recognised across events. It arrives here already hashed.
EXEMPT_KEYS: Set[str] = {"sessionid", "identitykey"}

_SEPARATORS = re.compile(r"[^a-z0-9]")

# Value shapes worth removing wherever they appear, including inside a message
# or under a key nobody thought to deny.
_VALUE_PATTERNS = (
    # JSON Web Tokens. Three base64url segments; the leading "eyJ" is the
    # encoded '{"' that begins every JWT header.
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # PEM private key blocks, including everything between the markers.
    re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----", re.DOTALL),
    # Credentials embedded in a URL: https://user:password@host
    re.compile(r"(?<=://)[^/\s:@]+:[^/\s:@]+(?=@)"),
    # An Authorization header value that turned up in free text.
    re.compile(r"(?i)\b(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{12,}"),
    # Provider-issued keys, which are recognisable by their prefixes.
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
)

# Candidate card numbers: 13-19 digits, optionally separated. Checked against
# Luhn before being redacted, because this shape also matches order numbers,
# timestamps and database ids, and redacting those would make the product worse
# at its job for no security benefit.
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# Bounds on how much of a structure is walked.
#
# These are not only about cost. A cyclic or absurdly deep payload should end in
# a truncated event rather than in a recursion error inside the SDK.
MAX_DEPTH = 8
MAX_ITEMS = 200
MAX_STRING = 8192

# The exact shape hash_session_id emits, used to recognise its own output.
_HASHED_SESSION = re.compile(r"^sess_[0-9a-f]{32}$")


def normalize_key(key: Any) -> str:
    """Lowercase a key and drop separators, so naming style stops mattering."""
    return _SEPARATORS.sub("", str(key).lower())


def _luhn_valid(digits: str) -> bool:
    """The checksum every real card number satisfies."""
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = ord(char) - 48
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _redact_cards(text: str) -> str:
    def replace(match: "re.Match[str]") -> str:
        digits = re.sub(r"[ -]", "", match.group(0))
        return REDACTED if _luhn_valid(digits) else match.group(0)

    return _CARD_CANDIDATE.sub(replace, text)


def scrub_string(value: str) -> str:
    """Remove secret-shaped substrings from free text."""
    if not value:
        return value

    scrubbed = value
    for pattern in _VALUE_PATTERNS:
        scrubbed = pattern.sub(REDACTED, scrubbed)
    scrubbed = _redact_cards(scrubbed)

    if len(scrubbed) > MAX_STRING:
        scrubbed = scrubbed[:MAX_STRING] + "…[truncated]"

    return scrubbed


def hash_session_id(value: Any) -> str:
    """
    Turn a session identifier into something that identifies without granting.

    A Django ``sessionid`` cookie is a live credential: anyone who reads one out
    of an event store can use it. But the product genuinely needs to recognise a
    session - to correlate an actor's activity and to target a revocation - so
    dropping it is not an option either.

    A hash keeps every property that is actually needed. It is stable, so the
    same session matches across events and processes; it is unique, so sessions
    stay distinct; and it cannot be replayed. Unsalted deliberately: a salt
    would have to be shared by every process and every service that compares
    these values, and the input is already high-entropy enough that a hash of it
    is not worth attacking.
    """
    text = str(value or "")
    if not text:
        return ""

    # Idempotent on purpose. Auth context is normalised at more than one layer,
    # and hashing an already-hashed value would produce something that matches
    # no control at all. A gate that silently stops enforcing is the worst way
    # for this to fail, so applying it twice has to equal applying it once.
    if _HASHED_SESSION.match(text):
        return text

    return "sess_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


class Scrubber:
    """Removes credentials from an event payload."""

    def __init__(
        self,
        deny_keys: Optional[Iterable[str]] = None,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.deny_keys = set(DEFAULT_DENY_KEYS)
        if deny_keys:
            self.deny_keys.update(normalize_key(key) for key in deny_keys)

    def is_denied(self, key: Any) -> bool:
        normalized = normalize_key(key)
        if not normalized or normalized in EXEMPT_KEYS:
            return False
        if normalized in self.deny_keys:
            return True
        # Substring match so "user_password", "stripe_api_key" and
        # "x_auth_token" are caught without having to enumerate every prefix a
        # framework might use.
        return any(denied in normalized for denied in self.deny_keys if len(denied) >= 5)

    def scrub(self, value: Any, _depth: int = 0) -> Any:
        """
        Walk a payload, redacting as it goes.

        Never raises. This runs on the path every event takes, and a scrubber
        that throws on an unusual object would stop the application reporting
        anything at all.
        """
        if not self.enabled:
            return value

        try:
            return self._scrub(value, _depth, set())
        except Exception:
            # Something in the payload defeated the walk. Returning it unscrubbed
            # would be exactly the leak this exists to prevent, so it does not
            # go out.
            return REDACTED

    def _scrub(self, value: Any, depth: int, seen: Set[int]) -> Any:
        if depth > MAX_DEPTH:
            return "[secploy:max-depth]"

        if isinstance(value, str):
            return scrub_string(value)

        if isinstance(value, (int, float, bool)) or value is None:
            return value

        if isinstance(value, dict):
            # Cycles are rare but real - a request object graph, a logging
            # extra that references its own record - and would otherwise
            # recurse until the depth cap, wasting the whole budget.
            marker = id(value)
            if marker in seen:
                return "[secploy:circular]"
            seen = seen | {marker}

            scrubbed: Dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= MAX_ITEMS:
                    scrubbed["[secploy:truncated]"] = len(value) - MAX_ITEMS
                    break
                if self.is_denied(key):
                    scrubbed[str(key)] = REDACTED
                else:
                    scrubbed[str(key)] = self._scrub(item, depth + 1, seen)
            return scrubbed

        if isinstance(value, (list, tuple, set)):
            marker = id(value)
            if marker in seen:
                return "[secploy:circular]"
            seen = seen | {marker}

            items = list(value)[:MAX_ITEMS]
            return [self._scrub(item, depth + 1, seen) for item in items]

        # Anything else - a model instance, a file handle, a custom object -
        # becomes its string form, which is then scrubbed like any other text.
        try:
            return scrub_string(str(value))
        except Exception:
            return REDACTED
