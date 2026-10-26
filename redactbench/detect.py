"""Three ways to remove secrets from one captured event on the laptop, before anything is sent."""
import math
import re
from collections import Counter

from .gen import luhn_ok

MARK = "[REDACTED]"
NAIVE = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+"), re.compile(r"\bAKIA[0-9A-Z]{16}\b"), re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"(?<=://)[^:\s/]+:[^@\s]+(?=@)"), re.compile(r"(?<=Bearer )\S+"), re.compile(r"(?i)(?<=password[:=] )\S+"),
    re.compile(r"\b(?:\d[ -]?){13,19}\b"), re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{11,30}\b"),
]


def naive(ev):
    t = ev["text"]
    for p in NAIVE:
        t = p.sub(MARK, t)
    return t


def entropy_bits(s):
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.]{20,}")


def entropy(ev):
    return TOKEN.sub(lambda m: MARK if entropy_bits(m[0]) >= 3.5 else m[0], ev["text"])


def mod97_ok(iban):
    s = iban[4:] + iban[:4]
    return int("".join(str(int(c, 36)) for c in s)) % 97 == 1


def ssn_ok(s):
    a, g, n = s.split("-")
    return a not in ("000", "666") and not a.startswith("9") and g != "00" and n != "0000"


def layered(ev):
    if ev.get("field") == "password":
        return MARK
    t = ev["text"]
    for p in NAIVE[:7]:                                           # PEM, JWT, AWS, GitHub, connection string, bearer, "password:" are fixed formats
        t = p.sub(MARK, t)
    t = re.sub(r"\b(?:\d[ -]?){13,19}\b", lambda m: MARK if luhn_ok(re.sub(r"\D", "", m[0])) else m[0], t)
    t = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", lambda m: MARK if ssn_ok(m[0]) else m[0], t)
    t = re.sub(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", lambda m: MARK if mod97_ok(m[0]) else m[0], t)
    return t


METHODS = {"naive patterns": naive, "entropy only": entropy, "layered (format + checksum + field context)": layered}
