"""Synthetic work-session event streams with planted secrets (known truth) and look-alikes that must survive.

All values are generated: card numbers are Luhn-valid test-style numbers, IBANs satisfy mod 97, nothing is a real credential."""
import base64
import json
import string

import numpy as np

ALNUM = string.ascii_letters + string.digits
BUSINESS = ["Refund approved for ticket {t}, amount ${a:,.2f}", "Customer asked about order {o}; escalate to tier 2", "Invoice {o} due {d}",
            "Dispatch note: truck 14 left depot at 06:40, ETA {d}", "Slack: can you check ticket {t} before standup?", "Status changed to Resolved for ticket {t}",
            "Quarterly report draft v{v} saved", "Meeting with {n} moved to Thursday"]
NAMES = ["Priya", "Marcus", "Ana", "Wei", "Tom", "Sofia"]


def luhn_complete(prefix, length, rng):
    body = prefix + "".join(str(rng.integers(10)) for _ in range(length - len(prefix) - 1))
    s = sum((int(c) * 2 - 9 if int(c) * 2 > 9 else int(c) * 2) if i % 2 == 0 else int(c) for i, c in enumerate(reversed(body)))
    return body + str((10 - s % 10) % 10)


def luhn_ok(num):
    d = [int(c) for c in num][::-1]
    return sum(x if i % 2 == 0 else (x * 2 - 9 if x * 2 > 9 else x * 2) for i, x in enumerate(d)) % 10 == 0


def iban_complete(rng, country="GB"):
    bank = "".join(rng.choice(list(string.ascii_uppercase), 4))
    rest = "".join(str(rng.integers(10)) for _ in range(14))
    tmp = bank + rest + country + "00"
    num = "".join(str(int(c, 36)) for c in tmp)
    chk = 98 - int(num) % 97
    return f"{country}{chk:02d}{bank}{rest}"


_VD = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
       [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VP = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
       [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_VINV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_ok(num):
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


def verhoeff_complete(body):
    c = 0
    for i, ch in enumerate(reversed(body + "0")):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return body + str(_VINV[c])


def rand(rng, alphabet, n):
    return "".join(rng.choice(list(alphabet), n))


def b64url(rng, n):
    return base64.urlsafe_b64encode(rng.bytes(n)).decode().rstrip("=")


def pem(rng):
    body = "\n".join(base64.b64encode(rng.bytes(48)).decode() for _ in range(4))
    return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"


def spaced(num, rng, group=4):
    sep = rng.choice([" ", "-", ""])
    return sep.join(num[i:i + group] for i in range(0, len(num), group))


DEV_TYPES = ["card", "ssn", "iban", "aws", "github", "jwt", "pw_field", "conn", "bearer", "pw_text", "pem"]
HELD_TYPES = ["slack", "stripe", "aadhaar", "card_wrapped", "iban_wrapped", "pw_prose", "otp", "gcp_json"] + ["card", "ssn", "iban", "aws", "github", "jwt", "pw_field"]


def make_secret(kind, rng):
    """-> (event dict, secret string(s) that must not survive)"""
    if kind == "card":
        n = luhn_complete(rng.choice(["4", "51", "37"]), 16, rng)
        s = spaced(n, rng)
        return {"kind": "text", "text": f"Card on file: {s} exp 09/28"}, [n]
    if kind == "card_wrapped":
        n = luhn_complete("4", 16, rng)
        a, b = " ".join(n[i:i + 4] for i in range(0, 8, 4)), " ".join(n[i:i + 4] for i in range(8, 16, 4))
        return {"kind": "text", "text": f"Payment method\n{a}\n{b}\nexp 11/27"}, [n]
    if kind == "ssn":
        s = f"{rng.integers(100, 665):03d}-{rng.integers(10, 99):02d}-{rng.integers(1000, 9999):04d}"
        return {"kind": "text", "text": f"Applicant SSN {s} verified"}, [s.replace("-", "")]
    if kind == "iban":
        i = iban_complete(rng)
        return {"kind": "text", "text": f"Beneficiary IBAN: {i}"}, [i]
    if kind == "iban_wrapped":
        i = iban_complete(rng)
        g = [i[k:k + 4] for k in range(0, len(i), 4)]
        return {"kind": "text", "text": "Bank details\n" + " ".join(g[:3]) + "\n" + " ".join(g[3:])}, [i]
    if kind == "aws":
        k = "AKIA" + rand(rng, string.ascii_uppercase + string.digits, 16)
        return {"kind": "text", "text": f"aws_access_key_id = {k}"}, [k]
    if kind == "github":
        k = "ghp_" + rand(rng, ALNUM, 36)
        return {"kind": "clipboard", "text": k}, [k]
    if kind == "jwt":
        j = ".".join([b64url(rng, 18), b64url(rng, 40), b64url(rng, 24)])
        j = "eyJ" + j
        return {"kind": "text", "text": f"Authorization header captured: {j}"}, [j]
    if kind == "pw_field":
        p = rand(rng, ALNUM + "!#$%", int(rng.integers(8, 16)))
        return {"kind": "typed", "field": "password", "text": p}, [p]
    if kind == "conn":
        p = rand(rng, ALNUM, 14)
        return {"kind": "text", "text": f"DATABASE_URL=postgres://app:{p}@db.internal:5432/prod"}, [p]
    if kind == "bearer":
        t = rand(rng, ALNUM, 40)
        return {"kind": "text", "text": f"curl -H 'Authorization: Bearer {t}' https://api.example.test/v1/items"}, [t]
    if kind == "pw_text":
        p = rand(rng, ALNUM + "!#", 12)
        return {"kind": "text", "text": f"login ok. password: {p}"}, [p]
    if kind == "pem":
        k = pem(rng)
        return {"kind": "text", "text": k}, [k.split("\n")[1]]
    if kind == "slack":
        t = f"xoxb-{rng.integers(10 ** 11, 10 ** 12)}-{rng.integers(10 ** 11, 10 ** 12)}-{rand(rng, ALNUM, 24)}"
        return {"kind": "text", "text": f"SLACK_BOT_TOKEN={t}"}, [t]
    if kind == "stripe":
        t = "sk_live_" + rand(rng, ALNUM, 24)
        return {"kind": "clipboard", "text": t}, [t]
    if kind == "aadhaar":
        n = verhoeff_complete(str(rng.integers(2, 10)) + "".join(str(rng.integers(10)) for _ in range(10)))
        s = f"{n[:4]} {n[4:8]} {n[8:]}"
        return {"kind": "text", "text": f"Aadhaar: {s}"}, [n]
    if kind == "pw_prose":
        p = rand(rng, ALNUM + "&", 10)
        return {"kind": "text", "text": f"Hey, the temp login for the vendor portal is jsmith and the temp pass is {p}, change it after first use."}, [p]
    if kind == "otp":
        c = f"{rng.integers(100000, 999999)}"
        return {"kind": "typed", "field": "otp", "text": c}, [c]
    if kind == "gcp_json":
        k = pem(rng)
        d = json.dumps({"type": "service_account", "project_id": "demo-proj", "private_key": k})
        return {"kind": "text", "text": d}, [k.split("\n")[1]]
    raise KeyError(kind)


def make_lookalike(rng):
    kind = rng.choice(["track", "uuid", "sha", "invoice", "iban_like", "amount", "iso"])
    if kind == "track":
        while True:
            n = "".join(str(rng.integers(10)) for _ in range(16))
            if not luhn_ok(n):
                break
        return f"Tracking number {n} handed to carrier", n
    if kind == "uuid":
        import uuid
        u = str(uuid.UUID(bytes=rng.bytes(16)))
        return f"Request id {u} logged", u
    if kind == "sha":
        h = rand(rng, "0123456789abcdef", 40)
        return f"Deployed commit {h} to staging", h
    if kind == "invoice":
        n = f"{rng.integers(10 ** 8, 10 ** 9)}"
        return f"Invoice no. {n} marked paid", n
    if kind == "iban_like":
        n = f"GB{rng.integers(10, 99)}{rand(rng, string.ascii_uppercase, 4)}{rng.integers(10 ** 13, 10 ** 14)}"
        return f"Cost centre code {n} on the PO", n
    if kind == "amount":
        n = f"{rng.integers(1000, 9999)},{rng.integers(100, 999)}.00"
        return f"Total due ${n} net 30", n
    n = f"2026-10-{rng.integers(10, 28)}T14:{rng.integers(10, 59)}:07Z"
    return f"Export finished at {n}", n


def make_session(seed, held=False):
    rng = np.random.default_rng(seed)
    events, secrets, looks = [], [], []
    for _ in range(int(rng.integers(5, 9))):
        t = str(rng.choice(BUSINESS)).format(t=int(rng.integers(4800, 4900)), a=float(rng.uniform(20, 900)), o=f"{rng.integers(10 ** 5, 10 ** 6)}",
                                            d=f"Oct {rng.integers(10, 28)}", v=int(rng.integers(1, 9)), n=str(rng.choice(NAMES)))
        events.append({"kind": "text", "text": t})
    types = HELD_TYPES if held else DEV_TYPES
    for kind in rng.choice(types, size=int(rng.integers(1, 4)), replace=False):
        ev, vals = make_secret(str(kind), rng)
        events.insert(int(rng.integers(len(events) + 1)), ev)
        secrets += [(str(kind), v) for v in vals]
    for _ in range(int(rng.integers(1, 4))):
        txt, val = make_lookalike(rng)
        events.insert(int(rng.integers(len(events) + 1)), {"kind": "text", "text": txt})
        looks.append(val)
    return {"events": events, "secrets": secrets, "looks": looks}
