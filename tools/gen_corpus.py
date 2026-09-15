#!/usr/bin/env python3
"""Generate the labeled evaluation corpus for PIIShield.

Ground truth is produced *by construction*: each document is assembled from a
template plus a set of values whose offsets are recorded as the entity is
inserted. The labels therefore never depend on what the detectors happen to
find, which is the only way the resulting precision and recall numbers mean
anything.

The corpus deliberately includes hard negatives -- order IDs, SKUs, version
strings, timestamps, tracking numbers -- because a PII detector's real failure
mode is over-redaction, and a corpus of nothing but positives cannot measure it.
"""
import json, random, pathlib

random.seed(20260916)  # deterministic corpus; regenerating gives identical output

# ---------------------------------------------------------------- validators
VT = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
VP = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
]

def verhoeff_ok(s):
    c = 0
    for i, ch in enumerate(reversed(s)):
        c = VT[c][VP[i % 8][int(ch)]]
    return c == 0

def make_aadhaar():
    while True:
        base = str(random.randint(2, 9)) + "".join(str(random.randint(0, 9)) for _ in range(11))
        if verhoeff_ok(base):
            return base

def luhn_ok(s):
    total, alt = 0, False
    for ch in reversed(s):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9: d -= 9
        total += d
        alt = not alt
    return total % 10 == 0

def make_card():
    prefix = random.choice(["4", "51", "52", "55", "4111"])
    while True:
        body = prefix + "".join(str(random.randint(0, 9)) for _ in range(16 - len(prefix)))
        if luhn_ok(body):
            return body

# ---------------------------------------------------------------- generators
FIRST = ["Anwesha","Rahul","Priya","Vikram","Sneha","Arjun","Meera","Karan","Divya","Rohan","Ananya","Suresh"]
LAST  = ["Yadav","Sharma","Patel","Reddy","Nair","Gupta","Singh","Iyer","Bose","Mehta","Joshi","Rao"]
DOMAINS = ["example.com","mailbox.co.in","testmail.org","shop.example.net","inbox.example.co"]
PSP = ["okhdfcbank","oksbi","okaxis","ybl","paytm","upi"]
BANKS = ["HDFC","ICIC","SBIN","UTIB","KKBK","PUNB"]

def g_email():
    return f"{random.choice(FIRST).lower()}.{random.choice(LAST).lower()}@{random.choice(DOMAINS)}"

def g_phone_in():
    n = str(random.randint(6, 9)) + "".join(str(random.randint(0, 9)) for _ in range(9))
    style = random.choice(["plain", "spaced", "cc", "cc-space"])
    if style == "plain":   return n, n
    if style == "spaced":  return f"{n[:5]} {n[5:]}", f"{n[:5]} {n[5:]}"
    if style == "cc":      return f"+91{n}", n
    return f"+91 {n[:5]} {n[5:]}", f"{n[:5]} {n[5:]}"

def g_phone_us():
    s = f"{random.randint(200,989)}-{random.randint(200,999)}-{random.randint(1000,9999)}"
    return s, s

def g_aadhaar():
    a = make_aadhaar()
    style = random.choice(["plain", "spaced", "dashed"])
    if style == "plain":  return a, a
    if style == "spaced": return f"{a[:4]} {a[4:8]} {a[8:]}", f"{a[:4]} {a[4:8]} {a[8:]}"
    return f"{a[:4]}-{a[4:8]}-{a[8:]}", f"{a[:4]}-{a[4:8]}-{a[8:]}"

def g_card():
    c = make_card()
    style = random.choice(["plain", "spaced", "dashed"])
    if style == "plain":  return c, c
    if style == "spaced": return f"{c[:4]} {c[4:8]} {c[8:12]} {c[12:]}", f"{c[:4]} {c[4:8]} {c[8:12]} {c[12:]}"
    return f"{c[:4]}-{c[4:8]}-{c[8:12]}-{c[12:]}", f"{c[:4]}-{c[4:8]}-{c[8:12]}-{c[12:]}"

def g_pan():
    s = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5)) \
        + "".join(str(random.randint(0,9)) for _ in range(4)) \
        + random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return s, s

def g_ifsc():
    s = random.choice(BANKS) + "0" + "".join(random.choice("0123456789ABCDEF") for _ in range(6))
    return s, s

def g_upi():
    s = f"{random.choice(FIRST).lower()}{random.randint(1,999)}@{random.choice(PSP)}"
    return s, s

def g_ip():
    s = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return s, s

def g_jwt():
    import base64
    def b64(o): return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b64({'alg':'HS256','typ':'JWT'})}.{b64({'sub':str(random.randint(10**9,10**10)),'name':'x'})}.{''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-') for _ in range(43))}", None

def g_apikey():
    kind = random.choice(["sk", "ghp", "akia"])
    if kind == "sk":  s = "sk-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(32))
    elif kind == "ghp": s = "ghp_" + "".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(36))
    else: s = "AKIA" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(16))
    return s, s

GENERATORS = {
    "EMAIL":       lambda: (g_email(), None),
    "PHONE_IN":    g_phone_in,
    "PHONE_US":    g_phone_us,
    "AADHAAR":     g_aadhaar,
    "CREDIT_CARD": g_card,
    "PAN":         g_pan,
    "IFSC":        g_ifsc,
    "UPI_ID":      g_upi,
    "IP_ADDRESS":  g_ip,
    "JWT":         g_jwt,
    "API_KEY":     g_apikey,
}

def gen(t):
    """Return the surface string to insert for entity type t."""
    out = GENERATORS[t]()
    return out[0] if isinstance(out, tuple) else out

# ---------------------------------------------------------------- hard negatives
# Strings that look like PII to a naive pattern but are not. These carry no
# labels, so any detector firing on them is scored as a false positive.
HARD_NEGATIVES = [
    "order 1234567890123456 was dispatched",
    "SKU 987654321098 is out of stock",
    "build version 999.999.999.999 failed",
    "tracking number 112233445566778899 updated",
    "invoice INV-2026-0098812 attached",
    "the batch ran 12 times over 3456789012 records",
    "our office line is listed on the website",
    "reference 000000000000 is a placeholder",
    "timestamp 1789456123 recorded",
    "quantity 4111111111111112 is obviously wrong",
    "ticket #55512345678 escalated",
    "please read section 192.168 of the manual",
    "coupon SAVE50NOW applied",
    "GSTIN format is 15 characters long",
    "the PIN code is six digits",
    "warehouse bay A1234567 restocked",
]

TEMPLATES = [
    "Hi team, {e} Please help.",
    "Customer wrote in: {e} -- needs a response today.",
    "Escalation from support queue: {e}",
    "Ticket #{tid} body: {e}",
    "{e} Thanks in advance.",
    "Forwarding the details below.\n{e}\nRegards",
    "Chat transcript excerpt --- {e} --- end of excerpt.",
    "Note added by agent: {e}",
]

SENTENCES = {
    "EMAIL":       ["you can reach me at {}", "drop a mail to {}", "cc {} on the reply", "my email is {}"],
    "PHONE_IN":    ["call me on {}", "my number is {}", "reachable at {} after 6pm", "contact {} for pickup"],
    "PHONE_US":    ["the US line is {}", "dial {} for support", "callback on {}"],
    "AADHAAR":     ["aadhaar {} attached for kyc", "my aadhaar number is {}", "uid {} submitted"],
    "CREDIT_CARD": ["charged card {} twice", "the card ending on {} failed", "paid using {}"],
    "PAN":         ["pan {} for the invoice", "my pan is {}", "pan card {} uploaded"],
    "IFSC":        ["branch ifsc {}", "use ifsc {} for the transfer", "ifsc code is {}"],
    "UPI_ID":      ["refund to {} please", "my upi is {}", "sent via {}"],
    "IP_ADDRESS":  ["request came from {}", "server {} is unreachable", "whitelisted {}"],
    "JWT":         ["the session token was {}", "auth header carried {}"],
    "API_KEY":     ["the key {} is in the config", "rotate {} immediately"],
}

def build_doc():
    """Assemble one document, recording entity offsets as values are inserted."""
    n = random.choices([1, 2, 3, 4], weights=[35, 35, 20, 10])[0]
    types = random.sample(list(SENTENCES.keys()), n)

    parts, entities = [], []
    body = ""
    for t in types:
        val = gen(t)
        sentence = random.choice(SENTENCES[t])
        before, after = sentence.split("{}")
        body += before
        entities.append({"type": t, "start": None, "end": None, "value": val, "_body_off": len(body)})
        body += val + after + ". "

    # Interleave hard negatives so false positives are actually exercised.
    if random.random() < 0.45:
        body += random.choice(HARD_NEGATIVES) + ". "

    tmpl = random.choice(TEMPLATES)
    text = tmpl.format(e=body.strip(), tid=random.randint(10000, 99999))

    # Offsets are recomputed against the final text by locating each value at
    # or after its recorded position in the body, which keeps labels correct
    # after the template wraps the body in a prefix.
    prefix = text.index(body.strip()[:20]) if body.strip()[:20] in text else 0
    for ent in entities:
        idx = text.find(ent["value"], max(0, prefix + ent["_body_off"] - 4))
        if idx < 0:
            idx = text.find(ent["value"])
        ent["start"], ent["end"] = idx, idx + len(ent["value"])
        del ent["_body_off"]

    entities = [e for e in entities if e["start"] >= 0 and text[e["start"]:e["end"]] == e["value"]]
    return {"text": text, "entities": entities}


def build_negative_doc():
    """A document containing only hard negatives: every detection is a false positive."""
    picks = random.sample(HARD_NEGATIVES, random.randint(2, 4))
    return {"text": " ".join(p.capitalize() + "." for p in picks), "entities": []}


def main():
    docs = [build_doc() for _ in range(200)]
    docs += [build_negative_doc() for _ in range(50)]
    random.shuffle(docs)

    out = pathlib.Path("testdata/corpus.jsonl")
    out.parent.mkdir(exist_ok=True)
    with out.open("w") as f:
        for i, d in enumerate(docs):
            d["id"] = f"doc-{i:04d}"
            f.write(json.dumps(d) + "\n")

    total = sum(len(d["entities"]) for d in docs)
    by_type = {}
    for d in docs:
        for e in d["entities"]:
            by_type[e["type"]] = by_type.get(e["type"], 0) + 1
    print(f"wrote {len(docs)} documents, {total} labeled entities")
    for t in sorted(by_type):
        print(f"  {t:<14} {by_type[t]}")
    print(f"  {'(negative docs)':<14} {sum(1 for d in docs if not d['entities'])}")

if __name__ == "__main__":
    main()
