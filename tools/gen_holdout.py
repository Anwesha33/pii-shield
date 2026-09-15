#!/usr/bin/env python3
"""Generate a held-out evaluation corpus.

The development corpus (tools/gen_corpus.py) was used while tuning detectors,
so its scores are an upper bound rather than an estimate of real performance.
This file builds a second corpus that was never used for tuning:

  * a different random seed, so no specific value is one the detectors were
    fitted to;
  * adversarial negatives absent from the development set -- UUIDs, MAC
    addresses, GSTINs, ISBNs, semantic versions, dates written with dots,
    base64 blobs that are not JWTs, malformed emails, out-of-range phone
    numbers, and Aadhaar-length digits that fail the Verhoeff check;
  * different sentence templates, so surrounding context differs too.

Whatever this corpus reports is the number worth quoting.
"""
import json, random, pathlib, base64, uuid, importlib.util, sys

spec = importlib.util.spec_from_file_location("genc", pathlib.Path(__file__).parent / "gen_corpus.py")
genc = importlib.util.module_from_spec(spec)
sys.modules["genc"] = genc
spec.loader.exec_module(genc)

random.seed(777371)
genc.random.seed(777371)

# Negatives the detectors were never tuned against. Every one of these is a
# string a naive pattern set plausibly fires on.
ADVERSARIAL = [
    f"trace id {uuid.UUID(int=random.getrandbits(128))} recorded",
    "mac address 3C:22:FB:9A:1D:04 registered",
    "gstin 27AAPFU0939F1ZV filed for the quarter",
    "isbn 978-3-16-148410-0 ordered",
    "released version 10.2.145.9 to canary",
    "the incident was on 2026.09.16 around noon",
    "blob SGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSB0b2tlbiBhdCBhbGw= attached",
    "write to user@localhost from the container",
    "the number 12345678901234 is an EAN code",
    "aadhaar-like 123456789012 fails the checksum",
    "priced at 1,23,45,678 rupees inclusive",
    "call the landline 011-2345-6789 instead",
    "employee id 9988776655 in the HR system",
    "docker image sha256:9f2a1c8e4b7d3a6f5e0c1b2d3a4f5e6c7b8a9d0e1f2a3b4c5d6e7f8a9b0c1d2e",
    "port 8080 and 192.168 subnet notation",
    "the coupon is FLAT500OFF until friday",
    "serial ABCDE12345 printed on the box",
    "latitude 12.9716 longitude 77.5946 for the warehouse",
    "run id 4111111111111111111111 truncated in logs",
    "reference AAAAA0000A is a dummy pan format",
]

TEMPLATES = [
    "Support case {tid}: {e}",
    "Agent notes --- {e}",
    "Customer follow-up. {e} Closing the loop.",
    "[escalated] {e}",
    "Summary for review:\n{e}\n-- end --",
    "WhatsApp message received: \"{e}\"",
]

SENTENCES = {
    "EMAIL":       ["write back on {}", "loop in {}", "confirmation went to {}"],
    "PHONE_IN":    ["ring {} between 10 and 6", "alternate number {}", "whatsapp on {}"],
    "PHONE_US":    ["international line {}", "try {} during PST hours"],
    "AADHAAR":     ["kyc doc shows {}", "aadhaar on file is {}"],
    "CREDIT_CARD": ["settlement failed for {}", "refund issued to {}"],
    "PAN":         ["pan on record {}", "tax id {} verified"],
    "IFSC":        ["neft to ifsc {}", "branch code {}"],
    "UPI_ID":      ["collect request to {}", "vpa {} declined"],
    "IP_ADDRESS":  ["login from {} flagged", "blocked {} after retries"],
    "JWT":         ["bearer {} expired", "stale token {} in the header"],
    "API_KEY":     ["leaked credential {} found in the repo", "revoke {} now"],
}


def build_doc():
    n = random.choices([1, 2, 3], weights=[40, 40, 20])[0]
    types = random.sample(list(SENTENCES.keys()), n)

    body, entities = "", []
    for t in types:
        val = genc.gen(t)
        before, after = random.choice(SENTENCES[t]).split("{}")
        body += before
        entities.append({"type": t, "value": val, "_off": len(body)})
        body += val + after + ". "

    # Adversarial negatives appear in most documents, which is what makes this
    # corpus harder than the development one.
    if random.random() < 0.7:
        body += random.choice(ADVERSARIAL) + ". "

    text = random.choice(TEMPLATES).format(e=body.strip(), tid=random.randint(100000, 999999))
    for ent in entities:
        idx = text.find(ent["value"])
        ent["start"], ent["end"] = idx, idx + len(ent["value"])
        del ent["_off"]
    entities = [e for e in entities if e["start"] >= 0 and text[e["start"]:e["end"]] == e["value"]]
    return {"text": text, "entities": entities}


def build_negative_doc():
    picks = random.sample(ADVERSARIAL, random.randint(2, 4))
    return {"text": " ".join(p.capitalize() + "." for p in picks), "entities": []}


def main():
    docs = [build_doc() for _ in range(150)]
    docs += [build_negative_doc() for _ in range(60)]
    random.shuffle(docs)

    out = pathlib.Path("testdata/holdout.jsonl")
    with out.open("w") as f:
        for i, d in enumerate(docs):
            d["id"] = f"hold-{i:04d}"
            f.write(json.dumps(d) + "\n")

    total = sum(len(d["entities"]) for d in docs)
    print(f"wrote {len(docs)} held-out documents, {total} labeled entities, "
          f"{sum(1 for d in docs if not d['entities'])} pure-negative documents")

if __name__ == "__main__":
    main()
