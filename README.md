# PIIShield

A drop-in redaction proxy that sits between your application and an LLM
provider. Sensitive values are replaced with reversible tokens before the
request leaves your network, and restored in the response — so the model never
sees real customer data, and your code never knows the difference.

Point your client at PIIShield instead of the provider. That is the entire
integration:

```diff
- base_url = "https://generativelanguage.googleapis.com/v1beta/openai"
+ base_url = "http://localhost:8080/v1"
```

## What it does

```
  request                                                        upstream
  ───────►  ┌──────────┐   detect   ┌────────┐   tokenize   ┌──────────┐
            │  policy  │ ─────────► │ vault  │ ───────────► │ provider │
  ◄───────  └──────────┘  rehydrate └────────┘   restore    └──────────┘
  response
```

Given this prompt:

> My name is Anwesha Yadav, email anwesha.y@example.com, phone 9876543210.
> Write a one-line order confirmation addressed to me that repeats my email.

the provider actually receives:

> My name is `[[PERSON_NAME_1]]`, email `[[EMAIL_1]]`, phone `[[PHONE_IN_1]]`.
> Write a one-line order confirmation addressed to me that repeats my email.

and the caller gets back:

> Dear **Anwesha Yadav**, your order is confirmed and a receipt has been sent
> to **anwesha.y@example.com**.

The proxy log records `EMAIL=1 PHONE_IN=1 PERSON_NAME=1 (3 distinct values
tokenized)` — entity types and counts only. Logging the values themselves would
recreate, inside the proxy's own logs, exactly the exposure the proxy exists to
prevent.

## Results

Two numbers are reported, because only one of them is honest.

| Corpus | Documents | Spans | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Development (detectors tuned against it) | 250 | 389 | 1.000 | 1.000 | 1.000 |
| **Held-out (never used for tuning)** | **210** | **257** | **0.889** | **1.000** | **0.941** |

The held-out figure is the one worth quoting. The development corpus scores a
perfect 1.000 precisely because it was used while fixing detectors, which makes
it an upper bound rather than an estimate of real performance.

**Latency** — detection and redaction only, excluding upstream time:

| p50 | p95 | p99 | Throughput |
|---|---|---|---|
| 34 µs | 66 µs | 87 µs | ~27,000 documents/sec/core |

Redaction is roughly three orders of magnitude cheaper than the model call it
protects, which is what makes the proxy viable in a synchronous request path.

### The benchmark earned its keep

Scoring the first working version against the corpus moved precision from
**0.906 to 1.000** by exposing four real bugs that reading the code had not:

1. **A tracking number scored as a credit card.** Luhn is a single check digit,
   so about one in ten arbitrary digit strings passes it — an 18-digit tracking
   number did. Fixed by also validating issuer prefix and card length.
2. **`bank` matched inside `okhdfcbank`.** Context keywords were compared with
   substring matching, so an unrelated UPI handle 48 bytes away licensed a
   bank-account match on the placeholder `000000000000`. Fixed with
   word-boundary matching.
3. **Phone numbers were redacted without their country code**, so the label and
   the redaction disagreed about where the entity ended and `+91` was left
   dangling in the outbound prompt.
4. **`\b` truncated JWTs.** A base64url signature may end in `-` or `_`, which
   are not word characters, so a trailing word boundary refused to close the
   match and left the final character of the signature in the prompt.

### Known false positives, deliberately unfixed

All 32 held-out false positives come from three classes, and each is a genuine
ambiguity rather than a sloppy pattern:

| Value | Detected as | Why it is hard |
|---|---|---|
| `9988776655` | `PHONE_IN` | An employee ID that is ten digits starting with 9. Pattern-identical to an Indian mobile, and no checksum exists to separate them. |
| `AAAAA0000A` | `PAN` | A dummy PAN. Structurally a *valid* PAN — arguably the detector is right and the label is wrong. |
| `10.2.145.9` | `IP_ADDRESS` | A software version string that is also a syntactically valid IPv4 address. |

These are left in place on purpose. Tuning against the held-out set would stop
it being held out, and the resulting number would mean nothing. Fixing them
properly needs signal a regex does not have — see *Limitations*.

## Quickstart

```bash
export GEMINI_API_KEY=...        # any OpenAI-compatible provider works
make run                          # or: make docker
```

```bash
curl localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gemini-flash-lite-latest",
       "messages":[{"role":"user","content":"Email anwesha.y@example.com about order 5512"}]}'
```

Streaming works identically — add `"stream": true`.

```bash
make test        # unit tests
make bench       # score against the development corpus
make holdout     # score against the held-out corpus
make corpus      # regenerate both corpora (deterministic)
```

`/metrics` exposes Prometheus counters; `docker compose up` brings up Prometheus
alongside the proxy.

## Design decisions worth knowing

**Tokens are reversible; masks are not.** Most entities become
`[[EMAIL_1]]` and are restored on the way back. Card numbers are masked to
`****1111` instead — the caller does not need the full number returned, and not
holding it in memory at all is strictly safer. Credentials (`API_KEY`, `JWT`)
are *blocked*: the request is rejected with HTTP 422, because a tokenized API
key is still an API key the moment the response is re-hydrated.

**One vault per request.** A process-wide vault would let a token minted for one
tenant re-hydrate inside another tenant's response — the worst possible failure
for a product whose only job is stopping data crossing a boundary.

**The same value always gets the same token.** If one email appears twice, both
become `[[EMAIL_1]]`. Otherwise the model sees two different placeholders and
can no longer tell that the sender and the recipient are the same person.

**Replacement walks backwards.** Rewriting spans from the end of the document
keeps every unprocessed offset valid. Going forwards invalidates every offset
after the first substitution of a different length — the classic bug in this
kind of code, and the reason for `TestOffsetsSurviveLengthChangingReplacements`.

**Streaming holds back partial tokens.** The provider splits output on
boundaries that have nothing to do with ours, so `[[EMAIL_1]]` can arrive as
`[[EMA` + `IL_1]]`. The rewriter withholds any trailing text that could still
become a placeholder and releases it once the completing chunk arrives — a
single trailing `[` counts. `TestStreamRehydratesTokenSplitAcrossChunks`
verifies every one of the 32 possible split points of one token.

**Unknown tokens survive rehydration.** If the model invents `[[EMAIL_9]]` that
was never minted, it is left visible rather than deleted, so the model's mistake
is obvious instead of silently corrupting the response.

**The request body is passed through as a generic map**, not a typed struct, so
provider-specific fields the proxy knows nothing about survive the round trip.
A proxy that silently eats parameters is worse than no proxy.

## Limitations

These are real and stated on purpose.

- **Name detection is cue-based and has low recall.** It fires on "my name is
  X" and similar phrasings, so `for Anwesha Yadav` is missed. Proper coverage
  needs a named-entity-recognition model; the `Detector` interface exists so one
  can be added without touching anything else.
- **Only text is scanned.** Multimodal image parts pass through untouched. A
  photographed Aadhaar card is invisible to this proxy.
- **The corpus is synthetic.** It is built from templates with ground truth
  recorded as values are inserted, which makes labels exact but the distribution
  cleaner than real support traffic.
- **The vault is in-memory and per-request**, so tokens do not survive across
  turns of a conversation. A session-scoped store is the natural next step.
- **Detection is regex and checksum based.** It cannot resolve the three
  false-positive classes above, which need either surrounding-context modelling
  or an NER model.

## Layout

```
cmd/proxy      the proxy binary
cmd/bench      benchmark scorer (precision/recall/F1 + latency)
internal/detect   detectors, checksums, overlap resolution
internal/policy   what happens to each entity class
internal/vault    token <-> value mapping, per request
internal/redact   applies policy, rewrites text, scans responses
internal/proxy    HTTP handler, SSE streaming rewriter
tools/         corpus generators (deterministic)
```

Go 1.25 · ~2,400 lines · 19 test functions · no runtime dependencies beyond
Prometheus client and a YAML parser.
