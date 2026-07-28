# inject-probe

**Status: v0.1.0, not yet published to PyPI.** Everything described below works;
install from source until the first release.

## The problem

Prompt injection is not a model bug. It is an application bug.

An LLM application concatenates things with different levels of trust — a system
prompt, a user turn, a retrieved document, a tool result — into one flat string, and
then asks a model that has no reliable way to tell them apart to act on it. Text that
arrived from an untrusted source gets treated as instruction. That is the whole bug
class, and no amount of testing the *model* finds it, because the defect is in how
*your* application assembles the prompt.

`inject-probe` points a corpus of injection payloads at your application's entry point
and reports which ones got through, with a reproducible case for each.

### The tradeoff this makes

Every payload works the same way: it tries to make the target emit a **harmless canary
token**. If the token comes back, the injection worked.

That buys determinism — a substring check, no second model, no judgment call, the same
answer every run. It costs coverage: a payload that would have elicited something
genuinely harmful and a payload that elicits a canary are not the same payload, and a
system that blocks the second may not block the first. **The canary is a proxy for
"untrusted text reached the instruction channel", not proof your application is safe.**
That is the trade, made deliberately, and it is why the number this tool reports is a
regression signal rather than a safety certificate.

## What this does not do

- **No defending.** No filter, no sanitiser, no guardrail. It finds; it does not fix.
- **No jailbreak corpus, no harmful content.** Payloads request a canary string and
  nothing else. This is a fuzzer for one bug class — the same category of tool as a
  protocol fuzzer or OWASP ZAP.
- **No model hosting, no proxy, no web UI.**
- **Not a safety certificate.** See the tradeoff above.

Out of scope for v1, and stated here so the boundary is explicit rather than implied:
tool-call hijacking, system-prompt extraction, multi-turn escalation.

**Use on systems you own or are authorised to test.**

## Install

```bash
uv pip install git+https://github.com/Jesusw0w/inject-probe   # pip install inject-probe at first release
```

## Usage

Point it at an entry point. A target is any Python callable taking a prompt and,
ideally, a list of retrieved documents:

```python
# myapp/entrypoint.py
def app(prompt: str, documents: Sequence[str] = ()) -> str:
    ...
```

```console
$ inject-probe run --target myapp/entrypoint.py:app
PROBE                              CLASS     OUTCOME
---------------------------------  --------  ---------
direct.ignore_previous             direct    succeeded
direct.role_reassignment           direct    blocked
...
indirect.injected_document         indirect  succeeded
indirect.fake_tool_result          indirect  succeeded
...
encoding.base64_encoded            encoding  blocked

direct     1/4 succeeded (25.0%)
indirect   2/4 succeeded (50.0%)
encoding   0/7 succeeded (0.0%)
TOTAL      3/15 succeeded (20.0%)
```

`--json` records the exact payload and the exact response for every success, plus
the citation for the technique, so a finding can be reproduced and looked up.

The `documents` argument is the important one: it is how the harness tests
*indirect* injection, where the payload arrives inside retrieved content rather
than the user's message. A target that ignores it cannot be tested for the attack
class that matters most.

```console
$ inject-probe run --target app.py:app --json report.json   # full report, incl. every successful payload
$ inject-probe run --target app.py:app --attack-class direct
$ inject-probe list-probes
```

Non-Python applications are reached over HTTP:

```console
$ inject-probe run --target-url https://api.internal/ask \
    --prompt-field question --documents-field context --response-field data.reply \
    --header 'Authorization: Bearer $TOKEN'

$ inject-probe run --target-chat http://localhost:11434/v1/chat/completions --model llama3
```

The chat form works against any OpenAI-compatible server — vLLM, Ollama, LM
Studio, a gateway. There are no provider SDKs: the runtime dependencies are
`httpx` and `pydantic`, and that is the whole list.

### In CI

A run on its own exits `0` no matter how many probes succeed. That is deliberate:
no real system scores zero, so an absolute threshold is red on day one and gets
switched off by the end of the week. What gates a build is a *regression* against
a recorded run.

```console
$ inject-probe run --target app.py:app --json baseline.json    # record, commit this
$ inject-probe run --target app.py:app --baseline baseline.json # exit 1 on regression
```

- was blocked, now succeeds → **fails the build**
- was succeeding, now blocked → passes, reported as fixed
- absent from the baseline → reported as new; fails only with `--fail-on-new`

The baseline *is* a report — no second format. Reports carry no timestamps, so an
unchanged system produces byte-identical output and a committed baseline shows an
empty diff.

## Measured results

Every number below comes from the command printed above it, run against a target
checked into this repository. Nothing here is hand-written, and all of it
reproduces offline on a fresh clone — v1 is 15 probes across 3 attack classes.

```console
$ inject-probe run --target examples/vulnerable.py:app
direct     4/4 succeeded (100.0%)
indirect   4/4 succeeded (100.0%)
encoding   0/7 succeeded (0.0%)
TOTAL      8/15 succeeded (53.3%)
```

`examples/vulnerable.py` is a deliberately vulnerable retrieval app: it flattens
its system prompt, the user turn and retrieved documents into one string and acts
on any instruction in the result. Direct and indirect injection get through
completely.

**Its 0/7 on the encoding class is not a defence.** It scores zero there because
it never decodes base64 or ROT13 — not because it resisted anything. Read that
row as "untested", and read the class alongside the direct results, never alone.
This is exactly the shape of false comfort the tool is meant to make visible
rather than hide.

```console
$ inject-probe run --target examples/echoing.py:app
TOTAL      0/15 succeeded (0.0%)
```

`examples/echoing.py` quotes its input back and never follows an instruction — it
has no vulnerability. It is the control case: a harness that put the canary token
literally into its payloads would score this target 15/15 and report a perfect
success rate against a system that did nothing. Getting 0 here is the single most
important number in this table, and there is a test that sweeps 25 seeds to keep
it that way.

There are no numbers here for a hosted model. Producing them needs an API key and
a paid account, so they would not reproduce from a clone — and an unreproducible
benchmark is a marketing claim.

## Design decisions

Three choices shape everything else. Each has an ADR in `docs/adr/` covering what
was chosen, what was rejected, and why:

1. [Canary detection over LLM-judge scoring](docs/adr/0001-canary-detection-over-llm-judge.md)
   — and why the canary is never present in the payload it is carried by.
2. [Static, cited payloads over model-generated ones](docs/adr/0002-static-cited-payloads.md)
   — reproducibility over coverage.
3. [Regression baselines over absolute thresholds](docs/adr/0003-regression-baselines-over-thresholds.md)
   — why a run exits 0 at a 100% success rate.

Every payload cites published research in its docstring — `inject-probe
list-probes` prints them, and the corpus is drawn from the OWASP LLM Top 10 and
from Perez & Ribeiro, Greshake et al., Liu et al., Kang et al., and Boucher et al.

## Development

```bash
uv sync --extra dev
uv run nox           # lint + mypy --strict + pytest on 3.12 / 3.13 / 3.14
```

`docs/PLANNING.md` holds the architecture; `docs/PROGRESS.md` is the running log.

## AI assistance

This project was built with AI assistance (Claude Code), and disclosing that reads
better than concealing it.

How it was structured: the architecture, the attack taxonomy, the detection strategy
and the scope boundaries were specified by the author up front in a written brief. The
agent worked in small increments against that brief, one reviewable change at a time,
and ran no git operations — every commit in this history was reviewed and made by the
author. The payload corpus cites public research; citations were checked, not taken on
trust.

Where the author's judgment overrode the default output: the echo-suppression design
(see `docs/adr/`), the decision to ship three finished attack classes rather than
twelve stubs, and the removal of a speculative plugin registry, an LLM-judge detector
and several unused abstractions from the first draft.

## Licence

Apache-2.0. The patent grant is deliberate — it matters for security tooling.
