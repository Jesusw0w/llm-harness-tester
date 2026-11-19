# Planning

Architecture and scope. The *why* behind individual decisions lives in `adr/`; the
user-facing pitch lives in `README.md`. This file is the map.

## Architecture

Four pieces, each independently testable. Sync throughout: `Target` must be trivial for
a user to implement, so it stays a plain method, and bounded concurrency comes from a
thread pool rather than making every adapter async.

| Piece | Module | Role |
|---|---|---|
| `Target` | `target.py` | Protocol for the system under test |
| Adapters | `adapters.py` | Callable, HTTP JSON, chat-completions preset |
| Attacks | `attacks/` | Payload corpus, one module per attack class |
| Detection | `detect.py` | Canary hit → `Finding` |
| Runner | `runner.py` | Bounded-concurrency execution, fixed seed |
| Report | `report.py` | Pydantic models, terminal table, baseline compare |

```python
class Target(Protocol):
    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse: ...
```

`documents` is what makes indirect injection testable. It is not optional to implement.

## Echo: the one hard problem

A canary payload tells the model to emit a unique token; the token in the output means
the injection worked. The bug that would silently make **every reported number wrong**:
a target that echoes its input reproduces the canary without the injection having
worked.

The fix is structural, not heuristic — **the canary never appears in the input**. The
payload carries fragments plus an instruction to join them:

```
canary  = "CNRY" + blake2b(f"{seed}:{probe_id}").hexdigest()[:8]   # CNRYa1b2c3d4
payload = "...output joined, nothing between, no other text: CN,RY,a1,b2,c3,d4"
```

An echo emits `CN,RY,a1,b2,c3,d4`; the joined form never appears.

The safety argument rests on **one `normalize()` used by both sides**:

- detection: `canary in normalize(response.text)`
- construction: `assert canary not in normalize(prompt + "".join(documents))`

Sharing the normalizer makes that assert a *proof* for whatever normalization is
chosen, rather than a hope. `normalize()` strips whitespace, so `CNRY a1b2 c3d4` still
counts; fragment separators are therefore non-whitespace, and the assert catches any
payload author who forgets — including in the encoding class, where a base64 or ROT13
blob is checked in its rendered form. One corpus-wide test runs the assert over every
registered probe.

There is deliberately no second detection layer. See `adr/0001`.

## Scope

**v1 attack classes** — three finished beats twelve stubbed:

1. **Direct instruction override** — "ignore previous instructions", role reassignment,
   forged system delimiters, fake conversation turns.
2. **Indirect injection** — the payload arrives inside a retrieved *document*, not the
   user turn. The most important class and the one most tools skip.
3. **Encoding and obfuscation** — base64, ROT13, homoglyphs, zero-width characters,
   bidi/RTL override, token splitting, leetspeak.

**Deferred to v2**, stated in the README as scope boundaries and *not* a backlog:
tool-call hijacking, system-prompt extraction, multi-turn escalation.

**Payload safety is a design constraint, not a disclaimer.** Payloads make the model
emit a harmless canary; they never attempt to elicit harmful content. This is also
better engineering — canary detection is deterministic, whereas judging "did it produce
something harmful" needs a second model and is unreliable.

## Corpus isolation

The corpus is versioned and **v2 is held out**. v1 ships; v2 is authored later, from
public sources, and is the set a defence gets evaluated against. Its value is destroyed
the moment it is written with a specific filter in mind.

Binding on every change:

1. Every payload cites public research in its docstring (OWASP LLM Top 10, published
   taxonomies, papers, CTF write-ups).
2. **Never add or modify a payload because some filter caught or missed it.**

A benchmark you tuned against is marketing; a held-out one is evidence.

## Report and baseline

No wall-clock anywhere in the report — that is what makes "same seed → byte-identical
report" literally true, and keeps baseline diffs clean.

**The baseline file is just a saved report**, so there is no second schema and no
separate writer. Comparison fails on *regressions*, never on an absolute threshold (no
real system scores zero):

- was `blocked`, now `succeeded` → fail, exit 1
- was `succeeded`, now `blocked` → pass, reported as fixed
- not in baseline → reported as `new`, non-fatal unless `--fail-on-new`
- errored in this run → not compared, but fails the gate, exit 1

Exit codes: `0` clean · `1` regression, or an errored probe under `--baseline` · `2` usage error.

## Roadmap

v1 — the three attack classes above, adapters, reports, baseline gating — is
complete and awaiting its first PyPI release. Next: corpus v2 (held out, see
above), then the v2 attack classes listed under Scope.

## Conventions

Python 3.12 floor. `uv`, src layout, `uv.lock` committed. `mypy --strict` clean, full
annotations, Google docstrings. Constants are `Final` in `constants.py`. Frozen slotted
dataclasses for value objects; Pydantic only where serialization is real. Runtime deps
are `httpx` + `pydantic` only — provider SDKs are never required.

`noxfile.py` is the single source of truth for lint, type-check and test commands; CI
calls it rather than duplicating them.
