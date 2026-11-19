# 1. Canary detection over LLM-judge scoring

**Status:** accepted

**Chosen.** Every payload asks the target to emit a unique canary token, and detection
is an exact substring match for that token in the output. The token is never present in
the payload: it is carried as fragments (`CN,RY,44,f1,7f,45`) with an instruction to
join them, so producing it requires the target to have acted on the injected
instruction. Construction and detection share one `normalize()` function, and `Probe`
refuses to be built if its canary survives `normalize()` of its own input — which makes
the echo guarantee a proof rather than a hope.

**Rejected.** Using a second model to judge whether an injection succeeded, and
rejected alongside it the heuristic form of echo suppression: putting the literal token
in the payload and then discounting hits that appear inside a long verbatim copy of the
input. Also rejected: asking payloads to elicit genuinely harmful output, which is the
only thing that would *require* a judge.

**Why.** An LLM judge is non-deterministic, costs money per probe, needs an API key to
run the test suite, and makes the tool's own correctness depend on a model's opinion —
so two runs against an unchanged system can disagree, which destroys the baseline
comparison this tool exists to provide. The heuristic echo filter is worse than it
looks: it is a similarity threshold nobody can tune honestly, it fails silently in both
directions, and it would be guarding against a state the construction-time check
already makes impossible. The cost of the canary approach is real and worth stating: a
payload that elicits a canary is not the same as one that elicits harm, so a system
that blocks the canary may not block everything. The tool therefore reports a
regression signal, not a safety certificate — and that limitation is on the README, not
buried here. A judge remains available as an explicitly opt-in, explicitly
lower-confidence fallback if a future attack class genuinely cannot be canaried; it
will never be the default.
