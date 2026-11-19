# 3. Regression baselines over absolute thresholds in CI

**Status:** accepted

**Chosen.** `inject-probe run --baseline baseline.json` compares against a recorded run
and fails only on *regressions* — a probe that was blocked and now succeeds. A probe
that was succeeding and is now blocked is reported as fixed and does not fail. Probes
absent from the baseline are reported as new and fail only under `--fail-on-new`, and
only when they succeeded. The baseline file is an ordinary `--json` report, so there is
no second schema and `--json` doubles as the recording command. A run without
`--baseline` always exits `0`, whatever the success rate.

**Rejected.** Failing the build when any probe succeeds, and the softer variant of
failing above a configured success-rate threshold. Also rejected: a separate, slimmer
baseline file format holding only probe ids and outcomes.

**Why.** No real LLM application scores zero against this corpus — the example target
in this repository scores 53%, and that is a *deliberately* vulnerable stub, not an
outlier. A gate that fails whenever any probe succeeds is therefore red from the first
commit, and a gate that is always red gets disabled within a week; a gate everybody
ignores is worse than no gate, because it launders inattention as coverage. A
percentage threshold merely moves the arbitrary number rather than removing it, and
invites tuning the threshold instead of fixing the application. The question a team can
actually act on is "did this change make it worse", which is a diff against recorded
state. Two consequences follow and are enforced: the report carries no wall-clock time,
so an unchanged system produces byte-identical output and a committed baseline shows an
empty diff; and a baseline recorded against a different corpus version is refused
outright rather than warned about, because comparing a v1 baseline to a v2 corpus
produces confident nonsense. Errored probes are excluded from the comparison on both
sides — treating an unreachable target as "everything got fixed" would turn an outage
into a green build — and for the same reason any errored probe fails the gate: an
incomplete comparison is not a clean one.
