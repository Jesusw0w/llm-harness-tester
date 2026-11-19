# 2. Static, cited payloads over model-generated ones

**Status:** accepted

**Chosen.** The corpus is a fixed set of payloads written as Python functions, each
carrying a docstring that cites published research — the docstring *is* the citation,
read at build time with `inspect.getdoc`, so a payload cannot exist without one. The
corpus is versioned, and v2 is held out: authored later, from public sources only, and
never written with any particular defence in view.

**Rejected.** Generating payloads with a model at run time, which is what most modern
red-teaming tools do, and which would give far broader coverage per unit of effort.
Also rejected: adding or tuning a payload because some filter caught or missed it.

**Why.** Reproducibility is the property that makes this tool useful in CI. A
model-generated corpus means the set of probes changes between runs, so a baseline
comparison cannot distinguish "the application got worse" from "the generator had a
different idea today" — and that comparison is the entire product. Static payloads also
make every result auditable: a reader can see the exact bytes that were sent, look up
the paper the technique came from, and judge whether the finding is real. The citation
requirement does a second job, which is why it is enforced structurally rather than by
convention: it keeps the corpus anchored to public research rather than to whatever a
particular defence happens to block. A benchmark tuned against the thing it
measures is marketing; a held-out one is evidence, and that property is destroyed
silently and permanently the first time a payload is adjusted to make a filter look
good. The accepted cost is coverage — a fixed corpus of fifteen probes finds less than
an adaptive attacker would, and the README says so rather than implying completeness.
