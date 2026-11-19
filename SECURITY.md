# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/Jesusw0w/llm-harness-tester/security/advisories/new)
rather than in a public issue. Include the version, steps to reproduce, and the
impact you expect.

This is a single-maintainer project. Expect an acknowledgement within a week.

## Scope

In scope: bugs in `inject-probe` itself, for example a report that marks a
successful injection as blocked, a probe whose canary leaks into its own input,
or unsafe handling of target responses or baseline files.

Out of scope: prompt-injection weaknesses in the systems you test with this
tool. Finding those is what the tool is for. Report them to whoever owns that
system.

## Supported versions

Only the latest release receives fixes.
