# Security policy

## Reporting a vulnerability

Do not open a public issue for security problems.

Report privately through
[GitHub Security Advisories](https://github.com/alpkeskin/jev-guardrail/security/advisories/new).
Include steps to reproduce and the affected version.

You will get an acknowledgement within 3 business days.

## Supported versions

Only the latest release receives security fixes.

## Scope notes

- `X-Client-ID` selects a policy. It is not an authentication mechanism.
- Request content is never logged by design.
- `tools/mockjev` is for development only. Never deploy it.
