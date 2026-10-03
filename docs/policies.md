# Policies

Policies are YAML files in `GUARDRAIL_POLICY_DIR` (default `policies/`).
They are loaded and validated once at startup.

```yaml
version: "1"
client_id: customer-a        # authoritative ID; the filename is irrelevant
description: optional free text
rules:
  prompt_injection:
    enabled: true            # optional, defaults to true
    threshold: 0.80          # required, in (0, 1]; matches when score >= threshold
    action: block            # required: block | review
  sensitive_data:
    threshold: 0.90
    action: review           # report as a finding, do not block
```

* **`policies/default.yaml` is mandatory** and must declare
  `client_id: default`. It is used when `X-Client-ID` is missing or unknown.
  Other files may not use the `default` client ID.
* The policy store is indexed by the `client_id` inside each file, not by
  filename. Client IDs are case-sensitive. When a supplied `X-Client-ID`
  falls back to the default policy, every log line for that request carries
  `policy_fallback: true`.
* Startup fails if the default policy is missing or invalid, if any policy
  file is malformed or invalid, or if two files share a `client_id`.
  Validation rejects all of the following:
  * unknown fields (typos)
  * unknown categories
  * thresholds outside (0, 1]
  * unknown actions
  * unsupported versions
  * policies with no rules
  * multiple YAML documents in one file
* Only the enabled categories are sent to Jev.

## Taxonomy

These identifiers are stable. Clients depend on them, so they must never
be renamed. New values may be added.

| Category                | Policy rule key            | Meaning |
|-------------------------|----------------------------|---------|
| `PROMPT_INJECTION`      | `prompt_injection`         | Attempts to override existing instructions |
| `JAILBREAK`             | `jailbreak`                | Attempts to bypass safety restrictions |
| `SYSTEM_PROMPT_LEAK`    | `system_prompt_extraction` (alias `system_prompt_leak`) | Extracting or leaking the system prompt |
| `SECRET_EXFILTRATION`   | `secret_exfiltration`      | Secrets or credentials being exfiltrated |
| `SENSITIVE_DATA`        | `sensitive_data`           | Sensitive or personal data |
| `MALICIOUS_INSTRUCTION` | `malicious_instruction`    | Instructions intended to cause harm |
| `MALICIOUS_URL`         | `malicious_url`            | Malicious or suspicious URLs |
| `UNSAFE_CONTENT`        | `unsafe_content`           | Otherwise unsafe content |

**Reason codes:** for `BLOCKED`, `reason.code` is one of the categories
above. For `FAILED`, it is one of `INVALID_REQUEST`, `INVALID_POLICY`,
`JEV_ERROR`, `JEV_TIMEOUT`, `JEV_UNAVAILABLE`, `UNSUPPORTED_CONTENT` or
`INTERNAL_ERROR`. When several blocking findings match, the primary reason
is the highest-scoring one, with ties broken by the table order above.
Reason and finding messages are fixed strings owned by this service. Jev's
explanations are never exposed.
