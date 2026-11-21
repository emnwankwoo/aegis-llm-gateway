# Security Policy

AegisGate is a portfolio and learning project. It demonstrates layered LLM
guardrails, but it is **not** a certified security product. Review the
Limitations section of the README before putting it in front of real traffic.

## Reporting a vulnerability

If you find a way to bypass a guardrail, leak data through the gateway, or
break authentication, please report it privately:

1. Open a [private security advisory](../../security/advisories/new) on this repository, **or**
2. Contact the maintainer through the GitHub profile.

Please don't open a public issue for an unpatched bypass. Include the prompt
or request you used, what you expected, and what happened. You'll get an
acknowledgement within a few days.

## Bypasses are welcome

Guardrail bypasses are useful findings, not embarrassments. Confirmed
bypasses get added to `tests/test_guardrails.py` as regression cases, with
credit if you'd like it.

## Supported versions

Only the latest commit on `main` is maintained.

## Handling secrets

* Never commit `.env`. It is listed in `.gitignore` and `.dockerignore`.
* All demo keys and sample credentials in this repo (for example
  `AKIAIOSFODNN7EXAMPLE`) are AWS's documented placeholders or invented test
  values. None of them grant access to anything.
