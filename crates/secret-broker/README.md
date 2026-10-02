# valutx-secret-broker

**Trust Level**: High Authority (Secrets Management)

## Purpose
Brokers access to credentials and tokens by reference. Models receive opaque handles (`SecretRef`) rather than raw secrets. Injects credentials at execution time inside the sandbox and scrubs outputs.

## Invariants & Restrictions (What it must NEVER do)
- **NEVER** expose raw credential values to the model, in prompts, or in tool responses.
- **NEVER** log, trace, or persist unmasked secrets.
- **NEVER** accept hardcoded test credentials in repository fixtures.
