# REST operation inventory

`rest-operation-index.csv` is generated from the `paths` entries in `api/openapi/common.yaml` and their referenced domain documents. It lists every declared HTTP method by operation ID, path, source reference, tags, declared security and response keys. The generator resolves each path reference, rejects duplicate YAML keys and operation IDs, and compares method/path/operation ID triples against the checked-in `api/openapi.yaml` bundle. A match does not verify that either specification describes all behavior or that a backend exists.

Generate with Python 3 and PyYAML (Debian WSL already has `python3-yaml`):

```sh
python3 docs/ps5-port/inventory-rest-operations.py
python3 docs/ps5-port/inventory-rest-operations.py --check
```

This is generated reference data: do not edit it to track implementation. A separate, durable progress matrix must link each operation to handlers, tests, authorization and error behavior, and live PS5 evidence. Declared security and response keys are only a map to the source; inherited semantics, reusable references, request/response schemas, pagination, idempotency and authorization must be read from the specification. Direct auth/fetch endpoints, undocumented or dynamic calls, websockets and UI journeys are not included. Rebundle upstream specifications with the repository's normal tool before regenerating when they change; a matching bundle alone is not proof of a fresh bundle's complete equivalence.

The baseline generated on upstream `3083c34b0e9153b86c532112bdf0048202e91000` contains 407 operations over 334 paths from 21 domain files. Counts are descriptive of that checkout and should change when upstream changes; never use them as a target for implemented parity.

`rest-coverage.csv` is the separate initial tracking ledger, seeded with every operation and `unassessed` status. Update its handler, host evidence, PS5 evidence and limitations as work proceeds. The index generator intentionally never rewrites this ledger; after upstream changes, reconcile additions, removals and renamed operations manually so existing evidence is not lost. No populated row establishes parity without examining the linked evidence and applicable contract semantics.
