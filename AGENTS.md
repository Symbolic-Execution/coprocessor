# Coprocessor Agent Instructions

## Project Overview

This repo implements the Symbolic Execution coprocessor: the off-chain private
execution system that monitors `symVM` events, reconstructs handle lineage,
resolves symbolic operations, and exposes materialized handle state to the
Coordinator.

The sibling spec repo is the current source of truth. Before changing behavior,
read the relevant files under `../spec`, especially:

- `../spec/README.md`
- `../spec/coprocessor/README.md`
- `../spec/coprocessor/domain-map.md`
- `../spec/coprocessor/coprocessor-api.md`
- `../spec/symvm/symvm-event-surface.md`
- `../spec/mpc/mpc-api.md`
- `../spec/coordinator/coordinator-api.md`

## Architecture Compass

Use the spec vocabulary:

- `symVM` is the on-chain handle registry and canonical event surface.
- The coprocessor host monitors chain events, tracks the handle graph, schedules
  resolution, calls `MPC`, and serves the internal Coordinator API.
- The enclave performs private computation, verifies enclave AAD, and returns
  encrypted `SystemCiphertextV1` plus receipts.
- `MPC` is the threshold key custody and ciphertext transformation system.
- The Coordinator owns public authorization, disclosure request lifecycle,
  reader registration, and `to-reader` transforms.

Do not move these responsibilities into the coprocessor:

- EIP-712 disclosure authorization
- reader key registration or rotation
- `SystemCiphertextV1 -> ReaderCiphertextV1`
- on-chain controller/policy checks for disclosure
- raw MPC key custody
- plaintext handling in the host

## Coding Style

Design for deep modules.

A module is anything with an interface and an implementation. An interface is
everything a caller must know: types, invariants, ordering, errors, config, and
performance expectations. A deep module gives high leverage through a small
interface; a shallow module makes callers learn almost as much as the
implementation.

When shaping code:

- Prefer modules that hide real complexity behind a stable interface.
- Apply the deletion test: if deleting a module only moves its complexity into
  callers, it was earning its keep; if complexity vanishes, it was likely a
  pass-through.
- Treat the interface as the test surface. Tests should verify observable
  behavior through public interfaces, not private helpers or internal state.
- Use seams where behavior genuinely varies: chain RPC, persistence, MPC,
  enclave runtime, HTTP server, and clock/randomness are plausible seams.
- Avoid speculative adapters. One adapter is a hypothetical seam; two adapters
  usually prove the seam is real.
- Keep pure domain logic close to the module that owns the invariant. Do not
  scatter handle-lineage, AAD, or operation-arity rules across call sites.
- Prefer domain names from `CONTEXT.md` and the spec over generic names like
  manager, processor, helper, util, or service.

## Testing

Use red-green-refactor for behavior changes once a test framework exists.

Test at stable interfaces:

- ingestion tests should feed canonical `symVM` events and assert handle state
- graph tests should assert ordered dependencies and invalid lineage failures
- scheduler tests should assert deduped resolution and state transitions
- enclave executor tests should assert operation semantics and AAD validation
- API tests should assert Coordinator-facing response shapes and error mapping

Prefer spec-shaped fixtures over arbitrary examples. Cover `suint256`, `sbool`,
`Select`, orphan/reorg handling, duplicate handles, unknown inputs, wrong arity,
wrong handle type, MPC failures, enclave failures, and repeated resolve
requests.

## Security And Privacy

- The host must never receive, log, persist, or return plaintext private values.
- Treat ciphertext AAD as part of the security model, not metadata decoration.
- Validate `chain_id`, `domain_id`, `handle_id`, `type_tag`, and `key_id` at the
  module that owns the transition.
- Logs and errors may include handle ids and request ids, but must not include
  plaintext, data-encryption keys, reader secrets, enclave private keys, or raw
  decrypted payloads.
- Do not commit `.env` files, keys, attestations containing secrets, or local
  chain credentials.
