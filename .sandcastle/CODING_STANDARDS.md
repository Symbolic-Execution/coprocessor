# Coding Standards

<!-- Customize this file with your project's coding standards.
     The reviewer agent loads it during code review via @.sandcastle/CODING_STANDARDS.md
     so these standards are enforced during review without costing tokens during implementation. -->

## Style

- Use the vocabulary in `CONTEXT.md` and the sibling `../spec` repo.
- Prefer Rust names that mirror the domain terms where natural.
- Run `cargo fmt --all` before committing.
- Keep public interfaces small and behavior-oriented.

## Testing

- Use red-green-refactor for implementation issues.
- Test through public crate interfaces, not private helpers.
- Prefer spec-shaped fixtures over arbitrary examples.
- Run `npm run typecheck` and `npm run test` before committing.

## Architecture

- Design for deep modules: small stable interfaces hiding real behavior.
- Keep raw chain/RPC, persistence, MPC, Enclave runtime, and HTTP concerns out
  of the Handle Graph Core unless an issue explicitly brings them in.
- Respect ADRs in `docs/adr/`.
