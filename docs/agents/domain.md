# Domain Docs

How engineering skills should consume this repo's domain documentation when
exploring the codebase.

## Before exploring, read these

- `CONTEXT.md` at the repo root, if it exists.
- `docs/adr/`, reading ADRs that touch the area being changed.
- The sibling spec files under `../spec` that define the relevant protocol
  surface.

If `CONTEXT.md` or `docs/adr/` does not exist yet, proceed silently. Do not
create them just to satisfy this file. The producer skill, `grill-with-docs`,
creates them lazily when terms or decisions actually get resolved.

## Layout

This repo is currently single-context:

```text
/
├── CONTEXT.md
├── docs/
│   ├── agents/
│   └── adr/
└── src/
```

If the coprocessor grows into genuinely separate contexts with separate domain
languages, introduce `CONTEXT-MAP.md` later and point it at each context's
`CONTEXT.md`.

## Use the glossary's vocabulary

When output names a domain concept, use the term as defined in `CONTEXT.md` and
the sibling specs. Do not drift to synonyms the glossary explicitly avoids.

If the concept is missing, either reconsider the wording or note the gap for
`grill-with-docs`.

## Flag ADR conflicts

If a change contradicts an existing ADR, surface it explicitly rather than
silently overriding it.
