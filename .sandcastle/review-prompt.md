# TASK

Review the code changes on branch `{{BRANCH}}` against the implementation
brief, issue intent, repository instructions, and sibling spec. Improve the
branch directly when the correction is clear and safe.

# IMPLEMENTATION BRIEF

<implementation-brief>
{{IMPLEMENTATION_BRIEF}}
</implementation-brief>

# CONTEXT

## Branch diff

!`git diff {{TARGET_BRANCH}}...{{BRANCH}}`

## Commits on this branch

!`git log {{TARGET_BRANCH}}..{{BRANCH}} --oneline`

# REVIEW PROCESS

1. **Understand the change**: Read the diff and commits above, then inspect the
   changed files and nearby tests as needed. Reconstruct the issue intent from
   the implementation brief and branch commits.

2. **Check planner-contract drift**: Prioritize concrete mismatches with the
   brief before style cleanup:
   - Behavior/spec mismatch
   - Wrong responsibility boundary
   - Missing stable-interface tests
   - Security/privacy leakage
   - Shallow or pass-through abstractions
   - Ambiguous error mapping or state transitions
   - Work that crossed a listed non-goal

3. **Analyze for improvements**: Look for opportunities to:
   - Reduce unnecessary complexity and nesting
   - Eliminate redundant code and abstractions
   - Improve readability through clear variable and function names
   - Consolidate related logic
   - Remove unnecessary comments that describe obvious code
   - Avoid nested ternary operators - prefer switch statements or if/else chains
   - Choose clarity over brevity - explicit code is often better than overly compact code

4. **Check correctness**:
   - Does the implementation match the intent? Are edge cases handled?
   - Are new/changed behaviours covered by tests?
   - Are there unsafe casts, `any` types, or unchecked assumptions?
   - Does the change introduce injection vulnerabilities, credential leaks, or other security issues?

5. **Maintain balance**: Avoid over-simplification that could:
   - Reduce code clarity or maintainability
   - Create overly clever solutions that are hard to understand
   - Combine too many concerns into single functions or components
   - Remove helpful abstractions that improve code organization
   - Make the code harder to debug or extend

6. **Apply project standards**: Follow the coding standards defined in @.sandcastle/CODING_STANDARDS.md

7. **Preserve intended functionality**: Do not change the issue's intended
   behavior except to fix drift from the brief, issue, spec, or tests.

# EXECUTION

If you find improvements to make:

1. Make the changes directly on this branch
2. Run tests and type checking to ensure nothing is broken
3. Commit describing the refinements

If the code is already clean and well-structured, do nothing.

If a blocker remains, make the blocker concrete enough for the next resolver
pass to act on: name the file, expected correction, and why it matters.

Once complete, output a JSON object wrapped in `<review>` tags:

<review>
{"approved": true, "summary": "Change is correct and ready to merge.", "blockers": [], "testNotes": "npm run typecheck and npm run test passed."}
</review>

Set `approved` to `false` if there are correctness, safety, merge-readiness, or test blockers you cannot fix in this review pass. Put concrete unresolved blockers in `blockers`.
