# TASK

Resolve merge conflicts on branch `{{BRANCH}}` for issue {{TASK_ID}}:
{{ISSUE_TITLE}}

The branch is currently in the middle of merging `origin/{{DEFAULT_BRANCH}}`.
Your job is only to finish that merge safely.

# IMPLEMENTATION BRIEF

Use this brief to preserve the issue branch's intended behavior while resolving
conflicts. Do not use it as permission to add new feature work during the merge.

<implementation-brief>
{{IMPLEMENTATION_BRIEF}}
</implementation-brief>

# CONFLICTED FILES

```text
{{CONFLICTED_FILES}}
```

# RULES

- Do not implement new feature work.
- Do not refactor unrelated code.
- Preserve both sides' intent: keep the issue branch behavior and keep the
  latest `origin/{{DEFAULT_BRANCH}}` behavior.
- When manifests, lockfiles, workspace members, or generated metadata conflict,
  include both valid additions and regenerate metadata with the repo's normal
  tooling when needed.
- Resolve conflicts through the smallest correct edits.
- Never discard `origin/{{DEFAULT_BRANCH}}` changes just to make the conflict go
  away.
- Never discard issue-branch changes unless they are truly superseded by
  equivalent code already on `origin/{{DEFAULT_BRANCH}}`.

# EXECUTION

1. Inspect `git status`.
2. Inspect each conflicted file.
3. Resolve every conflict marker.
4. Run `cargo fmt --all` if Rust/TOML files changed.
5. Run `npm run typecheck`.
6. Run `npm run test`.
7. Finish the merge with a commit. If Git still has `MERGE_HEAD`, prefer
   `git commit --no-edit`; otherwise commit only the conflict-resolution edits.

# OUTPUT

When the merge is resolved, tests pass, and the worktree is clean, output:

<promise>COMPLETE</promise>
