# TASK

Fix issue {{TASK_ID}}: {{ISSUE_TITLE}}

Pull in the issue using `gh issue view <ID>`. If it has a parent PRD, pull that in too.

Only work on the issue specified.

Work on branch {{BRANCH}}. Make commits and run tests.

# IMPLEMENTATION BRIEF

The planner prepared this brief. Treat it as your execution contract unless it
conflicts with the issue body, parent PRD, repository instructions, or sibling
spec. If it conflicts, follow the higher-authority source and call out the
reason in the commit message.

<implementation-brief>
{{IMPLEMENTATION_BRIEF}}
</implementation-brief>

# CONTEXT

Here are the last 10 commits:

<recent-commits>

!`git log -n 10 --format="%H%n%ad%n%B---" --date=short`

</recent-commits>

# EXPLORATION

Explore the repo and fill your context window with relevant information that will allow you to complete the task.

Pay extra attention to test files that touch the relevant parts of the code.
Before coding, reconcile the issue, parent PRD if present, sibling spec, and
implementation brief into a short checklist for yourself. Use the brief to
avoid re-deciding architecture that the planner already made explicit.

# EXECUTION

If applicable, use RGR to complete the task.

1. RED: write one test
2. GREEN: write the implementation to pass that test
3. REPEAT until done
4. REFACTOR the code

Stay inside the brief's non-goals. If an escalation trigger fires, do not guess:
leave a concise issue comment explaining the blocker and avoid partial commits
unless they are independently correct and useful.

# FEEDBACK LOOPS

Before committing, run `npm run typecheck` and `npm run test` to ensure the tests pass.

For Rust changes, use red-green-refactor through the public crate interface.
Prefer `cargo fmt --all` before committing.

# COMMIT

Make a git commit. The commit message must:

1. Use an imperative summary that names the task completed
2. Include the PRD or issue reference
3. Call out key decisions made
4. Mention files changed when useful
5. Note blockers or next-iteration context when relevant

Keep it concise.

# THE ISSUE

If the task is not complete, leave a comment on the issue with what was done.

Do not close the issue - this will be done later.

Once complete, output <promise>COMPLETE</promise>.

# FINAL RULES

ONLY WORK ON A SINGLE TASK.
