import * as sandcastle from "@ai-hero/sandcastle";
import { docker } from "@ai-hero/sandcastle/sandboxes/docker";
import { z } from "zod";
import { claudeAgent, codexAgent } from "./agents.mts";
import {
  CommandError,
  fetchRemoteBranch,
  formatError,
  git,
  pushBranch,
  redactSecrets,
  refreshDefaultBranch,
  runCommand,
} from "./git.mts";
import type {
  GithubClient,
  GithubConfig,
  GithubIssue,
  ImplementationBrief,
  PlannedIssue,
} from "./github-client.mts";
import {
  buildBlockedComment,
  buildPullRequestBody,
  parseReview,
  truncateForComment,
  type QualityGateResult,
  type Review,
} from "./review-output.mts";
import {
  readCachedApprovedReview,
  writeCachedReview,
} from "./review-cache.mts";
import { repairManagedWorktreeSubmodules } from "./worktree-repair.mts";

const CODEX_AUTH_MOUNT = "/home/agent/.codex-host";
const CODEX_SANDBOX_HOME = "/home/agent/.codex";

const hooks = {
  sandbox: {
    onSandboxReady: [
      { command: "npm install" },
      {
        command: [
          `if [ ! -f ${CODEX_AUTH_MOUNT}/auth.json ]; then echo "Missing Codex subscription auth at ${CODEX_AUTH_MOUNT}/auth.json" >&2; exit 1; fi`,
          `mkdir -p ${CODEX_SANDBOX_HOME}`,
          `cp -f ${CODEX_AUTH_MOUNT}/auth.json ${CODEX_SANDBOX_HOME}/auth.json`,
          `if [ -f ${CODEX_AUTH_MOUNT}/config.toml ]; then cp -f ${CODEX_AUTH_MOUNT}/config.toml ${CODEX_SANDBOX_HOME}/config.toml; fi`,
          `chmod 600 ${CODEX_SANDBOX_HOME}/auth.json`,
        ].join(" && "),
      },
    ],
  },
};

const copyToWorktree = ["node_modules"];
const MAX_SYNC_REVIEW_PASSES = 3;
const RESOLVER_IDLE_TIMEOUT_SECONDS = 1800;
const plannerAgent = claudeAgent("claude-opus-4-8");
const implementerAgent = claudeAgent("claude-sonnet-4-6");
const resolverAgent = claudeAgent("claude-sonnet-4-6");
const reviewerAgent = codexAgent("gpt-5.5", { effort: "high" });

const implementationBriefSchema = z.object({
  intent: z.string(),
  nonGoals: z.array(z.string()).default([]),
  designDecisions: z.array(z.string()).default([]),
  filesLikelyTouched: z.array(z.string()).default([]),
  testsRequired: z.array(z.string()).default([]),
  securityPrivacyChecks: z.array(z.string()).default([]),
  escalationTriggers: z.array(z.string()).default([]),
});

const planSchema = z.object({
  issues: z.array(
    z.object({
      id: z.string(),
      title: z.string(),
      branch: z.string(),
      implementationBrief: implementationBriefSchema,
    }),
  ),
});
type PlannedIssueOutput = z.infer<typeof planSchema>["issues"][number];

export async function planIssues(
  openIssues: GithubIssue[],
  allOpenIssues: GithubIssue[],
  token: string,
  issueLabel: string,
  codexHome: string,
): Promise<PlannedIssue[]> {
  const externalOpenIssues = allOpenIssues.filter(
    (issue) => !issue.labels.includes(issueLabel),
  );
  const plan = await sandcastle.run({
    hooks,
    sandbox: sandcastleDocker(token, codexHome),
    name: "planner",
    maxIterations: 1,
    agent: plannerAgent,
    promptFile: "./.sandcastle/plan-prompt.md",
    promptArgs: {
      ISSUES_JSON: JSON.stringify(openIssues, null, 2),
      EXTERNAL_OPEN_ISSUES_JSON: JSON.stringify(externalOpenIssues, null, 2),
      ISSUE_LABEL: issueLabel,
    },
    output: sandcastle.Output.object({ tag: "plan", schema: planSchema }),
  });

  const issuesById = new Map(openIssues.map((issue) => [issue.id, issue]));

  return plan.output.issues.map((planned: PlannedIssueOutput) => {
    const issue = issuesById.get(planned.id);
    if (!issue) {
      throw new Error(`Planner returned unknown issue id: ${planned.id}`);
    }

    const expectedBranch = branchForIssue(issue.id);
    if (planned.branch !== expectedBranch) {
      throw new Error(
        `Planner returned branch ${planned.branch} for issue ${planned.id}; expected ${expectedBranch}`,
      );
    }

    return {
      ...issue,
      branch: planned.branch,
      implementationBrief: planned.implementationBrief,
    };
  });
}

export async function runIssueWorkflow(options: {
  issue: PlannedIssue;
  github: GithubConfig;
  githubClient: GithubClient;
  defaultBranch: string;
  codexHome: string;
}) {
  const { issue, github, githubClient, defaultBranch, codexHome } = options;
  const implementationBrief = formatImplementationBrief(
    issue.implementationBrief,
  );
  await repairManagedWorktreeSubmodules(issue.branch);

  const sandbox = await sandcastle.createSandbox({
    branch: issue.branch,
    baseBranch: `origin/${defaultBranch}`,
    sandbox: sandcastleDocker(github.token, codexHome),
    hooks,
    copyToWorktree,
  });

  let branchCommits: string[] = [];
  let review: Review = {
    approved: false,
    summary: "Reviewer did not run.",
    blockers: ["Reviewer did not run."],
    testNotes: "",
  };
  let gate: QualityGateResult = {
    passed: false,
    summary: "Quality gates were not run.",
    details:
      "Reviewer approval is required before running final quality gates.",
  };

  try {
    const implement = await sandbox.run({
      name: "implementer",
      maxIterations: 100,
      agent: implementerAgent,
      promptFile: "./.sandcastle/implement-prompt.md",
      promptArgs: {
        TASK_ID: issue.id,
        ISSUE_TITLE: issue.title,
        BRANCH: issue.branch,
        IMPLEMENTATION_BRIEF: implementationBrief,
      },
    });

    branchCommits = await listBranchCommitsSince(
      `origin/${defaultBranch}`,
      issue.branch,
    );

    if (branchCommits.length === 0) {
      console.log(`#${issue.number}: no commits produced; no PR created.`);
      return;
    }

    if (implement.commits.length === 0) {
      console.log(
        `#${issue.number}: no new commits this run; reviewing ${branchCommits.length} existing commit(s).`,
      );
    }

    for (let syncPass = 1; syncPass <= MAX_SYNC_REVIEW_PASSES; syncPass++) {
      const preReviewSync = await syncIssueBranchWithDefault({
        sandbox,
        issue,
        github,
        defaultBranch,
      });
      if (preReviewSync.changed) {
        console.log(
          `#${issue.number}: synced ${issue.branch} with origin/${defaultBranch} before review.`,
        );
      }

      branchCommits = await listBranchCommitsSince(
        `origin/${defaultBranch}`,
        issue.branch,
      );
      if (branchCommits.length === 0) {
        console.log(`#${issue.number}: no commits produced; no PR created.`);
        return;
      }

      const headShaBeforeReview = await branchHeadSha(issue.branch);
      const cachedReview = await readCachedApprovedReview(
        issue.branch,
        headShaBeforeReview,
        implementationBrief,
      );

      if (cachedReview) {
        review = cachedReview;
        console.log(
          `#${issue.number}: using cached approved review for ${headShaBeforeReview.slice(0, 7)}.`,
        );
      } else {
        const reviewResult = await sandbox.run({
          name: "reviewer",
          maxIterations: 1,
          agent: reviewerAgent,
          promptFile: "./.sandcastle/review-prompt.md",
          promptArgs: {
            BRANCH: issue.branch,
            IMPLEMENTATION_BRIEF: implementationBrief,
          },
        });

        review = parseReview(reviewResult.stdout);
      }
      branchCommits = await listBranchCommitsSince(
        `origin/${defaultBranch}`,
        issue.branch,
      );
      await writeCachedReview(
        issue.branch,
        await branchHeadSha(issue.branch),
        implementationBrief,
        review,
      );

      if (review.approved) {
        gate = await runQualityGates(sandbox.worktreePath);
      }

      if (!review.approved || !gate.passed) {
        break;
      }

      const preMergeSync = await syncIssueBranchWithDefault({
        sandbox,
        issue,
        github,
        defaultBranch,
      });
      if (!preMergeSync.changed) {
        break;
      }

      branchCommits = await listBranchCommitsSince(
        `origin/${defaultBranch}`,
        issue.branch,
      );
      review = {
        approved: false,
        summary: "Reviewer did not run after the latest main sync.",
        blockers: ["Reviewer did not run after the latest main sync."],
        testNotes: "",
      };
      gate = {
        passed: false,
        summary: "Quality gates were not run after the latest main sync.",
        details:
          "A merge from the default branch changed this branch after review.",
      };

      if (syncPass === MAX_SYNC_REVIEW_PASSES) {
        gate = {
          passed: false,
          summary: `Could not stabilize ${issue.branch} against origin/${defaultBranch}.`,
          details:
            "The default branch changed after review too many times. Re-run Sandcastle to review the latest sync.",
        };
        break;
      }

      console.log(
        `#${issue.number}: origin/${defaultBranch} changed after review; re-running review and gates.`,
      );
    }
  } finally {
    const closeResult = await sandbox.close();
    if (closeResult.preservedWorktreePath && gate.passed) {
      gate = {
        passed: false,
        summary: "Sandbox preserved a dirty worktree after the run.",
        details: `Preserved worktree: ${closeResult.preservedWorktreePath}`,
      };
    }
  }

  if (branchCommits.length === 0) {
    console.log(`#${issue.number}: no commits produced; no PR created.`);
    return;
  }

  await pushBranch(github, issue.branch);

  const pr = await githubClient.createOrUpdatePullRequest(
    issue,
    defaultBranch,
    buildPullRequestBody(issue, review, gate),
  );

  if (!review.approved) {
    await githubClient.commentOnPullRequest(
      pr.number,
      buildBlockedComment(
        "Reviewer did not approve this change.",
        review,
        gate,
      ),
    );
    console.log(
      `#${issue.number}: PR left open pending review fixes: ${pr.html_url}`,
    );
    return;
  }

  if (!gate.passed) {
    await githubClient.commentOnPullRequest(
      pr.number,
      buildBlockedComment("Quality gates failed.", review, gate),
    );
    console.log(
      `#${issue.number}: PR left open because checks failed: ${pr.html_url}`,
    );
    return;
  }

  try {
    await githubClient.squashMergePullRequest(pr, issue);
    await githubClient.deleteRemoteBranch(issue.branch);
    await refreshDefaultBranch(github, defaultBranch);
    console.log(`#${issue.number}: merged ${pr.html_url}`);
  } catch (error) {
    await githubClient.commentOnPullRequest(
      pr.number,
      [
        "Sandcastle could not merge this PR automatically.",
        "",
        "Reason:",
        "```",
        truncateForComment(redactSecrets(formatError(error), github.token)),
        "```",
      ].join("\n"),
    );
    console.log(
      `#${issue.number}: PR left open because merge failed: ${pr.html_url}`,
    );
  }
}

function sandcastleDocker(token: string, codexHome: string) {
  return docker({
    env: { GH_TOKEN: token },
    mounts: [
      {
        hostPath: codexHome,
        sandboxPath: CODEX_AUTH_MOUNT,
        readonly: true,
      },
    ],
  });
}

async function syncIssueBranchWithDefault(options: {
  sandbox: Awaited<ReturnType<typeof sandcastle.createSandbox>>;
  issue: PlannedIssue;
  github: GithubConfig;
  defaultBranch: string;
}) {
  const { sandbox, issue, github, defaultBranch } = options;
  const targetRef = `origin/${defaultBranch}`;
  await fetchRemoteBranch(github, defaultBranch);

  const before = await worktreeHeadSha(sandbox.worktreePath);
  try {
    await git(["merge", "--no-edit", targetRef], {
      cwd: sandbox.worktreePath,
    });
  } catch (error) {
    if (
      !(error instanceof CommandError) ||
      !(await hasMergeInProgress(sandbox.worktreePath))
    ) {
      throw error;
    }

    const conflicts = await conflictedFiles(sandbox.worktreePath);
    console.log(
      `#${issue.number}: resolving conflicts with ${targetRef}: ${conflicts.join(", ")}`,
    );

    await sandbox.run({
      name: "resolver",
      maxIterations: 20,
      idleTimeoutSeconds: RESOLVER_IDLE_TIMEOUT_SECONDS,
      agent: resolverAgent,
      promptFile: "./.sandcastle/resolve-conflicts-prompt.md",
      promptArgs: {
        TASK_ID: issue.id,
        ISSUE_TITLE: issue.title,
        BRANCH: issue.branch,
        DEFAULT_BRANCH: defaultBranch,
        CONFLICTED_FILES: conflicts.join("\n"),
        IMPLEMENTATION_BRIEF: formatImplementationBrief(
          issue.implementationBrief,
        ),
      },
    });

    await finishMergeResolution(sandbox.worktreePath);
  }

  const after = await worktreeHeadSha(sandbox.worktreePath);
  return { changed: before !== after };
}

async function finishMergeResolution(worktreePath: string) {
  const conflicts = await conflictedFiles(worktreePath);
  if (conflicts.length > 0) {
    throw new Error(
      `Resolver left merge conflicts unresolved: ${conflicts.join(", ")}`,
    );
  }

  if (await hasMergeInProgress(worktreePath)) {
    await git(["commit", "--no-edit"], { cwd: worktreePath });
  }

  const status = (
    await git(["status", "--porcelain", "--ignore-submodules=all"], {
      cwd: worktreePath,
    })
  ).stdout.trim();
  if (status) {
    throw new Error(
      `Resolver left uncommitted changes after merge resolution:\n${status}`,
    );
  }
}

async function conflictedFiles(worktreePath: string) {
  return (
    await git(["diff", "--name-only", "--diff-filter=U"], {
      cwd: worktreePath,
    })
  ).stdout
    .trim()
    .split("\n")
    .filter((file) => file.length > 0);
}

async function hasMergeInProgress(worktreePath: string) {
  try {
    await git(["rev-parse", "-q", "--verify", "MERGE_HEAD"], {
      cwd: worktreePath,
    });
    return true;
  } catch (error) {
    if (error instanceof CommandError) {
      return false;
    }
    throw error;
  }
}

async function worktreeHeadSha(worktreePath: string) {
  return (
    await git(["rev-parse", "HEAD"], { cwd: worktreePath })
  ).stdout.trim();
}

async function runQualityGates(
  worktreePath: string,
): Promise<QualityGateResult> {
  const steps = [
    { name: "npm run typecheck", command: "npm", args: ["run", "typecheck"] },
    { name: "npm run test", command: "npm", args: ["run", "test"] },
  ];

  for (const step of steps) {
    try {
      await runCommand(step.command, step.args, { cwd: worktreePath });
    } catch (error) {
      if (error instanceof CommandError) {
        return {
          passed: false,
          summary: `${step.name} failed with exit code ${error.exitCode}.`,
          details: truncateForComment(
            [error.stdout, error.stderr].filter(Boolean).join("\n"),
          ),
        };
      }
      throw error;
    }
  }

  let status;
  try {
    status = await git(["status", "--porcelain", "--ignore-submodules=all"], {
      cwd: worktreePath,
    });
  } catch (error) {
    if (error instanceof CommandError) {
      return {
        passed: false,
        summary: `git status failed with exit code ${error.exitCode}.`,
        details: truncateForComment(
          [error.stdout, error.stderr].filter(Boolean).join("\n"),
        ),
      };
    }
    throw error;
  }

  if (status.stdout.trim()) {
    return {
      passed: false,
      summary: "Worktree has uncommitted changes after tests.",
      details: truncateForComment(status.stdout),
    };
  }

  return {
    passed: true,
    summary: "npm run typecheck and npm run test passed.",
  };
}

async function listBranchCommitsSince(baseRef: string, branch: string) {
  const result = await git(["rev-list", `${baseRef}..${branch}`, "--reverse"]);
  return result.stdout
    .trim()
    .split("\n")
    .filter((sha) => sha.length > 0);
}

async function branchHeadSha(branch: string) {
  return (await git(["rev-parse", branch])).stdout.trim();
}

function branchForIssue(id: string) {
  return `sandcastle/issue-${id}`;
}

function formatImplementationBrief(brief: ImplementationBrief) {
  return [
    "## Intent",
    brief.intent.trim() || "Use the issue body as the source of truth.",
    "",
    "## Non-goals",
    bulletList(brief.nonGoals),
    "",
    "## Design decisions",
    bulletList(brief.designDecisions),
    "",
    "## Files likely touched",
    bulletList(brief.filesLikelyTouched),
    "",
    "## Tests required",
    bulletList(brief.testsRequired),
    "",
    "## Security/privacy checks",
    bulletList(brief.securityPrivacyChecks),
    "",
    "## Escalation triggers",
    bulletList(brief.escalationTriggers),
  ].join("\n");
}

function bulletList(items: string[]) {
  const presentItems = items
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

  if (presentItems.length === 0) {
    return "- None";
  }

  return presentItems
    .map((item) => `- ${item.replace(/\n/g, "\n  ")}`)
    .join("\n");
}
