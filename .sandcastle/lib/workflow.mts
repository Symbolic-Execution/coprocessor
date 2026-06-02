import * as sandcastle from "@ai-hero/sandcastle";
import { docker } from "@ai-hero/sandcastle/sandboxes/docker";
import { z } from "zod";
import { claudeAgent } from "./agents.mts";
import {
  CommandError,
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

const hooks = {
  sandbox: { onSandboxReady: [{ command: "npm install" }] },
};

const copyToWorktree = ["node_modules"];
const plannerAgent = claudeAgent("claude-opus-4-8");
const implementerAgent = claudeAgent("claude-opus-4-7");
const reviewerAgent = claudeAgent("claude-opus-4-8");

const planSchema = z.object({
  issues: z.array(
    z.object({ id: z.string(), title: z.string(), branch: z.string() }),
  ),
});

type PlannerIssue = z.infer<typeof planSchema>["issues"][number];

export async function planIssues(
  openIssues: GithubIssue[],
  token: string,
  issueLabel: string,
): Promise<PlannedIssue[]> {
  const plan = await sandcastle.run({
    hooks,
    sandbox: docker({ env: { GH_TOKEN: token } }),
    name: "planner",
    maxIterations: 1,
    agent: plannerAgent,
    promptFile: "./.sandcastle/plan-prompt.md",
    promptArgs: {
      ISSUES_JSON: JSON.stringify(openIssues, null, 2),
      ISSUE_LABEL: issueLabel,
    },
    output: sandcastle.Output.object({ tag: "plan", schema: planSchema }),
  });

  const issuesById = new Map(openIssues.map((issue) => [issue.id, issue]));

  return plan.output.issues.map((planned: PlannerIssue) => {
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

    return { ...issue, branch: planned.branch };
  });
}

export async function runIssueWorkflow(options: {
  issue: PlannedIssue;
  github: GithubConfig;
  githubClient: GithubClient;
  defaultBranch: string;
}) {
  const { issue, github, githubClient, defaultBranch } = options;
  await repairManagedWorktreeSubmodules(issue.branch);

  const sandbox = await sandcastle.createSandbox({
    branch: issue.branch,
    baseBranch: `origin/${defaultBranch}`,
    sandbox: docker({ env: { GH_TOKEN: github.token } }),
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

    const headShaBeforeReview = await branchHeadSha(issue.branch);
    const cachedReview = await readCachedApprovedReview(
      issue.branch,
      headShaBeforeReview,
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
      review,
    );

    if (review.approved) {
      gate = await runQualityGates(sandbox.worktreePath);
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
