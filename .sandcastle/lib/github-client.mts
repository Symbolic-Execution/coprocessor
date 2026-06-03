import { z } from "zod";
import { CommandError, runCommand } from "./git.mts";

const GITHUB_CLI_IMAGE = "sandcastle:coprocessor";

const repoInfoSchema = z.object({
  defaultBranchRef: z.object({ name: z.string() }),
});

const ghLabelSchema = z.object({ name: z.string() }).passthrough();

const ghIssueSchema = z
  .object({
    number: z.number(),
    title: z.string(),
    body: z.string().nullable().optional(),
    labels: z.array(ghLabelSchema).default([]),
    comments: z.union([z.number(), z.array(z.unknown())]).optional(),
  })
  .passthrough();

const ghIssueListSchema = z.array(ghIssueSchema);

const ghIssueCommentsSchema = z
  .object({
    comments: z
      .array(z.object({ body: z.string().nullable().optional() }).passthrough())
      .default([]),
  })
  .passthrough();

const ghPullRequestSchema = z
  .object({
    number: z.number(),
    url: z.string(),
    title: z.string(),
  })
  .passthrough();

const ghPullRequestListSchema = z.array(ghPullRequestSchema);

export type GithubRepo = {
  owner: string;
  repo: string;
};

export type GithubConfig = GithubRepo & {
  token: string;
};

export type GithubIssue = {
  id: string;
  number: number;
  title: string;
  body: string;
  labels: string[];
  comments: string[];
};

export type ImplementationBrief = {
  intent: string;
  nonGoals: string[];
  designDecisions: string[];
  filesLikelyTouched: string[];
  testsRequired: string[];
  securityPrivacyChecks: string[];
  escalationTriggers: string[];
};

export type PlannedIssue = GithubIssue & {
  branch: string;
  implementationBrief: ImplementationBrief;
};

export type PullRequest = {
  number: number;
  html_url: string;
  title: string;
};

export function createGithubClient(github: GithubConfig) {
  return {
    getDefaultBranch: () => getDefaultBranch(github),
    listOpenIssues: (label?: string) => listOpenIssues(github, label),
    createOrUpdatePullRequest: (
      issue: PlannedIssue,
      defaultBranch: string,
      body: string,
    ) => createOrUpdatePullRequest(github, issue, defaultBranch, body),
    commentOnPullRequest: (pullNumber: number, body: string) =>
      commentOnPullRequest(github, pullNumber, body),
    squashMergePullRequest: (pr: PullRequest, issue: PlannedIssue) =>
      squashMergePullRequest(github, pr, issue),
    deleteRemoteBranch: (branch: string) => deleteRemoteBranch(github, branch),
    assertCanPushBranches: () => assertCanPushBranches(github),
  };
}

export type GithubClient = ReturnType<typeof createGithubClient>;

async function getDefaultBranch(github: GithubConfig) {
  const repoInfo = await ghJson(github, repoInfoSchema, [
    "repo",
    "view",
    repository(github),
    "--json",
    "defaultBranchRef",
  ]);

  return repoInfo.defaultBranchRef.name;
}

async function listOpenIssues(github: GithubConfig, label?: string) {
  const args = [
    "issue",
    "list",
    "--repo",
    repository(github),
    "--state",
    "open",
    "--limit",
    "100",
    "--json",
    "number,title,body,labels,comments",
  ];
  if (label) {
    args.push("--label", label);
  }

  const rawIssues = await ghJson(github, ghIssueListSchema, [
    ...args,
  ]);

  return Promise.all(
    rawIssues.map(async (issue) => {
      const comments =
        commentCount(issue.comments) > 0
          ? await fetchIssueComments(github, issue.number)
          : [];

      return {
        id: String(issue.number),
        number: issue.number,
        title: issue.title,
        body: issue.body ?? "",
        labels: issue.labels.map((labelValue) => labelValue.name),
        comments,
      };
    }),
  );
}

async function fetchIssueComments(github: GithubConfig, issueNumber: number) {
  const issue = await ghJson(github, ghIssueCommentsSchema, [
    "issue",
    "view",
    String(issueNumber),
    "--repo",
    repository(github),
    "--json",
    "comments",
  ]);

  return issue.comments
    .map((comment) => comment.body ?? "")
    .filter((body) => body.trim().length > 0);
}

async function createOrUpdatePullRequest(
  github: GithubConfig,
  issue: PlannedIssue,
  defaultBranch: string,
  body: string,
) {
  const existing = await findOpenPullRequest(
    github,
    issue.branch,
    defaultBranch,
  );

  if (existing) {
    await gh(github, [
      "pr",
      "edit",
      String(existing.number),
      "--repo",
      repository(github),
      "--title",
      issue.title,
      "--body",
      body,
      "--base",
      defaultBranch,
    ]);

    return viewPullRequest(github, existing.number);
  }

  await gh(github, [
    "pr",
    "create",
    "--repo",
    repository(github),
    "--title",
    issue.title,
    "--head",
    issue.branch,
    "--base",
    defaultBranch,
    "--body",
    body,
  ]);

  const created = await findOpenPullRequest(github, issue.branch, defaultBranch);
  if (!created) {
    throw new Error(`gh pr create did not create a PR for ${issue.branch}.`);
  }

  return created;
}

async function findOpenPullRequest(
  github: GithubConfig,
  branch: string,
  defaultBranch: string,
) {
  const pulls = await ghJson(github, ghPullRequestListSchema, [
    "pr",
    "list",
    "--repo",
    repository(github),
    "--state",
    "open",
    "--head",
    branch,
    "--base",
    defaultBranch,
    "--limit",
    "1",
    "--json",
    "number,url,title",
  ]);

  return pulls[0] ? toPullRequest(pulls[0]) : undefined;
}

async function viewPullRequest(github: GithubConfig, pullNumber: number) {
  const pr = await ghJson(github, ghPullRequestSchema, [
    "pr",
    "view",
    String(pullNumber),
    "--repo",
    repository(github),
    "--json",
    "number,url,title",
  ]);

  return toPullRequest(pr);
}

async function squashMergePullRequest(
  github: GithubConfig,
  pr: PullRequest,
  issue: PlannedIssue,
) {
  await gh(github, [
    "pr",
    "merge",
    String(pr.number),
    "--repo",
    repository(github),
    "--squash",
    "--subject",
    `${issue.title} (#${pr.number})`,
    "--body",
    `Closes #${issue.number}\n\nMerged by Sandcastle after structured review and local quality gates.`,
  ]);
}

async function deleteRemoteBranch(github: GithubConfig, branch: string) {
  try {
    await gh(github, [
      "api",
      "--method",
      "DELETE",
      `/repos/${repository(github)}/git/refs/heads/${refPath(branch)}`,
    ]);
  } catch (error) {
    if (error instanceof CommandError && isNotFoundError(error)) {
      return;
    }
    throw error;
  }
}

async function assertCanPushBranches(github: GithubConfig) {
  try {
    await gh(github, [
      "api",
      "--method",
      "POST",
      `/repos/${repository(github)}/git/refs`,
      "-f",
      "ref=refs/heads/__sandcastle-permission-probe",
      "-f",
      "sha=0000000000000000000000000000000000000000",
    ]);
  } catch (error) {
    if (error instanceof CommandError && isMissingContentsWrite(error)) {
      throw new Error(
        [
          "GH_TOKEN can read the repository but cannot create or push branches.",
          "Regenerate or update the token with repository Contents: Read and write permission for Symbolic-Execution/coprocessor, then rerun Sandcastle.",
        ].join(" "),
      );
    }

    if (error instanceof CommandError && isExpectedInvalidProbe(error)) {
      return;
    }

    throw error;
  }
}

async function commentOnPullRequest(
  github: GithubConfig,
  pullNumber: number,
  body: string,
) {
  await gh(github, [
    "pr",
    "comment",
    String(pullNumber),
    "--repo",
    repository(github),
    "--body",
    body,
  ]);
}

async function ghJson<T>(
  github: GithubConfig,
  schema: z.ZodType<T>,
  args: string[],
) {
  const result = await gh(github, args);
  return schema.parse(JSON.parse(result.stdout));
}

async function gh(github: GithubConfig, args: string[]) {
  const env = ghEnv(github);

  try {
    return await runCommand("gh", args, { env });
  } catch (error) {
    if (isMissingExecutableError(error)) {
      return ghViaDocker(args, env);
    }
    throw error;
  }
}

async function ghViaDocker(args: string[], env: NodeJS.ProcessEnv) {
  try {
    return await runCommand(
      "docker",
      [
        "run",
        "--rm",
        "--env",
        "GH_TOKEN",
        "--env",
        "GITHUB_TOKEN",
        "--env",
        "GH_PROMPT_DISABLED",
        "--env",
        "NO_COLOR",
        "--entrypoint",
        "gh",
        GITHUB_CLI_IMAGE,
        ...args,
      ],
      { env },
    );
  } catch (error) {
    if (isMissingExecutableError(error)) {
      throw new Error(
        `GitHub CLI \`gh\` is required for Sandcastle GitHub operations. Install it on PATH, or build the ${GITHUB_CLI_IMAGE} Docker image.`,
      );
    }
    throw error;
  }
}

function ghEnv(github: GithubConfig): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GH_TOKEN: github.token,
    GITHUB_TOKEN: github.token,
    GH_PROMPT_DISABLED: "1",
    NO_COLOR: "1",
  };
}

function commentCount(comments: number | unknown[] | undefined) {
  return Array.isArray(comments) ? comments.length : (comments ?? 0);
}

function toPullRequest(pr: z.infer<typeof ghPullRequestSchema>): PullRequest {
  return { number: pr.number, html_url: pr.url, title: pr.title };
}

function repository(repo: GithubRepo) {
  return `${repo.owner}/${repo.repo}`;
}

function refPath(ref: string) {
  return ref.split("/").map(encodeURIComponent).join("/");
}

function isNotFoundError(error: CommandError) {
  return [error.stdout, error.stderr].some((output) =>
    /not found|HTTP 404/i.test(output),
  );
}

function isMissingContentsWrite(error: CommandError) {
  return [error.stdout, error.stderr].some(
    (output) =>
      /Resource not accessible by personal access token|HTTP 403/i.test(
        output,
      ) && /contents=write|git\/refs|personal access token/i.test(output),
  );
}

function isExpectedInvalidProbe(error: CommandError) {
  return [error.stdout, error.stderr].some((output) =>
    /HTTP 422|No commit found for SHA|Invalid request|Validation Failed/i.test(
      output,
    ),
  );
}

function isMissingExecutableError(error: unknown): error is CommandError {
  return (
    error instanceof CommandError &&
    !error.stdout.trim() &&
    !error.stderr.trim()
  );
}
