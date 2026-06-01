import { readFile } from "node:fs/promises";
import { git } from "./git.mts";
import type { GithubConfig, GithubRepo } from "./github-client.mts";

export type RuntimeConfig =
  | {
      checkConfigOnly: true;
      repo: GithubRepo;
      token?: string;
    }
  | {
      checkConfigOnly: false;
      repo: GithubRepo;
      token: string;
      github: GithubConfig;
    };

export async function loadRuntimeConfig(
  argv: string[] = process.argv,
): Promise<RuntimeConfig> {
  const repo = await readGithubRepoFromOrigin();
  const fileEnv = await readSandcastleEnv();
  const token =
    fileEnv.GH_TOKEN ||
    fileEnv.GITHUB_TOKEN ||
    process.env.GH_TOKEN ||
    process.env.GITHUB_TOKEN;
  const checkConfigOnly = argv.includes("--check-config");

  if (checkConfigOnly) {
    return { checkConfigOnly, repo, token };
  }

  if (!token) {
    throw new Error(
      "GH_TOKEN is required. Set it in .sandcastle/.env or the process environment.",
    );
  }

  return { checkConfigOnly, repo, token, github: { ...repo, token } };
}

export function printConfigCheck(config: RuntimeConfig) {
  console.log(`GitHub repo: ${config.repo.owner}/${config.repo.repo}`);
  console.log(`GH_TOKEN: ${config.token ? "configured" : "missing"}`);
}

async function readGithubRepoFromOrigin(): Promise<GithubRepo> {
  const origin = (await git(["config", "--get", "remote.origin.url"])).stdout.trim();
  const patterns = [
    /^git@github\.com:([^/]+)\/(.+?)(?:\.git)?$/,
    /^ssh:\/\/git@github\.com\/([^/]+)\/(.+?)(?:\.git)?$/,
    /^https:\/\/github\.com\/([^/]+)\/(.+?)(?:\.git)?$/,
    /^https:\/\/[^@]+@github\.com\/([^/]+)\/(.+?)(?:\.git)?$/,
  ];

  for (const pattern of patterns) {
    const match = origin.match(pattern);
    if (match) {
      return { owner: match[1]!, repo: match[2]!.replace(/\.git$/, "") };
    }
  }

  throw new Error(`Could not parse GitHub owner/repo from origin: ${origin}`);
}

async function readSandcastleEnv() {
  try {
    return parseEnv(await readFile(".sandcastle/.env", "utf8"));
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return {};
    }
    throw error;
  }
}

function parseEnv(content: string) {
  const env: Record<string, string> = {};

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const equalsIndex = trimmed.indexOf("=");
    if (equalsIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, equalsIndex).trim();
    let value = trimmed.slice(equalsIndex + 1).trim();

    const quote = value[0];
    if (
      value.length >= 2 &&
      (quote === `"` || quote === `'`) &&
      value[value.length - 1] === quote
    ) {
      value = value.slice(1, -1);
    }

    env[key] = value;
  }

  return env;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
