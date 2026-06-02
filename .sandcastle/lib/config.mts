import { access, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { git } from "./git.mts";
import type { GithubConfig, GithubRepo } from "./github-client.mts";

export type RuntimeConfig =
  | {
      checkConfigOnly: true;
      repo: GithubRepo;
      token?: string;
      codexHome: string;
      codexAuthConfigured: boolean;
    }
  | {
      checkConfigOnly: false;
      repo: GithubRepo;
      token: string;
      codexHome: string;
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
  const codexHome = resolveHostPath(
    fileEnv.SANDCASTLE_CODEX_HOME ||
      process.env.SANDCASTLE_CODEX_HOME ||
      fileEnv.CODEX_HOME ||
      process.env.CODEX_HOME ||
      "~/.codex",
  );
  const checkConfigOnly = argv.includes("--check-config");
  const codexAuthConfigured = await hasCodexSubscriptionAuth(codexHome);

  if (checkConfigOnly) {
    return {
      checkConfigOnly,
      repo,
      token,
      codexHome,
      codexAuthConfigured,
    };
  }

  if (!token) {
    throw new Error(
      "GH_TOKEN is required. Set it in .sandcastle/.env or the process environment.",
    );
  }

  if (!codexAuthConfigured) {
    throw new Error(
      [
        `Codex subscription auth is required at ${codexHome}/auth.json for the review agent.`,
        "Run `codex login --device-auth` locally, or set SANDCASTLE_CODEX_HOME in .sandcastle/.env to a Codex home containing auth.json.",
        "Do not use OPENAI_API_KEY for this workflow.",
      ].join(" "),
    );
  }

  return {
    checkConfigOnly,
    repo,
    token,
    codexHome,
    github: { ...repo, token },
  };
}

export function printConfigCheck(config: RuntimeConfig) {
  console.log(`GitHub repo: ${config.repo.owner}/${config.repo.repo}`);
  console.log(`GH_TOKEN: ${config.token ? "configured" : "missing"}`);
  console.log(`SANDCASTLE_CODEX_HOME: ${config.codexHome}`);
  if (config.checkConfigOnly) {
    console.log(
      `Codex subscription auth: ${
        config.codexAuthConfigured ? "configured" : "missing"
      }`,
    );
  }
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

function resolveHostPath(pathValue: string) {
  if (pathValue === "~") {
    return homedir();
  }

  if (pathValue.startsWith("~/")) {
    return join(homedir(), pathValue.slice(2));
  }

  if (isAbsolute(pathValue)) {
    return pathValue;
  }

  return resolve(pathValue);
}

async function hasCodexSubscriptionAuth(codexHome: string) {
  try {
    await access(join(codexHome, "auth.json"));
    return true;
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
