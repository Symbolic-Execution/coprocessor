import { readFile, stat, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { CommandError, git } from "./git.mts";

export async function repairManagedWorktreeSubmodules(
  branch: string,
  repoDir = process.cwd(),
) {
  const worktreeName = branch.replace(/\//g, "-");
  const worktreePath = join(repoDir, ".sandcastle", "worktrees", worktreeName);

  if (!(await pathExists(worktreePath))) {
    return;
  }

  const submodulePaths = await listSubmodulePaths(repoDir);
  let repaired = 0;

  for (const submodulePath of submodulePaths) {
    if (
      await repairSubmoduleGitPointers(
        repoDir,
        worktreePath,
        worktreeName,
        submodulePath,
      )
    ) {
      repaired += 1;
    }
  }

  if (repaired > 0) {
    console.log(
      `Repaired ${repaired} submodule git pointer(s) in ${worktreePath}.`,
    );
  }
}

async function listSubmodulePaths(repoDir: string) {
  try {
    const result = await git(
      [
        "config",
        "--file",
        ".gitmodules",
        "--get-regexp",
        "^submodule\\..*\\.path$",
      ],
      { cwd: repoDir },
    );

    return result.stdout
      .trim()
      .split("\n")
      .map((line) => line.trim().split(/\s+/)[1])
      .filter((path): path is string => Boolean(path));
  } catch (error) {
    if (error instanceof CommandError && error.exitCode === 1) {
      return [];
    }
    throw error;
  }
}

async function repairSubmoduleGitPointers(
  repoDir: string,
  worktreePath: string,
  worktreeName: string,
  submodulePath: string,
) {
  const submoduleDir = join(worktreePath, submodulePath);
  const gitFilePath = join(submoduleDir, ".git");
  const gitDirPath = join(
    repoDir,
    ".git",
    "worktrees",
    worktreeName,
    "modules",
    submodulePath,
  );

  if (!(await pathExists(gitFilePath)) || !(await pathExists(gitDirPath))) {
    return false;
  }

  let repaired = false;
  const desiredGitFile = `gitdir: ${relative(submoduleDir, gitDirPath)}\n`;
  const currentGitFile = await readFile(gitFilePath, "utf8");

  if (currentGitFile !== desiredGitFile) {
    await writeFile(gitFilePath, desiredGitFile);
    repaired = true;
  }

  const configPath = join(gitDirPath, "config");
  if (await pathExists(configPath)) {
    const desiredWorktree = relative(gitDirPath, submoduleDir);
    const currentWorktree = await currentCoreWorktree(configPath);

    if (currentWorktree !== desiredWorktree) {
      await git(
        ["config", "--file", configPath, "core.worktree", desiredWorktree],
        { cwd: repoDir },
      );
      repaired = true;
    }
  }

  return repaired;
}

async function currentCoreWorktree(configPath: string) {
  try {
    const result = await git(["config", "--file", configPath, "core.worktree"]);
    return result.stdout.trim();
  } catch (error) {
    if (error instanceof CommandError && error.exitCode === 1) {
      return undefined;
    }
    throw error;
  }
}

async function pathExists(path: string) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}
