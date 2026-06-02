import { loadRuntimeConfig, printConfigCheck } from "./lib/config.mts";
import { createGithubClient } from "./lib/github-client.mts";
import { formatError, redactSecrets, refreshDefaultBranch } from "./lib/git.mts";
import { planIssues, runIssueWorkflow } from "./lib/workflow.mts";

const MAX_ITERATIONS = 10;
const ISSUE_LABEL = "Sandcastle";

let tokenForRedaction: string | undefined;

try {
  const config = await loadRuntimeConfig();
  tokenForRedaction = config.token;

  if (config.checkConfigOnly) {
    printConfigCheck(config);
  } else {
    const githubClient = createGithubClient(config.github);
    const defaultBranch = await githubClient.getDefaultBranch();
    await githubClient.assertCanPushBranches();

    for (let iteration = 1; iteration <= MAX_ITERATIONS; iteration++) {
      console.log(`\n=== Iteration ${iteration}/${MAX_ITERATIONS} ===\n`);

      await refreshDefaultBranch(config.github, defaultBranch);

      const allOpenIssues = await githubClient.listOpenIssues();
      const openIssues = allOpenIssues.filter((issue) =>
        issue.labels.includes(ISSUE_LABEL),
      );
      if (openIssues.length === 0) {
        console.log(`No open issues labeled "${ISSUE_LABEL}". Exiting.`);
        break;
      }

      const plannedIssues = await planIssues(
        openIssues,
        allOpenIssues,
        config.token,
        ISSUE_LABEL,
        config.codexHome,
      );

      if (plannedIssues.length === 0) {
        console.log("No unblocked issues to work on. Exiting.");
        break;
      }

      console.log(
        `Planning complete. ${plannedIssues.length} issue(s) to work in parallel:`,
      );
      for (const issue of plannedIssues) {
        console.log(`  #${issue.number}: ${issue.title} -> ${issue.branch}`);
      }

      const settled = await Promise.allSettled(
        plannedIssues.map((issue) =>
          runIssueWorkflow({
            issue,
            github: config.github,
            githubClient,
            defaultBranch,
            codexHome: config.codexHome,
          }),
        ),
      );

      for (const [i, outcome] of settled.entries()) {
        const issue = plannedIssues[i]!;
        if (outcome.status === "rejected") {
          console.error(`  x #${issue.number} (${issue.branch}) failed:`);
          console.error(redactSecrets(formatError(outcome.reason), config.token));
        }
      }
    }

    console.log("\nAll done.");
  }
} catch (error) {
  console.error(redactSecrets(formatError(error), tokenForRedaction));
  process.exitCode = 1;
}
