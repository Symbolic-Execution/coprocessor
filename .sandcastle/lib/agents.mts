import * as sandcastle from "@ai-hero/sandcastle";

const SANDBOX_CODEX_HOME = "/home/agent/.codex";

export function claudeAgent(
  model: string,
  options: Parameters<typeof sandcastle.claudeCode>[1] = {},
) {
  const provider = sandcastle.claudeCode(model, {
    ...options,
    captureSessions: false,
  });

  return {
    ...provider,
    captureSessions: false,
    buildPrintCommand(
      args: Parameters<typeof provider.buildPrintCommand>[0],
    ) {
      const command = provider.buildPrintCommand(args);
      return {
        ...command,
        command: command.command.replace(
          " --output-format",
          " --no-session-persistence --output-format",
        ),
      };
    },
  };
}

export function codexAgent(
  model: string,
  options: Parameters<typeof sandcastle.codex>[1] = {},
) {
  const { env, ...rest } = options;
  const provider = sandcastle.codex(model, {
    ...rest,
    env: {
      CODEX_HOME: SANDBOX_CODEX_HOME,
      ...env,
    },
    captureSessions: false,
  });

  return {
    ...provider,
    captureSessions: false,
    buildPrintCommand(args: Parameters<typeof provider.buildPrintCommand>[0]) {
      const command = provider.buildPrintCommand(args);
      return {
        ...command,
        command: command.command.replace("codex exec", "codex exec --ephemeral"),
      };
    },
  };
}
