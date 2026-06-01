import * as sandcastle from "@ai-hero/sandcastle";

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
