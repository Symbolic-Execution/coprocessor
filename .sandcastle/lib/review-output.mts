import { z } from "zod";
import type { PlannedIssue } from "./github-client.mts";

const COMMENT_OUTPUT_LIMIT = 6_000;

export const reviewSchema = z.object({
  approved: z.boolean(),
  summary: z.string(),
  blockers: z.array(z.string()).default([]),
  testNotes: z.string().default(""),
});

export type Review = z.infer<typeof reviewSchema>;

export type QualityGateResult =
  | { passed: true; summary: string }
  | { passed: false; summary: string; details: string };

export function parseReview(stdout: string): Review {
  const matches = [...stdout.matchAll(/<review>\s*([\s\S]*?)\s*<\/review>/g)];
  if (matches.length === 0) {
    return {
      approved: false,
      summary: "Reviewer did not emit a <review> block.",
      blockers: ["Missing structured reviewer output."],
      testNotes: "",
    };
  }

  const rawJson = stripJsonFence(matches[matches.length - 1]![1]!.trim());
  try {
    return reviewSchema.parse(JSON.parse(rawJson));
  } catch (error) {
    return {
      approved: false,
      summary: "Reviewer emitted invalid structured output.",
      blockers: [String(error)],
      testNotes: "",
    };
  }
}

export function buildPullRequestBody(
  issue: PlannedIssue,
  review: Review,
  gate: QualityGateResult,
) {
  const blockers = review.blockers.length
    ? review.blockers.map((blocker) => `- ${blocker}`).join("\n")
    : "- None";

  return [
    `Closes #${issue.number}`,
    "",
    "## Sandcastle Summary",
    review.summary,
    "",
    "## Review",
    `Approved: ${review.approved ? "yes" : "no"}`,
    "",
    "Blockers:",
    blockers,
    "",
    "## Validation",
    gate.summary,
    review.testNotes ? `\nReviewer test notes:\n${review.testNotes}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

export function buildBlockedComment(
  reason: string,
  review: Review,
  gate: QualityGateResult,
) {
  const lines = [
    `Sandcastle left this PR open: ${reason}`,
    "",
    "Review summary:",
    review.summary,
  ];

  if (review.blockers.length > 0) {
    lines.push(
      "",
      "Blockers:",
      ...review.blockers.map((blocker) => `- ${blocker}`),
    );
  }

  lines.push("", "Validation:", gate.summary);

  if (!gate.passed && gate.details) {
    lines.push("", "Details:", "```", truncateForComment(gate.details), "```");
  }

  return lines.join("\n");
}

export function truncateForComment(value: string) {
  if (value.length <= COMMENT_OUTPUT_LIMIT) {
    return value;
  }
  return value.slice(value.length - COMMENT_OUTPUT_LIMIT);
}

function stripJsonFence(value: string) {
  const match = value.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  return match ? match[1]!.trim() : value;
}
