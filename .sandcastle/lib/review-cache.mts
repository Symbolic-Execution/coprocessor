import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";
import { reviewSchema, type Review } from "./review-output.mts";

const REVIEW_CACHE_VERSION = "implementation-brief-v1";

const cachedReviewSchema = z.object({
  branch: z.string(),
  headSha: z.string(),
  reviewContextHash: z.string(),
  review: reviewSchema,
});

export async function readCachedApprovedReview(
  branch: string,
  headSha: string,
  reviewContext: string,
) {
  try {
    const cached = cachedReviewSchema.parse(
      JSON.parse(await readFile(cachePath(branch), "utf8")),
    );

    if (
      cached.branch === branch &&
      cached.headSha === headSha &&
      cached.reviewContextHash === reviewContextHash(reviewContext) &&
      cached.review.approved
    ) {
      return cached.review;
    }
  } catch {
    return undefined;
  }
}

export async function writeCachedReview(
  branch: string,
  headSha: string,
  reviewContext: string,
  review: Review,
) {
  if (!review.approved) {
    return;
  }

  const path = cachePath(branch);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(
    path,
    `${JSON.stringify(
      {
        branch,
        headSha,
        reviewContextHash: reviewContextHash(reviewContext),
        review,
      },
      null,
      2,
    )}\n`,
  );
}

function cachePath(branch: string) {
  return join(
    ".sandcastle",
    "review-cache",
    `${branch.replace(/\//g, "-")}.json`,
  );
}

function reviewContextHash(reviewContext: string) {
  return createHash("sha256")
    .update(REVIEW_CACHE_VERSION)
    .update("\0")
    .update(reviewContext)
    .digest("hex");
}
