import { createHash } from "node:crypto";

/** A stable source/item identity that is also enforced by the composite database unique index. */
export function sourceItemIdentity(sourceKey: string, sourceExternalId: string): string {
  return createHash("sha256").update(`${sourceKey}\u0000${sourceExternalId}`).digest("hex");
}
