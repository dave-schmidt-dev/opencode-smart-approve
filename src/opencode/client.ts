/** The narrow part of the OpenCode SDK used by the approval boundary. */
export interface PermissionReplyClient {
  readonly permission: {
    readonly reply: (input: {
      readonly requestID: string;
      readonly reply: "once";
    }) => unknown | Promise<unknown>;
  };
}

export interface ApprovalAdapter {
  /** Reply to exactly this pending request, for one execution only. */
  readonly approve: (requestID: string) => Promise<void>;
}

/**
 * Adapt the OpenCode SDK client without exposing any other reply mode to the
 * rest of the plugin. The request ID is passed through unchanged.
 */
export function createApprovalAdapter(client: PermissionReplyClient): ApprovalAdapter {
  return {
    approve: async (requestID: string): Promise<void> => {
      if (typeof requestID !== "string" || requestID.length === 0) {
        throw new TypeError("requestID must be a non-empty string");
      }
      await client.permission.reply({ requestID, reply: "once" });
    },
  };
}

/** Convenience function for integrations that do not need to retain an adapter. */
export async function replyOnce(
  client: PermissionReplyClient,
  requestID: string,
): Promise<void> {
  await createApprovalAdapter(client).approve(requestID);
}
