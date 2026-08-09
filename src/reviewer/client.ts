/** Structural OpenCode boundary used by the isolated reviewer. */
export interface ReviewerSessionClient {
  readonly session: {
    readonly create: (input: unknown) => unknown | Promise<unknown>;
    readonly prompt: (input: unknown) => unknown | Promise<unknown>;
    readonly abort: (input: unknown) => unknown | Promise<unknown>;
    readonly delete: (input: unknown) => unknown | Promise<unknown>;
  };
  readonly permission?: {
    readonly reply: (input: { readonly requestID: string; readonly reply: "reject" }) => unknown | Promise<unknown>;
  };
}

export const REVIEWER_TOOL_DENY: Readonly<Record<string, false>> = Object.freeze({
  bash: false,
  edit: false,
  write: false,
  read: false,
  webfetch: false,
  task: false,
  todoread: false,
  todowrite: false,
  glob: false,
  grep: false,
  list: false,
  lsp: false,
  external_directory: false,
});

/** Return a narrow client view; this deliberately exposes no config/provider APIs. */
export function createReviewerClient(client: ReviewerSessionClient): ReviewerSessionClient {
  return {
    session: {
      create: (input) => client.session.create(input),
      prompt: (input) => client.session.prompt(input),
      abort: (input) => client.session.abort(input),
      delete: (input) => client.session.delete(input),
    },
    ...(client.permission ? { permission: { reply: (input) => client.permission!.reply(input) } } : {}),
  };
}

export const createIsolatedReviewerClient = createReviewerClient;

/** Reject only permission requests originating from an active reviewer child. */
export async function rejectReviewerPermission(
  client: ReviewerSessionClient,
  requestID: string,
  reviewerSessionIDs: ReadonlySet<string>,
  sessionID?: string,
): Promise<boolean> {
  if (!client.permission || !sessionID || !reviewerSessionIDs.has(sessionID)) return false;
  await client.permission.reply({ requestID, reply: "reject" });
  return true;
}

/** Tolerant event adapter for recursive permission events from reviewer children. */
export async function handleReviewerPermissionEvent(
  client: ReviewerSessionClient,
  event: unknown,
  reviewerSessionIDs: ReadonlySet<string>,
): Promise<boolean> {
  if (typeof event !== "object" || event === null) return false;
  const root = event as Record<string, unknown>;
  const body = (root.properties ?? root.data) as Record<string, unknown> | undefined;
  if (!body || typeof body.id !== "string" || typeof body.sessionID !== "string") return false;
  return rejectReviewerPermission(client, body.id, reviewerSessionIDs, body.sessionID);
}
