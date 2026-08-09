/** Structural OpenCode boundary used by the isolated reviewer. */
export interface ReviewerSessionClient {
  /** Root OpenCode 1.18.10 PluginInput client permission endpoint. */
  readonly postSessionIdPermissionsPermissionId?: (input: {
    readonly path: { readonly id: string; readonly permissionID: string };
    readonly body: { readonly response: "reject" };
    readonly query?: { readonly directory?: string };
  }) => unknown | Promise<unknown>;
  readonly session: {
    readonly create: (input: unknown) => unknown | Promise<unknown>;
    readonly prompt: (input: unknown) => unknown | Promise<unknown>;
    readonly abort: (input: unknown) => unknown | Promise<unknown>;
    readonly delete: (input: unknown) => unknown | Promise<unknown>;
  };
  /** Flattened v2 client shape, retained as an explicit compatibility fallback. */
  readonly permission?: {
    readonly reply: (input: {
      readonly requestID: string;
      readonly directory?: string;
      readonly reply: "reject";
    }) => unknown | Promise<unknown>;
  };
}

export const REVIEWER_TOOL_DENY: Readonly<Record<string, false>> = Object.freeze({
  "*": false,
  bash: false,
  shell: false,
  terminal: false,
  exec: false,
  edit: false,
  write: false,
  patch: false,
  multiedit: false,
  read: false,
  webfetch: false,
  websearch: false,
  fetch: false,
  http: false,
  network: false,
  mcp: false,
  task: false,
  skill: false,
  question: false,
  todoread: false,
  todowrite: false,
  glob: false,
  grep: false,
  list: false,
  lsp: false,
  external_directory: false,
});

/** Session-scoped deny rule covers built-ins and dynamically named MCP tools. */
export const REVIEWER_PERMISSION_DENY = Object.freeze([
  Object.freeze({ permission: "*", pattern: "*", action: "deny" as const }),
]);

/** Return a narrow client view; this deliberately exposes no config/provider APIs. */
export function createReviewerClient(client: ReviewerSessionClient): ReviewerSessionClient {
  return {
    ...(client.postSessionIdPermissionsPermissionId
      ? { postSessionIdPermissionsPermissionId: (input) => client.postSessionIdPermissionsPermissionId!(input) }
      : {}),
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
  directory?: string,
): Promise<boolean> {
  if (!sessionID || !reviewerSessionIDs.has(sessionID)) return false;
  if (client.postSessionIdPermissionsPermissionId) {
    await client.postSessionIdPermissionsPermissionId({
      path: { id: sessionID, permissionID: requestID },
      body: { response: "reject" },
      query: { directory },
    });
    return true;
  }
  if (!client.permission) return false;
  await client.permission.reply({ requestID, directory, reply: "reject" });
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
