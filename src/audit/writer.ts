import { appendFile, mkdir, rename, stat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createAuditRecord, type AuditRecord, type AuditRecordInput } from "./schema";

export interface AuditWriterOptions {
  /** Audit is opt-in. No file is opened unless this is true. */
  readonly enabled?: boolean;
  readonly filePath?: string;
  readonly directory?: string;
  readonly fileName?: string;
  readonly maxBytes?: number;
  readonly maxFiles?: number;
  /** File operations are injectable so non-blocking behavior can be proven. */
  readonly fileSystem?: AuditFileSystem;
}

export interface AuditFileSystem {
  readonly appendFile: typeof appendFile;
  readonly mkdir: typeof mkdir;
  readonly rename: typeof rename;
  readonly stat: typeof stat;
  readonly unlink: typeof unlink;
}

export interface AuditWriter {
  readonly enabled: boolean;
  readonly append: (input: AuditRecordInput | AuditRecord) => Promise<void>;
  readonly write: (input: AuditRecordInput | AuditRecord) => Promise<void>;
  readonly record: (input: AuditRecordInput | AuditRecord) => Promise<void>;
  readonly flush: () => Promise<void>;
}

const DEFAULT_MAX_BYTES = 1_000_000;
const DEFAULT_MAX_FILES = 2;

/**
 * A non-authoritative, serialized JSONL sink. Writes are queued and failures
 * are swallowed so audit I/O cannot delay or change an approval decision.
 */
export function createAuditWriter(options: AuditWriterOptions = {}): AuditWriter {
  const enabled = options.enabled === true;
  const maxBytes = Number.isInteger(options.maxBytes) && (options.maxBytes ?? 0) > 0 ? options.maxBytes as number : DEFAULT_MAX_BYTES;
  const maxFiles = Number.isInteger(options.maxFiles) && (options.maxFiles ?? 0) >= 2 ? Math.min(options.maxFiles as number, 8) : DEFAULT_MAX_FILES;
  const filePath = options.filePath ?? (options.directory ? join(options.directory, options.fileName ?? "smart-approve-audit.jsonl") : undefined);
  const fileSystem: AuditFileSystem = options.fileSystem ?? { appendFile, mkdir, rename, stat, unlink };
  let queue = Promise.resolve();

  const rotate = async (incomingBytes: number): Promise<void> => {
    if (!filePath) return;
    let currentSize = 0;
    try { currentSize = (await fileSystem.stat(filePath)).size; } catch { return; }
    if (currentSize === 0 || currentSize + incomingBytes <= maxBytes) return;
    // Keep at most maxFiles files (live file plus backups), with .1 newest.
    try { await fileSystem.unlink(`${filePath}.${maxFiles - 1}`); } catch { /* missing oldest file */ }
    for (let index = maxFiles - 2; index >= 1; index -= 1) {
      try { await fileSystem.rename(`${filePath}.${index}`, `${filePath}.${index + 1}`); } catch { /* missing older file */ }
    }
    try { await fileSystem.rename(filePath, `${filePath}.1`); } catch { /* an audit failure is non-authoritative */ }
  };

  const append = (input: AuditRecordInput | AuditRecord): Promise<void> => {
    if (!enabled || !filePath) return Promise.resolve();
    let line: string;
    try {
      // Sanitize synchronously so the queued closure retains neither the raw
      // caller object nor values that the caller can mutate after this call.
      line = `${JSON.stringify(createAuditRecord(input as AuditRecordInput))}\n`;
    } catch {
      return Promise.resolve();
    }
    queue = queue.then(async () => {
      try {
        const incomingBytes = Buffer.byteLength(line, "utf8");
        if (incomingBytes > maxBytes) return;
        await fileSystem.mkdir(dirname(filePath), { recursive: true });
        await rotate(incomingBytes);
        await fileSystem.appendFile(filePath, line, { encoding: "utf8", mode: 0o600 });
      } catch {
        // Logging is diagnostic only; never propagate filesystem/schema errors.
      }
    }).catch(() => undefined);
    // Audit is diagnostic. Even a caller that awaits append must not put
    // filesystem latency on the permission-decision path; flush owns waiting.
    return Promise.resolve();
  };

  const writer: AuditWriter = {
    enabled,
    append,
    write: append,
    record: append,
    flush: async () => { await queue; },
  };
  return writer;
}

export const createAuditLogWriter = createAuditWriter;
export const writeAuditRecord = (writer: AuditWriter, input: AuditRecordInput | AuditRecord): Promise<void> => writer.append(input);
