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
  let queue = Promise.resolve();

  const rotate = async (): Promise<void> => {
    if (!filePath) return;
    let currentSize = 0;
    try { currentSize = (await stat(filePath)).size; } catch { return; }
    if (currentSize <= maxBytes) return;
    // Keep at most maxFiles files (live file plus backups), with .1 newest.
    try { await unlink(`${filePath}.${maxFiles - 1}`); } catch { /* missing oldest file */ }
    for (let index = maxFiles - 2; index >= 1; index -= 1) {
      try { await rename(`${filePath}.${index}`, `${filePath}.${index + 1}`); } catch { /* missing older file */ }
    }
    try { await rename(filePath, `${filePath}.1`); } catch { /* an audit failure is non-authoritative */ }
  };

  const append = (input: AuditRecordInput | AuditRecord): Promise<void> => {
    if (!enabled || !filePath) return Promise.resolve();
    const operation = queue.then(async () => {
      try {
        // Rebuild even already-shaped values so unknown/raw fields cannot be
        // smuggled into the JSONL line.
        const record = createAuditRecord(input as AuditRecordInput);
        const line = `${JSON.stringify(record)}\n`;
        await mkdir(dirname(filePath), { recursive: true });
        await rotate();
        await appendFile(filePath, line, { encoding: "utf8", mode: 0o600 });
      } catch {
        // Logging is diagnostic only; never propagate filesystem/schema errors.
      }
    });
    queue = operation.catch(() => undefined);
    return operation;
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
