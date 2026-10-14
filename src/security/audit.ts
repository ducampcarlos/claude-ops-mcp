/**
 * Append-only JSONL audit log: one line per tool call.
 *
 * It records WHAT was probed and the outcome, never request/response bodies, headers or
 * cookies, so the log can't leak secrets that a target might return.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export interface AuditEntry {
  tool: string;
  /** The host or URL that was probed (credentials are never accepted, so none can leak here). */
  target?: string;
  ok: boolean;
  durationMs: number;
  /** Short error/refusal description, truncated. */
  error?: string;
}

export type AuditSink = (line: string) => void | Promise<void>;

export class AuditLog {
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly sink: AuditSink | undefined) {}

  static toFile(path: string | undefined): AuditLog {
    if (!path) return new AuditLog(undefined);
    let ready: Promise<unknown> | undefined;
    return new AuditLog(async (line) => {
      ready ??= mkdir(dirname(path), { recursive: true });
      await ready;
      await appendFile(path, line, { encoding: "utf8", mode: 0o600 });
    });
  }

  record(entry: AuditEntry): void {
    if (!this.sink) return;
    const line =
      JSON.stringify({
        ts: new Date().toISOString(),
        tool: entry.tool,
        target: entry.target?.slice(0, 300),
        ok: entry.ok,
        durationMs: Math.round(entry.durationMs),
        error: entry.error?.slice(0, 300),
      }) + "\n";
    const sink = this.sink;
    // Serialise writes so lines never interleave; a failing sink must never break a tool call.
    this.queue = this.queue.then(() => sink(line)).catch(() => undefined);
  }

  /** Resolves when every queued line has been written (used by tests and on shutdown). */
  flush(): Promise<void> {
    return this.queue;
  }
}
