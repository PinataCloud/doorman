import type { Ui } from "./ui.js";

/**
 * Progress for long work, on stderr. On a terminal one line redraws in place
 * (a spinner, or a bar when the total is known) and is cleared when the work
 * ends; otherwise it prints sparse lines, so logs stay short: one per quarter
 * when the total is known, else one every `quietMs` while the work goes on.
 */
export interface Progress {
  /** `done` of `total` (in the units `format` names); unknown total = 0. */
  update(done: number, total?: number): void;
  /** Clear the line, then print `line` if given. */
  end(line?: string): void;
}

export interface ProgressOptions {
  /** What is happening, e.g. "Downloading doorman-1" or "Scanning transcripts". */
  label: string;
  /** How an amount reads: "4.0 MB", "1203 files". */
  format(n: number): string;
  /** Without a known total, how long between plain lines (default 5s). */
  quietMs?: number;
  now?: () => number;
}

const REDRAW_MS = 80;
const CLEAR = "\r\u001b[2K";

export function startProgress(ui: Ui, stream: NodeJS.WritableStream, options: ProgressOptions): Progress {
  const now = options.now ?? Date.now;
  const quietMs = options.quietMs ?? 5000;
  let drawn = false;
  let lastDraw = 0;
  let lastQuarter = -1;
  let lastSparse = now();
  let frame = 0;

  const draw = (done: number, total: number) => {
    const s = ui.style;
    const spinner = s.accent(ui.glyphs.spinner[frame++ % ui.glyphs.spinner.length]!);
    const width = ui.width ?? 80;
    let line: string;
    if (total > 0) {
      const fraction = Math.min(1, done / total);
      const tail = ` ${options.format(done)} of ${options.format(total)}  ${String(Math.floor(fraction * 100)).padStart(3)}%`;
      const cells = Math.max(10, Math.min(30, width - options.label.length - tail.length - 6));
      line = `${spinner} ${options.label}  ${ui.bar(fraction, cells, "info")}${s.dim(tail)}`;
    } else {
      line = `${spinner} ${options.label}${s.dim(`  ${options.format(done)}`)}`;
    }
    stream.write(`${CLEAR}${ui.truncate(line, Math.max(10, width - 1))}`);
    drawn = true;
  };

  return {
    update(done, total = 0) {
      const t = now();
      if (ui.term.live) {
        if (t - lastDraw < REDRAW_MS && (total === 0 || done < total)) return;
        lastDraw = t;
        draw(done, total);
      } else if (total > 0) {
        const quarter = Math.floor((done / total) * 4);
        if (quarter <= lastQuarter) return;
        lastQuarter = quarter;
        stream.write(`${options.label}: ${options.format(done)} of ${options.format(total)} (${Math.floor((done / total) * 100)}%)\n`);
      } else if (t - lastSparse >= quietMs) {
        lastSparse = t;
        stream.write(`${options.label}: ${options.format(done)}\n`);
      }
    },
    end(line) {
      if (drawn) stream.write(CLEAR);
      drawn = false;
      if (line !== undefined) stream.write(`${line}\n`);
    },
  };
}

/** Run `work`, showing the progress `poll` reads every `everyMs`: for work
 * that reports nothing itself, like the transcript scan. */
export async function withPolledProgress<T>(progress: Progress, poll: () => number, work: () => Promise<T>, everyMs = 100): Promise<T> {
  const timer = setInterval(() => progress.update(poll()), everyMs);
  try {
    return await work();
  } finally {
    clearInterval(timer);
    progress.end();
  }
}
