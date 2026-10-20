/**
 * macOS notifications — the ONLY delivery channel this app has; nothing is
 * sent off the machine. Three kinds:
 * a held tool call waiting for a decision, radar findings above the preferred
 * severity band, and the daily/weekly spend digest at 09:00 local time.
 */

import { Notification } from "electron";
import { SEVERITY_RANK } from "./guard/policy.js";
import type { SecuritySeverity } from "./guard/security-detect.js";
import { localDetectorLabel } from "./lib/findings.js";
import type { ApprovalRequest } from "./guard/handshake.js";
import { approvalRules, approvalSummary, approvalWhere } from "./lib/approvals.js";
import type { FindingRow } from "./lib/findings.js";
import { formatTokens } from "./lib/format.js";
import type { SpendGraphs } from "./lib/spend.js";
import type { NotifyThreshold, Prefs } from "./state.js";

/**
 * Notification Center can REFUSE a banner, and it does so after `show()` — via
 * a `failed` event, not a throw, and `isSupported()` still says true. The case
 * that bites: an unsigned/dev build has no notification authorization, so macOS
 * answers `UNErrorDomain error 1` and nothing ever appears on screen.
 *
 * That matters more here than in most apps, because one of these banners is how
 * a person learns their session is BLOCKED waiting on them. So a refusal is
 * recorded and reported (the UI says notifications aren't being delivered)
 * rather than swallowed — and every notification path in this app has a
 * non-notification fallback: the window comes forward, the tray keeps the
 * numbers, and the approval overlay is the real prompt.
 */
let deliveryRefused = false;
let onRefused: (() => void) | undefined;

/**
 * What one delivery check learned. `ok` is a `show` event: Notification Center
 * ACCEPTED the banner — which is all Electron can know. macOS still decides
 * whether anything appears: an alert style of "None", a Focus mode or Do Not
 * Disturb all accept and show nothing, and none of that is readable from here
 * (the per-app flags live in an undocumented bitfield in com.apple.ncprefs), so
 * a healthy check means "not refused", not "seen". `undetermined` marks the
 * answers that are not evidence either way — a 4 s silence, a platform with
 * no notifications — so a caller never records them as a refusal.
 */
export interface DeliveryCheck {
  ok: boolean;
  error?: string;
  undetermined?: boolean;
}

/**
 * The in-window mirror: every findings/digest banner ALSO lands in the app's
 * notice stack, so what a banner said still reaches the person when macOS
 * drops it (permission never granted, Focus mode, unsigned build) — the OS
 * banner is the attention-getter, never the only copy. index.ts registers the
 * sink (it owns the Store); registration is a hook rather than a parameter so
 * the notify call sites keep their shapes.
 */
export interface NoticeMirror {
  title: string;
  body: string;
  nav?: "radar" | "spend" | "settings" | "integrations" | "ledger";
}
let noticeSink: ((notice: NoticeMirror) => void) | undefined;

export function setNoticeSink(sink: (notice: NoticeMirror) => void): void {
  noticeSink = sink;
}

/**
 * Whether a message has to be shown INSIDE the window to reach the person at
 * all: the platform has no notifications, or macOS has refused one of ours
 * (permission never granted, or turned off later). Everywhere else the OS
 * banner — top right, outside the app — is the one and only copy: the in-app
 * stack used to mirror every banner, which meant the same sentence twice,
 * once outside and once inside, every time. Now it is the rail of last resort
 * it was always described as.
 */
export function inWindowFallbackNeeded(): boolean {
  return !Notification.isSupported() || deliveryRefused;
}

/** Mirror a banner into the in-window stack ONLY when the banner cannot reach
 * the person (see inWindowFallbackNeeded). */
function mirrorNotice(notice: NoticeMirror): void {
  if (inWindowFallbackNeeded()) noticeSink?.(notice);
}

export function notificationsRefused(): boolean {
  return deliveryRefused;
}

export function onNotificationsRefused(cb: () => void): void {
  onRefused = cb;
}

/** The error a 4 s silence records. Shown in Settings beside the delivery
 * problem, on every platform, so it names no one OS's notification list. */
const NO_ANSWER = "no response from the system's notification service";

function trackDelivery(notification: Notification): Notification {
  notification.on("failed", (_event, error) => {
    if (!deliveryRefused) {
      deliveryRefused = true;
      console.warn(`[doorman] the OS refused a notification: ${String(error)}`);
      onRefused?.();
    }
  });
  return notification;
}

/**
 * What the app knows about itself right now, in the four facts a banner has
 * room for. Every delivery check carries this — see `statusBannerText`.
 */
export interface StatusSummary {
  /** input+output tokens on the local calendar day / over the 7-day window —
   * tokens, never dollars. */
  todayTokens: number;
  windowTokens: number;
  openFindings: number;
  /** Tool calls held at this instant, waiting on a decision. */
  heldNow?: number;
  /** False when the guard is not installed as the app left it. */
  guardHealthy?: boolean;
}

/**
 * The two lines every delivery-check banner says.
 *
 * A check has to send a real banner (macOS has no "am I authorized?" API — see
 * `testNotification`), so the only question is what that banner says, and
 * "Notification delivery check." is a banner that spends a person's attention
 * and returns nothing. These say the same thing the app would say if asked:
 * the one security fact that matters most right now, and the usage.
 *
 * The subtitle is ordered by what needs a person: a broken guard means findings
 * may have STOPPED arriving, a held call is a stopped session, exposures are a
 * queue, and "all clear" is the only line that asks for nothing.
 */
export function statusBannerText(summary: StatusSummary): { subtitle: string; body: string } {
  const subtitle =
    summary.guardHealthy === false
      ? "The guard was changed — nothing is being held"
      : summary.heldNow && summary.heldNow > 0
        ? `${summary.heldNow} call${summary.heldNow === 1 ? "" : "s"} waiting on you`
        : summary.openFindings > 0
          ? `${summary.openFindings} exposure${summary.openFindings === 1 ? "" : "s"} to review`
          : "Radar all clear";
  return {
    subtitle,
    body: `Today ${formatTokens(summary.todayTokens)} · last 7 days ${formatTokens(summary.windowTokens)} tokens.`,
  };
}

/**
 * Ask macOS, by actually asking it: show one real notification and report which
 * event came back. There is no API for "am I authorized?" on macOS — Electron
 * exposes `isSupported()` (a platform question, always true here) and the
 * per-notification `show`/`failed` events, and nothing else. So the honest
 * check is a test send, which is also the thing a person wants when they are
 * trying to work out why banners aren't arriving.
 *
 * This is the Settings button, and it sends the SAME status banner the startup
 * check does, with one added line about the buttons a held call carries. The
 * point is that pressing Test spends a banner on real numbers rather than on
 * the words "test notification" — proving delivery is what it does, not what
 * it is for.
 */
export function testNotification(
  iconPath?: string,
  summary?: StatusSummary,
): Promise<DeliveryCheck> {
  if (!Notification.isSupported()) {
    return Promise.resolve({ ok: false, error: "this platform has no notifications", undetermined: true });
  }
  const status = summary ? statusBannerText(summary) : undefined;
  return new Promise((resolve) => {
    let settled = false;
    const done = (result: DeliveryCheck) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const notification = new Notification({
      title: "Doorman — notifications are working",
      subtitle: status?.subtitle ?? "Test notification",
      body: `${status ? `${status.body}\n` : ""}A held tool call will look like this, with Deny and Allow buttons.`,
      ...(iconPath ? { icon: iconPath } : {}),
      silent: false,
    });
    notification.on("show", () => done({ ok: true }));
    notification.on("failed", (_event, error) => {
      deliveryRefused = true;
      onRefused?.();
      done({ ok: false, error: String(error) });
    });
    notification.show();
    // macOS answers within milliseconds; a silence this long is recorded as
    // undetermined — not a refusal — because the OS permission prompt or a busy
    // Notification Center can also hold the answer.
    setTimeout(() => done({ ok: false, error: NO_ANSWER, undetermined: true }), 4000);
  });
}

/**
 * The startup digest: one banner after the first scan settles, carrying the
 * numbers a person opens the app for — today's spend, the week, and how many
 * exposures wait for review. It is also the launch-time delivery CHECK
 * (show/failed reported like testNotification), so Settings can say
 * "delivering" without anyone pressing Test — a digest is a banner worth
 * sending, where a bare "testing notifications" on every start was not.
 */
export function notifyStartupDigest(
  summary: StatusSummary,
  handlers: { onClick(): void; iconPath?: string },
): Promise<DeliveryCheck> {
  if (!Notification.isSupported()) {
    return Promise.resolve({ ok: false, error: "this platform has no notifications", undetermined: true });
  }
  const status = statusBannerText(summary);
  return new Promise((resolve) => {
    let settled = false;
    const done = (result: DeliveryCheck) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const notification = trackDelivery(new Notification({
      id: "doorman-startup-digest",
      title: "Doorman — watching",
      subtitle: status.subtitle,
      body: status.body,
      ...(handlers.iconPath ? { icon: handlers.iconPath } : {}),
      // A status line, not an interruption.
      silent: true,
    }));
    notification.on("show", () => done({ ok: true }));
    notification.on("failed", (_event, error) => done({ ok: false, error: String(error) }));
    notification.on("click", handlers.onClick);
    notification.show();
    setTimeout(() => done({ ok: false, error: NO_ANSWER, undetermined: true }), 4000);
  });
}

export function deliver(
  title: string,
  body: string,
  onClick?: () => void,
  nav?: NoticeMirror["nav"],
  options: { mirror?: boolean } = {},
): void {
  // Mirror BEFORE the isSupported gate: on a platform with no notifications at
  // all, the in-window copy is the delivery, not a duplicate of one.
  //
  // `mirror: false` is for the one message the window is already showing: a new
  // finding lands on the Radar and bumps the sidebar badge, so a toast saying
  // so is a third copy of a fact already on screen — and findings arrive in
  // bursts, which made the toast the most frequent thing in the app. The OS
  // banner still fires, because that one is for when you are somewhere else.
  if (options.mirror !== false) mirrorNotice({ title, body, nav });
  if (!Notification.isSupported()) return;
  const notification = trackDelivery(new Notification({ title, body }));
  if (onClick) notification.on("click", onClick);
  notification.show();
}

/**
 * The launch-time delivery check for when the startup digest is turned off: a
 * SILENT banner withdrawn the instant Notification Center accepts it, so the
 * check leaves no on-screen residue — its only job is the show/failed answer.
 * (The digest, when enabled, is the better probe: a banner worth reading that
 * reports the same answer. This exists so turning the digest off doesn't also
 * turn off knowing whether notifications work.)
 *
 * It still carries the STATUS SUMMARY rather than the words "delivery check",
 * because withdrawal is a request, not a guarantee: a Mac in Focus mode, a
 * slow Notification Center, or a build macOS never authorized can leave the
 * banner (or its Notification Center row) on screen after `close()`. What is
 * left behind should then be the same thing the digest would have said — the
 * quiet default costs the person nothing, but it must not cost them a banner
 * that says nothing.
 */
export function probeNotificationDelivery(
  summary?: StatusSummary,
): Promise<DeliveryCheck> {
  if (!Notification.isSupported()) {
    return Promise.resolve({ ok: false, error: "this platform has no notifications", undetermined: true });
  }
  const status = summary ? statusBannerText(summary) : undefined;
  return new Promise((resolve) => {
    let settled = false;
    const done = (result: DeliveryCheck) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const notification = new Notification({
      id: "doorman-startup-digest",
      title: "Doorman — watching",
      ...(status ? { subtitle: status.subtitle } : {}),
      body: status?.body ?? "Watching this computer's coding agents.",
      silent: true,
    });
    notification.on("show", () => {
      notification.close();
      done({ ok: true });
    });
    notification.on("failed", (_event, error) => {
      deliveryRefused = true;
      onRefused?.();
      done({ ok: false, error: String(error) });
    });
    notification.show();
    setTimeout(() => done({ ok: false, error: NO_ANSWER, undetermined: true }), 4000);
  });
}

/**
 * A held tool call, asked THROUGH Notification Center: the banner carries the
 * decision buttons, so the answer costs one click from wherever you are instead
 * of a trip to the window. macOS shows the first action inline and tucks the
 * rest under the banner's Options; `notification.on("action")` reports which.
 *
 * DENY IS FIRST, and that ordering is the safety property: macOS surfaces the
 * first action most prominently, and the prominent button on a security prompt
 * must not be the one that lets the call through.
 *
 * Returns the Notification so the caller can withdraw it — a banner still
 * sitting there after the hold was answered in the window (or timed out) is an
 * invitation to answer a question that no longer exists. Undefined when the
 * platform has no notifications at all, in which case the window overlay is
 * the whole UI and nothing here is load-bearing.
 */
export function notifyApprovalNeeded(
  request: ApprovalRequest,
  handlers: { onDeny(): void; onAllow(): void; onOpen(): void; iconPath?: string },
): Notification | undefined {
  if (!Notification.isSupported()) return undefined;
  const where = approvalWhere(request);
  const notification = trackDelivery(new Notification({
    // Identity: macOS labels the banner with the app name and the bundle icon,
    // so the brand is already on it — `icon` adds the mark as the banner's
    // attachment image, and the subtitle names the RULE so the banner says what
    // is wrong before you decide.
    id: `doorman-approval-${request.id}`,
    groupId: "cloud.pinata.doorman.approvals",
    title: "Doorman — approve tool call?",
    subtitle: approvalRules(request),
    body:
      (where ? `${where}\n` : "") +
      (request.on_timeout === "deny"
        ? `Denied automatically in ${request.hold_seconds}s.`
        : request.source === "codex"
          ? `Codex warns and continues in ${request.hold_seconds}s; native ask is unsupported.`
          : `Handed to Claude Code in ${request.hold_seconds}s.`),
    ...(handlers.iconPath ? { icon: handlers.iconPath } : {}),
    // Not silent: the session is stopped until this is answered, so it earns a
    // sound rather than sliding past unheard.
    silent: false,
    urgency: "critical",
    actions: [
      { type: "button", text: "Deny" },
      { type: "button", text: "Allow once" },
    ],
    closeButtonText: "Later",
  }));
  notification.on("action", (_event, index) => {
    if (index === 0) handlers.onDeny();
    else handlers.onAllow();
  });
  // Clicking the body is "show me the details" — never a silent approval.
  notification.on("click", handlers.onOpen);
  notification.show();
  return notification;
}

/**
 * The guard is no longer as the app left it: its hook entry removed or
 * rewritten, or a bundle file changed. Not a finding banner — the thing this
 * announces is that findings may have STOPPED arriving. Critical urgency, and
 * the one action a person can take is offered on the banner.
 */
/**
 * A downloaded update is waiting on the person (the window is in front, so the
 * self-install holds off). The OS banner with an **Update now** button; the
 * in-window card is raised by the caller with a stable id (state.ts
 * updateReadyNotice), so this deliberately does NOT mirror through the sink —
 * a generated-id mirror would stack a new card on every reminder.
 */
export function notifyUpdateReady(
  version: string | undefined,
  handlers: { onInstall(): void; onOpen(): void; iconPath?: string },
): Notification | undefined {
  if (!Notification.isSupported()) return undefined;
  const label = version ? `v${version}` : "an update";
  const notification = trackDelivery(
    new Notification({
      id: "doorman-update-ready",
      title: `Doorman ${label} is ready`,
      body: "Update now to restart into it. It also installs on its own once the window is out of sight.",
      ...(handlers.iconPath ? { icon: handlers.iconPath } : {}),
      silent: true,
      actions: [{ type: "button", text: "Update now" }],
      closeButtonText: "Later",
    }),
  );
  notification.on("action", () => handlers.onInstall());
  notification.on("click", handlers.onOpen);
  notification.show();
  return notification;
}

export function notifyGuardTampered(
  description: string,
  handlers: { onReinstall(): void; onOpen(): void; iconPath?: string },
): Notification | undefined {
  mirrorNotice({ title: "Doorman — the guard was changed", body: description, nav: "radar" });
  if (!Notification.isSupported()) return undefined;
  const notification = trackDelivery(
    new Notification({
      id: "doorman-guard-integrity",
      title: "Doorman — the guard was changed",
      subtitle: "Nothing is being held until it is restored",
      body: description,
      ...(handlers.iconPath ? { icon: handlers.iconPath } : {}),
      silent: false,
      urgency: "critical",
      actions: [{ type: "button", text: "Reinstall the guard" }],
      closeButtonText: "Later",
    }),
  );
  notification.on("action", () => handlers.onReinstall());
  notification.on("click", handlers.onOpen);
  notification.show();
  return notification;
}

/** An MCP server's tool description changed after the person recognized it —
 * the rug pull. The recognition is stale; say so once per change. */
export function notifyMcpToolChanged(
  server: string,
  tool: string,
  note: string,
  handlers: { onOpen(): void; iconPath?: string },
): void {
  const title = `Doorman — ${server} changed a tool description`;
  const body = `${tool}: ${note}. Its recognition no longer covers what the server now says — review it in Integrations.`;
  mirrorNotice({ title, body, nav: "radar" });
  if (!Notification.isSupported()) return;
  const notification = trackDelivery(
    new Notification({
      id: `doorman-mcp-changed-${server}-${tool}`,
      title,
      body,
      ...(handlers.iconPath ? { icon: handlers.iconPath } : {}),
      silent: false,
    }),
  );
  notification.on("click", handlers.onOpen);
  notification.show();
}

const THRESHOLD_RANK: Record<Exclude<NotifyThreshold, "off">, number> = {
  critical: SEVERITY_RANK.critical,
  high: SEVERITY_RANK.high,
  medium: SEVERITY_RANK.medium,
};

export function findingsAboveThreshold(
  rows: readonly FindingRow[],
  threshold: NotifyThreshold,
): FindingRow[] {
  if (threshold === "off") return [];
  const min = THRESHOLD_RANK[threshold];
  return rows.filter((row) => SEVERITY_RANK[row.severity] >= min);
}

/** One notification per batch — a backfill burst must never become a burst of
 * banners (the initial scan is already suppressed upstream; this handles a
 * chatty session). */
export function notifyFindings(
  rows: readonly FindingRow[],
  threshold: NotifyThreshold,
  onClick: () => void,
): void {
  const relevant = findingsAboveThreshold(rows, threshold);
  if (relevant.length === 0) return;
  let max: SecuritySeverity = "low";
  for (const row of relevant) {
    if (SEVERITY_RANK[row.severity] > SEVERITY_RANK[max]) max = row.severity;
  }
  const first = relevant[0]!;
  const label = first.detector_label ?? localDetectorLabel(first.detector);
  const title =
    relevant.length === 1
      ? `Security Radar: ${label}`
      : `Security Radar: ${relevant.length} new findings`;
  const body =
    relevant.length === 1
      ? `${max} severity${first.key_name ? ` · ${first.key_name}` : ""}${first.enforced ? ` · ${first.enforced === "deny" ? "blocked" : "asked"}` : ""}`
      : `Highest severity: ${max}. Open the Radar to review.`;
  // Banner only — see `mirror` in deliver(): the Radar and its badge are the
  // in-window copy, and they are already up to date by the time this runs.
  deliver(title, body, onClick, "radar", { mirror: false });
}

/**
 * The coaching banner — what a warn-mode rule produces instead of a hold. The
 * call already ran (warn never blocks), so the banner's job is teaching, not
 * deciding: it names the rule, shows where it fired, and offers the one action
 * a nudge can honestly offer — stop warning about this rule. Silent (no sound):
 * nothing is waiting on the person. One banner per detector per batch, capped,
 * so a chatty session can't wallpaper Notification Center.
 */
const COACH_BANNER_CAP = 3;

export function notifyCoaching(
  rows: readonly FindingRow[],
  handlers: { onOpen(): void; onStopWarning(detector: string): void; iconPath?: string },
): void {
  if (rows.length === 0) return;
  const byDetector = new Map<string, FindingRow[]>();
  for (const row of rows) {
    const list = byDetector.get(row.detector);
    if (list) list.push(row);
    else byDetector.set(row.detector, [row]);
  }
  let shown = 0;
  for (const [detector, group] of byDetector) {
    if (shown >= COACH_BANNER_CAP) break;
    shown += 1;
    const first = group[0]!;
    const label = first.detector_label ?? localDetectorLabel(detector);
    const where = [first.tool_name, first.target].filter(Boolean).join(" → ");
    const body =
      (where ? `${where}\n` : "") +
      "The call ran — this rule is set to warn, not hold. Click for the evidence.";
    // Mirror into the in-window notice stack first, same as every other banner.
    mirrorNotice({ title: `Doorman — heads up: ${label}`, body, nav: "radar" });
    if (!Notification.isSupported()) continue;
    const notification = trackDelivery(
      new Notification({
        id: `doorman-coach-${first.finding_id}`,
        title: `Doorman — heads up: ${label}`,
        ...(group.length > 1 ? { subtitle: `${group.length} calls this session` } : {}),
        body,
        ...(handlers.iconPath ? { icon: handlers.iconPath } : {}),
        // A nudge, not an interruption: the call already happened.
        silent: true,
        actions: [{ type: "button", text: "Watch only from now on" }],
        closeButtonText: "OK",
      }),
    );
    notification.on("action", () => handlers.onStopWarning(detector));
    notification.on("click", handlers.onOpen);
    notification.show();
  }
}

const DIGEST_HOUR_LOCAL = 9;

/** Next 09:00 local strictly after `now` — Monday-only when weekly. */
export function nextDigestAt(now: Date, weekly: boolean): Date {
  const next = new Date(now.getFullYear(), now.getMonth(), now.getDate(), DIGEST_HOUR_LOCAL, 0, 0, 0);
  while (next <= now || (weekly && next.getDay() !== 1)) {
    next.setDate(next.getDate() + 1);
    next.setHours(DIGEST_HOUR_LOCAL, 0, 0, 0);
  }
  return next;
}

/** The period's security facts, as the digest states them. Computed by the
 * caller from the findings ledger, the inventory and the egress set over
 * `days` — 1 for the daily digest, 7 for the Monday one. */
export interface SecurityWeek {
  /** The window these facts were counted over. The body needs it: "a quiet
   * week" and "a quiet day" are different claims, and a digest that says the
   * wrong one is a digest that gets ignored. Optional so a caller written
   * before the daily digest existed still types, and reads as the week. */
  days?: number;
  held: number;
  denied: number;
  blocked: number;
  new_rules_fired: string[];
  new_mcp_servers: number;
  new_egress_destinations: number;
  open_groups: number;
  guard_healthy: boolean;
}

/** One sentence per fact, only the facts that are non-zero — a digest that
 * reads "0 held · 0 denied · 0 new servers" is a digest nobody opens twice. */
export function securityDigestBody(week: SecurityWeek): string {
  const parts: string[] = [];
  if (week.held > 0) parts.push(`${week.held} call${week.held === 1 ? "" : "s"} held for you`);
  if (week.denied > 0) parts.push(`${week.denied} denied`);
  if (week.blocked > 0) parts.push(`${week.blocked} blocked outright`);
  if (week.new_rules_fired.length > 0) {
    parts.push(
      `${week.new_rules_fired.length} rule${week.new_rules_fired.length === 1 ? "" : "s"} fired for the first time (${week.new_rules_fired.slice(0, 3).join(", ")}${week.new_rules_fired.length > 3 ? ", …" : ""})`,
    );
  }
  if (week.new_mcp_servers > 0) parts.push(`${week.new_mcp_servers} new MCP server${week.new_mcp_servers === 1 ? "" : "s"}`);
  if (week.new_egress_destinations > 0) {
    parts.push(`${week.new_egress_destinations} new external destination${week.new_egress_destinations === 1 ? "" : "s"}`);
  }
  const period = week.days === 1 ? "day" : "week";
  const head = parts.length > 0 ? `${parts.join(" · ")}.` : `A quiet ${period}: nothing held, nothing new.`;
  const tail = week.open_groups > 0 ? ` ${week.open_groups} exposure${week.open_groups === 1 ? "" : "s"} still need review.` : "";
  const guard = week.guard_healthy ? "" : " The guard is not installed as the app left it — check Settings.";
  return `${head}${tail}${guard}`;
}

export class DigestScheduler {
  private timers: NodeJS.Timeout[] = [];

  constructor(
    private readonly deps: {
      prefs(): Prefs;
      graphs(): SpendGraphs;
      onClick(): void;
      /** The security facts over `days`, for the security digest. Optional:
       * older callers and tests don't send one. */
      securityWeek?(days: number): SecurityWeek;
      onSecurityClick?(): void;
    },
  ) {}

  start(): void {
    this.stop();
    this.schedule(false);
    this.schedule(true);
  }

  stop(): void {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers = [];
  }

  private schedule(weekly: boolean): void {
    const at = nextDigestAt(new Date(), weekly);
    const timer = setTimeout(() => {
      this.fire(weekly);
      this.schedule(weekly); // chain, don't interval — DST-proof
    }, at.getTime() - Date.now());
    timer.unref?.();
    this.timers.push(timer);
  }

  /** The security digest rides whichever slot its period names, on its own
   * preference and its own period — so security can be daily while spend is
   * weekly, or either can be off without the other. */
  fireSecurity(weekly: boolean): void {
    const prefs = this.deps.prefs();
    if (prefs.notify_security_digest === false || !this.deps.securityWeek) return;
    if ((prefs.security_digest_period === "weekly") !== weekly) return;
    const days = weekly ? 7 : 1;
    const week = this.deps.securityWeek(days);
    deliver(
      weekly ? "Doorman — this week's security" : "Doorman — today's security",
      securityDigestBody({ ...week, days }),
      this.deps.onSecurityClick ?? this.deps.onClick,
      "radar",
    );
  }

  private fire(weekly: boolean): void {
    const prefs = this.deps.prefs();
    this.fireSecurity(weekly);
    if (!prefs.notify_spend_digest) return;
    if ((prefs.spend_digest_period === "weekly") !== weekly) return;
    const graphs = this.deps.graphs();
    if (weekly) {
      deliver(
        "Doorman — weekly usage",
        `Last 7 days: ${formatTokens(graphs.window_tokens)} tokens across your local sessions.`,
        this.deps.onClick,
        "spend",
      );
      return;
    }
    const yesterday = graphs.token_days.length >= 2 ? graphs.token_days[graphs.token_days.length - 2]!.total : 0;
    deliver(
      "Doorman — daily usage",
      `Yesterday: ${formatTokens(yesterday)} · Last 7 days: ${formatTokens(graphs.window_tokens)} tokens.`,
      this.deps.onClick,
      "spend",
    );
  }
}
