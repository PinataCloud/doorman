import { contextBridge, ipcRenderer } from "electron";

const api = {
  getState: () => ipcRenderer.invoke("state:get"),
  onState: (cb: (state: unknown) => void) => {
    const listener = (_e: unknown, state: unknown) => cb(state);
    ipcRenderer.on("state:changed", listener);
    return () => ipcRenderer.removeListener("state:changed", listener);
  },
  onNav: (cb: (screen: unknown) => void) => {
    const listener = (_e: unknown, screen: unknown) => cb(screen);
    ipcRenderer.on("nav:go", listener);
    return () => ipcRenderer.removeListener("nav:go", listener);
  },
  searchTurns: (query: string) => ipcRenderer.invoke("ledger:search", query),
  sessionTurns: (sessionId: string, offset: number, limit: number) =>
    ipcRenderer.invoke("ledger:session-turns", sessionId, offset, limit),
  /** The RAW stored text of one ledger turn — displayed redacted by default. */
  turnRaw: (turnId: string) => ipcRenderer.invoke("ledger:turn-raw", turnId),
  /** Re-read a finding's raw window from the transcript on disk. Local only. */
  revealFinding: (findingId: string) => ipcRenderer.invoke("radar:reveal", findingId),
  /** SECRET TRACE: everywhere a pasted value appears in what the agents on
   * this Mac wrote. The value crosses the bridge once and is never kept. */
  traceSecret: (value: string) => ipcRenderer.invoke("radar:trace-secret", value),
  onTraceProgress: (cb: (progress: unknown) => void) => {
    const listener = (_e: unknown, progress: unknown) => cb(progress);
    ipcRenderer.on("trace:progress", listener);
    return () => ipcRenderer.removeListener("trace:progress", listener);
  },
  /** Show a transcript file the last trace named in Finder. */
  showTraceFile: (path: string) => ipcRenderer.invoke("radar:trace-show-file", path),
  openTraceFileInEditor: (path: string) => ipcRenderer.invoke("radar:trace-open-in-editor", path),
  setFindingStatus: (findingId: string, status: string) =>
    ipcRenderer.invoke("radar:finding-status", findingId, status),
  setFindingStatusBulk: (findingIds: string[], status: string) =>
    ipcRenderer.invoke("radar:finding-status-bulk", findingIds, status),
  setDetectorMode: (detector: string, mode: string) =>
    ipcRenderer.invoke("radar:detector-mode", detector, mode),
  /** Move the security level — one preset over the same per-detector
   * modes; packs, custom rules, exceptions and the hold behaviour survive it.
   * `saveAs` keeps the rules as they stand under that name first, which is the
   * confirm sheet's offer before a level overwrites a hand-edited rule. */
  setSecurityLevel: (level: string, saveAs?: string) =>
    ipcRenderer.invoke("radar:security-level", level, saveAs),
  /** Saved rule sets: keep the current rules under a name, put one back, or
   * drop one. */
  saveRuleSet: (name: string) => ipcRenderer.invoke("rules:set-save", name),
  restoreRuleSet: (id: string) => ipcRenderer.invoke("rules:set-restore", id),
  deleteRuleSet: (id: string) => ipcRenderer.invoke("rules:set-delete", id),
  setConfirmPolicy: (patch: unknown) => ipcRenderer.invoke("radar:confirm-policy", patch),
  /** The local-model second opinion: settings patch, and a reachability probe
   * of the configured endpoint (lists the models it serves). */
  setSecondOpinion: (patch: unknown) => ipcRenderer.invoke("radar:second-opinion", patch),
  probeSecondOpinion: () => ipcRenderer.invoke("radar:second-opinion-probe"),
  /** The injection classifier (Prompt Guard 2 in the app process): settings
   * patch, and whether the runtime + model are actually present on this Mac. */
  setInjectionClassifier: (patch: unknown) => ipcRenderer.invoke("radar:injection-classifier", patch),
  probeInjectionClassifier: () => ipcRenderer.invoke("radar:injection-classifier-probe"),
  /** Fetch the pinned model (~82 MB) into the data folder, or remove it. */
  downloadInjectionModel: () => ipcRenderer.invoke("radar:injection-classifier-download"),
  removeInjectionModel: () => ipcRenderer.invoke("radar:injection-classifier-remove"),
  /** The person's ignore rules (incl. the scoped "allow for this project" ones):
   * add one, or remove one by its position in the policy's list. */
  addIgnoreRule: (rule: unknown) => ipcRenderer.invoke("rules:ignore-add", rule),
  removeIgnoreRule: (index: number) => ipcRenderer.invoke("rules:ignore-remove", index),
  /** Custom rules: replace the whole list (the editor saves the set), or dry-run
   * one rule over the last 14 days of transcripts — a preview the editor offers
   * before a save, never a precondition of one. */
  setCustomRules: (rules: unknown) => ipcRenderer.invoke("rules:custom-set", rules),
  dryRunCustomRule: (rule: unknown, days?: number) => ipcRenderer.invoke("rules:custom-dry-run", rule, days),
  /** Shipped rule packs on/off. */
  setRulePack: (packId: string, on: boolean) => ipcRenderer.invoke("rules:pack", packId, on),
  /** My wallets: the chains watched + unknown-address posture (patch), and the
   * person's own addresses — added by value (hashed in main, never stored) and
   * removed by hash. */
  setWallets: (patch: unknown) => ipcRenderer.invoke("rules:wallets", patch),
  addWallet: (address: string, label: string) => ipcRenderer.invoke("rules:wallet-add", address, label),
  removeWallet: (hash: string) => ipcRenderer.invoke("rules:wallet-remove", hash),
  /** Per-server MCP gateway permissions: read / write / act → allow / ask / block. */
  setMcpPermission: (server: string, cls: string, mode: string) =>
    ipcRenderer.invoke("mcp:permission", server, cls, mode),
  /** Export the local security report (masked) to a file the person chooses. */
  exportSecurityReport: (format: "markdown" | "json") => ipcRenderer.invoke("radar:export-report", format),
  /** Export every shown detection as the schema-valid JSON bundle
   * (lib/detection-schema.ts) — masked, fingerprints only. */
  exportDetections: () => ipcRenderer.invoke("radar:export-detections"),
  /** Export the Event Ledger (every session, or one) as the schema-valid JSON
   * bundle (lib/ledger-export.ts) — redacted text, fingerprints only. */
  exportLedger: (sessionId?: string) => ipcRenderer.invoke("ledger:export", sessionId),
  /** Re-run the guard integrity check now. */
  checkGuardIntegrity: () => ipcRenderer.invoke("guard:integrity"),
  /** The masked context a reference (a finding id, a held call id, an MCP
   * server name) resolves to — main builds it; the renderer never composes
   * evidence itself. The "How to fix this?" prompt is built from it. */
  aiContext: (contextRef: unknown) => ipcRenderer.invoke("ai:context", contextRef),
  /** macOS notification permission: send one and see, or open its settings. */
  testNotification: () => ipcRenderer.invoke("notifications:test"),
  openNotificationSettings: () => ipcRenderer.invoke("notifications:open-settings"),
  /** Retire an in-window notice (state.notices) — auto-expiry and the ✕ alike. */
  dismissNotice: (id: string) => ipcRenderer.invoke("notices:dismiss", id),
  /** Answer a held tool call. `options.silence` also switches its detectors to
   * observe; `options.scope === "project"` writes a dated ignore rule for the
   * call's directory; `options.via` says which surface answered. */
  resolveApproval: (
    id: string,
    verdict: "allow" | "deny",
    options?: boolean | { silence?: boolean; scope?: "project"; via?: "panel" | "window" | "notification" },
  ) =>
    ipcRenderer.invoke(
      "approvals:resolve",
      id,
      verdict,
      typeof options === "boolean" ? { silence: options } : options ?? {},
    ),
  /** The floating panel's card height in CSS pixels; its window resizes to fit. */
  fitApprovalPanel: (height: number) => ipcRenderer.send("panel:fit", height),
  installGuard: () => ipcRenderer.invoke("guard:install"),
  uninstallGuard: () => ipcRenderer.invoke("guard:uninstall"),
  setPrefs: (patch: unknown) => ipcRenderer.invoke("prefs:set", patch),
  rescan: () => ipcRenderer.invoke("capture:rescan"),
  /** Mark an MCP server recognized (or clear it) — feeds the approved-server
   * list the unknown_mcp_server radar rule reads. */
  recognizeMcpServer: (server: string, recognized: boolean) =>
    ipcRenderer.invoke("mcp:recognize", server, recognized),
  /** Route (or restore) a server's config entry through the MCP gateway so its
   * live tool descriptions can be scanned for poisoning. */
  routeMcpServer: (server: string, configPath: string, on: boolean) =>
    ipcRenderer.invoke("mcp:route-gateway", server, configPath, on),
  /** Bring a live session's terminal forward, or resume an ended one in a
   * new window — lib/terminal-handoff.ts decides which. */
  liveOpen: (ref: { session_id?: string; pid?: number }) => ipcRenderer.invoke("live:open", ref),
  liveRefresh: () => ipcRenderer.invoke("live:refresh"),
  openExternal: (url: string) => ipcRenderer.invoke("shell:open", url),
  openDataDir: () => ipcRenderer.invoke("shell:open-data-dir"),
  checkForUpdates: () => ipcRenderer.invoke("updater:check"),
  installUpdate: () => ipcRenderer.invoke("updater:install"),
  /** Setup doctor: re-check now (applying lossless repairs), or repair —
   * everything fixable, or one check by id (this is how the lossy
   * "restore from backup" runs: only ever on an explicit click). */
  doctorCheck: () => ipcRenderer.invoke("doctor:check"),
  doctorRepair: (checkId?: string) => ipcRenderer.invoke("doctor:repair", checkId ?? null),
  /** Move this copy into /Applications and relaunch — the setup flow's first
   * step when macOS launched the app from a temporary location. On success the
   * app relaunches, so this promise usually never settles. */
  moveToApplications: () => ipcRenderer.invoke("app:move-to-applications"),
  quit: () => ipcRenderer.invoke("app:quit"),
};

contextBridge.exposeInMainWorld("doorman", api);

export type ObApi = typeof api;
