import { useEffect, useRef, useState } from "react";
import { type EventRecord, type FacetSchema } from "../lib/api";
import { formatFacetValue, useFacets } from "../lib/facets";
import { fmtTime, statusColorClass } from "../lib/format";

type RowState = EventRecord & {
  frames?: { direction: string; frame: string; ts: string }[];
  // repeat is the number of coalesced occurrences this row stands for
  // (see coalesceAdjacent). Absent/1 for an ordinary single event; the
  // row carries the newest occurrence's timestamp/status/ms.
  repeat?: number;
};

function isDeniedAction(ev: EventRecord): boolean {
  return ev.action === "deny" || ev.action === "denied" || ev.action === "hitl_deny";
}

// A "quiet" dial is an allowed brokered-dial action — the gateway→upstream
// dial a plugin endpoint makes (e.g. an AWS call's dial to *.amazonaws.com).
// It carries no metadata, so it's hidden unless the operator opts in. A
// denied dial is a blocked egress and is never hidden.
function isQuietDial(ev: EventRecord): boolean {
  return ev.method === "dial" && !isDeniedAction(ev);
}

// isCollapsible gates which rows are allowed to fold into a run. Only
// "quiet" completed rows collapse — anything that renders its own
// detail block (in-flight, WS frames, denied, approved-by, awaiting
// approval) always shows in full so nothing security-interesting hides
// behind a counter.
function isCollapsible(ev: RowState): boolean {
  if (ev.phase === "start") return false;
  if ((ev.frames?.length ?? 0) > 0) return false;
  if (isDeniedAction(ev)) return false;
  if (ev.action === "approved" || ev.action === "hitl_allow") return false;
  if (ev.action === "hitl_pending") return false;
  return true;
}

// rowSignature is the collapse key: two rows fold together iff they
// would render the same leading verb, host+body, and status. Reusing
// rowDescriptors means the rule is simply "rows that look identical
// collapse" — no separate notion of sameness to keep in sync.
function rowSignature(ev: RowState, byFamily: Record<string, FacetSchema>): string {
  const schema = ev.family ? byFamily[ev.family] : undefined;
  const { verb, body } = rowDescriptors(ev, schema);
  return [ev.family ?? "", ev.host, verb, body, ev.status ?? "", ev.mode ?? ""].join("\n");
}

// coalesceAdjacent folds consecutive collapsible rows with the same
// signature into a single row carrying a `repeat` count (browser-console
// style). Applied to the buffer on every merge so a chatty endpoint (a
// burst of Telegram getUpdates polls) occupies ONE slot instead of
// evicting distinct events under the `max` cap. The kept row is the
// newest occurrence (the list is newest-first, so it's the head of the
// run); its repeat accumulates the occurrences it stands for.
//
// A row that isn't collapsible, or whose signature differs from the
// current run, breaks the run — so an interleaved distinct request (a
// sendMessage between two bursts of getUpdates) keeps them as two rows
// and preserves the timeline. Only completed rows coalesce (isCollapsible
// excludes in-flight/frames/denied/approved/pending), so this never
// disturbs the id-correlated start/end/frame bookkeeping in mergeEvent.
function coalesceAdjacent(rows: RowState[], byFamily: Record<string, FacetSchema>): RowState[] {
  const out: RowState[] = [];
  let lastSig = "";
  for (const ev of rows) {
    const prev = out[out.length - 1];
    const sig = rowSignature(ev, byFamily);
    if (prev && isCollapsible(ev) && isCollapsible(prev) && sig === lastSig) {
      // Keep prev (the newer occurrence, already at the head) and roll
      // ev's count into it. Clone so we never mutate a row still held by
      // the previous React state.
      out[out.length - 1] = { ...prev, repeat: (prev.repeat ?? 1) + (ev.repeat ?? 1) };
      continue;
    }
    out.push(ev);
    lastSig = sig;
  }
  return out;
}

export function LiveRequests({
  agentIP,
  max = 200,
  height,
}: {
  agentIP?: string;
  max?: number;
  height?: string;
}) {
  const [events, setEvents] = useState<RowState[]>([]);
  // Allowed brokered "dial" actions are the plumbing behind a plugin
  // endpoint (an AWS API call's gateway→AWS dial); they carry no metadata
  // and just clutter the log, so hide them by default. Denied dials are a
  // real egress block and always show (isQuietDial excludes them).
  const [showDials, setShowDials] = useState(false);
  const { byFamily } = useFacets();
  // coalesceAdjacent runs inside the setEvents updaters, which are
  // created once by the effect below; a ref keeps them reading the
  // latest facet schema (it loads async after mount) without re-running
  // the effect and tearing down the SSE connection.
  const byFamilyRef = useRef(byFamily);
  byFamilyRef.current = byFamily;

  useEffect(() => {
    setEvents([]);
    const url = agentIP ? `/api/events?agent=${encodeURIComponent(agentIP)}` : "/api/events";
    const es = new EventSource(url);

    // Batched render: SSE can fire dozens of events per second on a
    // busy gateway (start + frame + end per request). setState every
    // event = a re-render every event = jank. Buffer parsed events
    // into pending[] and flush via requestAnimationFrame; the React
    // commit happens at most once per browser frame (~16 ms) no
    // matter how many events arrived in between.
    let pending: EventRecord[] = [];
    let raf = 0;
    const flush = () => {
      raf = 0;
      if (pending.length === 0) return;
      const batch = pending;
      pending = [];
      setEvents((prev) => {
        let next = prev;
        for (const ev of batch) next = mergeEvent(next, ev);
        // Coalesce identical runs, THEN cap: the cap counts distinct
        // rows, so a flood of repeats can't evict distinct events.
        return coalesceAdjacent(next, byFamilyRef.current).slice(0, max);
      });
    };
    // Backlog ships as one event up front: bulk-insert in a single
    // commit so old events appear instantly instead of streaming in
    // through the live render path and looking like fresh activity.
    es.addEventListener("backlog", (e) => {
      try {
        const arr = JSON.parse((e as MessageEvent).data) as EventRecord[];
        setEvents((prev) => {
          let next = prev;
          for (const ev of arr) next = mergeEvent(next, ev);
          return coalesceAdjacent(next, byFamilyRef.current).slice(0, max);
        });
      } catch {
        /* ignore */
      }
    });
    es.onmessage = (e) => {
      try {
        pending.push(JSON.parse(e.data) as EventRecord);
        if (raf === 0) raf = requestAnimationFrame(flush);
      } catch {
        /* ignore */
      }
    };
    return () => {
      es.close();
      if (raf !== 0) cancelAnimationFrame(raf);
    };
  }, [agentIP, max]);

  const hiddenDials = events.reduce((n, e) => n + (isQuietDial(e) ? 1 : 0), 0);
  const shown = showDials ? events : events.filter((e) => !isQuietDial(e));
  // Rows are already coalesced in the buffer (see coalesceAdjacent), so
  // each carries a `repeat`. Sum them for the header so the count still
  // reads as total requests seen, not collapsed rows.
  const shownTotal = shown.reduce((n, e) => n + (e.repeat ?? 1), 0);

  return (
    <div
      className="flex flex-col bg-canvas border-1.5 border-navy overflow-hidden"
      style={{ height: height ?? "420px" }}
    >
      <div className="flex items-center px-4 py-2.5 text-xs font-mono uppercase tracking-wider text-navy font-bold bg-navy-100 border-b border-navy shrink-0">
        <span>Live requests</span>
        <span className="ml-2 text-success-500 tabular-nums flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
          {shownTotal}
        </span>
        {hiddenDials > 0 && (
          <button
            type="button"
            onClick={() => setShowDials((v) => !v)}
            className="ml-auto normal-case tracking-normal font-normal text-2xs text-text-subtle hover:text-text-muted"
            title="Brokered upstream dials carry no metadata; hidden by default"
          >
            {showDials ? "hide" : "show"} {hiddenDials} dial{hiddenDials === 1 ? "" : "s"}
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto">
        {shown.length === 0 ? (
          <div className="px-5 py-8 text-center text-xs text-text-subtle flex items-center justify-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
            Waiting for requests
            <AnimatedDots />
          </div>
        ) : (
          shown.map((e, i) => (
            <Row
              key={i}
              ev={e}
              count={e.repeat ?? 1}
              schema={e.family ? byFamily[e.family] : undefined}
            />
          ))
        )}
      </div>
    </div>
  );
}

// mergeEvent applies a new SSE event to the row list:
//   - phase="start" with id  → prepend in-flight row, dedupe by id.
//   - phase="end" with id    → replace the matching in-flight row in
//                              place so its visual position doesn't
//                              jump (preserve any accumulated WS frames).
//   - phase="frame" with id  → append a frame to the matching row's
//                              `frames` list, no row reorder.
//   - phase undefined / no id → legacy/non-correlated event, prepend.
//
// Never truncates: the caller coalesces the result and applies the
// `max` cap afterwards, so a run of repeats collapses to one row before
// the cap counts it (otherwise a flood would evict distinct events).
function mergeEvent(prev: RowState[], ev: EventRecord): RowState[] {
  if (ev.id && ev.phase === "frame") {
    return prev.map((r) =>
      r.id === ev.id
        ? {
            ...r,
            frames: [
              ...(r.frames ?? []),
              {
                direction: ev.direction ?? "",
                frame: ev.frame ?? "",
                ts: ev.ts,
              },
            ],
          }
        : r,
    );
  }
  if (ev.id && ev.phase === "end") {
    let found = false;
    const next = prev.map((r) => {
      if (r.id !== ev.id) return r;
      found = true;
      return { ...ev, frames: r.frames };
    });
    if (found) return next;
    return [ev, ...prev];
  }
  if (ev.id && ev.phase === "start") {
    if (prev.some((r) => r.id === ev.id)) return prev;
    return [ev, ...prev];
  }
  return [ev, ...prev];
}

// rowDescriptors picks the short labels shown per event:
//   - leading slot (HTTP verb / SQL verb / k8s verb / "" if unknown)
//   - trailing slot (path / SQL summary / k8s resource·name / "")
// Uses the facet schema when one is registered for ev.family so new
// protocol plugins drop in without dashboard edits; falls back to
// the legacy method/path stuffing when facets aren't populated
// (pre-migration rows / unknown families).
export function rowDescriptors(
  ev: EventRecord,
  schema: FacetSchema | undefined,
): { verb: string; body: string } {
  const facets = ev.facets ?? {};
  if (schema && Object.keys(facets).length > 0) {
    // The leading column (the "verb") is the field the facet marks as
    // `title` — e.g. an AWS plugin marks iam_action so the row reads
    // "s3:ListBucket" rather than "POST". Facets that declare no title
    // (the built-ins) fall back to the method/verb-named field. The rest
    // of the report fields render into the trailing body, except those
    // marked `detail_only` (kept for the per-action detail view).
    const lead =
      schema.report_fields.find((f) => f.title) ??
      schema.report_fields.find((f) => f.name === "method") ??
      schema.report_fields.find((f) => f.name === "verb");
    const verb = lead ? formatFacetValue(lead.kind, facets[lead.name]) : "";
    const bodyParts: string[] = [];
    for (const f of schema.report_fields) {
      if (lead && f.name === lead.name) continue;
      if (f.detail_only) continue;
      // Status is rendered in its own coloured slot below — don't
      // duplicate it in the body.
      if (f.name === "status") continue;
      const v = formatFacetValue(f.kind, facets[f.name]);
      if (v) bodyParts.push(v);
    }
    return { verb, body: bodyParts.join(" · ") };
  }
  // Legacy fallback for events without a facets payload — the
  // gateway still populates ev.method/ev.path for back-compat with
  // pre-migration consumers.
  return { verb: ev.method ?? "", body: ev.path ?? "" };
}

function Row({
  ev,
  schema,
  count = 1,
}: {
  ev: RowState;
  schema: FacetSchema | undefined;
  count?: number;
}) {
  const onClick = ev.id
    ? () => {
        window.location.hash = `#/request/${ev.id}`;
      }
    : undefined;
  const time = fmtTime(ev.ts);
  const inFlight = ev.phase === "start";
  const status = ev.status ?? "";
  const statusColor = inFlight ? "text-text-subtle" : statusColorClass(status);
  const { verb, body } = rowDescriptors(ev, schema);
  const sep = body && !body.startsWith("/") ? " " : "";
  // "splice"/"relay" forward the bytes without inspecting them, so
  // there's no verb to show — surface a lock instead. Every other mode
  // (mitm HTTP, parsed SQL like "pg"/"clickhouse_native", k8s) is
  // inspected and shows its verb (empty if none was parsed).
  const inspected = ev.mode !== "splice" && ev.mode !== "relay";
  const hasFrames = (ev.frames?.length ?? 0) > 0;
  const isDenied = ev.action === "deny" || ev.action === "denied" || ev.action === "hitl_deny";
  const isApproved = ev.action === "approved" || ev.action === "hitl_allow";
  return (
    <div className="border-b border-canvas-muted">
      <div
        onClick={onClick}
        className={
          "px-4 py-2 flex items-center gap-3 min-w-0 transition-colors" +
          (onClick ? " cursor-pointer" : "") +
          (inFlight ? " opacity-70" : "") +
          " hover:bg-canvas-muted"
        }
      >
        <span className="text-2xs tabular-nums text-text-subtle shrink-0">{time}</span>
        <ApprovalStatusIcon ev={ev} inFlight={inFlight} />
        <span
          className="font-mono text-2xs font-semibold text-text-muted shrink-0 w-28 truncate flex items-center"
          title={inspected ? verb : undefined}
        >
          {inspected ? verb : <LockGlyph />}
        </span>
        <span
          className={"text-xs shrink-0 w-14 truncate " + statusColor}
          title={status || undefined}
        >
          {inFlight ? <InFlightSpinner /> : status || "—"}
        </span>
        <span className="text-xs text-text truncate flex-1 min-w-0" title={ev.host + sep + body}>
          <span className="text-text-muted">{ev.host}</span>
          {sep && <span> </span>}
          <span>{body}</span>
        </span>
        {count > 1 && (
          <span
            className="text-2xs tabular-nums font-mono font-semibold text-text-muted bg-navy-100 border border-navy/20 rounded px-1 shrink-0"
            title={`${count} identical requests collapsed`}
          >
            ×{count}
          </span>
        )}
        <span className="text-2xs tabular-nums text-text-subtle shrink-0">
          {inFlight ? "…" : ev.ms + "ms"}
        </span>
      </div>
      {inFlight && ev.action === "hitl_pending" && (
        <div className="px-4 pb-1.5 flex items-center gap-1.5 text-2xs font-mono text-butter-600">
          <span className="w-1.5 h-1.5 rounded-full bg-butter-400 animate-pulse shrink-0" />
          awaiting approval
        </div>
      )}
      {isDenied && (
        <div className="px-4 pb-1.5 flex items-center gap-1.5 text-2xs font-mono text-danger-600 min-w-0">
          <span className="w-1.5 h-1.5 rounded-full bg-danger-500 shrink-0" />
          <span className="font-semibold">denied</span>
          {ev.rule && <span className="text-danger-400 shrink-0">· {ev.rule}</span>}
          {ev.reason && <span className="text-text-subtle truncate">· {ev.reason}</span>}
        </div>
      )}
      {isApproved && ev.approver_by && (
        <div className="px-4 pb-1.5 flex items-center gap-1.5 text-2xs font-mono text-success-600">
          <span className="w-1.5 h-1.5 rounded-full bg-success-500 shrink-0" />
          approved by {ev.approver_by}
        </div>
      )}
      {hasFrames && (
        <div className="bg-canvas-muted border-t border-canvas-muted max-h-45 overflow-y-auto">
          {ev.frames!.map((f, i) => (
            <div key={i} className="px-4 py-1 flex items-start gap-2 text-2xs font-mono">
              <span className="text-text-subtle shrink-0 w-6">{f.direction}</span>
              <span className="text-text-muted truncate" title={f.frame}>
                {f.frame}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function InFlightSpinner() {
  return (
    <span className="inline-block w-1.5 h-1.5 rounded-full bg-text-subtle animate-pulse align-middle" />
  );
}

// AnimatedDots: cycles "", ".", "..", "..." every 400ms so the empty
// state reads as actively waiting rather than stalled. Pure CSS would
// need monospace + width pinning to avoid layout shift; the JS version
// is small and the surrounding row only paints when the list is empty.
function AnimatedDots() {
  const [n, setN] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setN((x) => (x + 1) % 4), 400);
    return () => clearInterval(t);
  }, []);
  return <span className="inline-block w-3 text-left">{".".repeat(n)}</span>;
}

// ApprovalStatusIcon renders the request's approval/policy outcome as
// a stoplight dot in the row's leading slot: green = allowed/approved,
// red = denied/error, amber (pulsing) = awaiting human approval, muted
// = in-flight/unknown. This slot previously showed MITM vs splice
// mode; the connection-visibility signal moved to the verb slot, which
// now shows a lock when the bytes weren't inspected.
export function ApprovalStatusIcon({ ev, inFlight }: { ev: EventRecord; inFlight: boolean }) {
  const a = ev.action ?? "";
  if (a === "hitl_pending")
    return <StatusDot cls="bg-butter-400 animate-pulse" title="awaiting approval" />;
  if (a === "deny" || a === "denied" || a === "hitl_deny")
    return <StatusDot cls="bg-danger-500" title="denied" />;
  if (a === "error") return <StatusDot cls="bg-danger-500" title="error" />;
  if (a === "approved" || a === "hitl_allow")
    return <StatusDot cls="bg-success-500" title="approved" />;
  if (a === "allow" || a === "passthrough")
    return <StatusDot cls="bg-success-500" title="allowed" />;
  if (inFlight) return <StatusDot cls="bg-text-subtle animate-pulse" title="in flight" />;
  return <StatusDot cls="bg-text-subtle" title={a || "—"} />;
}

function StatusDot({ cls, title }: { cls: string; title: string }) {
  return (
    <span title={title} className="shrink-0 flex items-center justify-center w-3.5">
      <span className={"w-2 h-2 rounded-full " + cls} />
    </span>
  );
}

// LockGlyph marks a connection the gateway passed through without
// inspecting (splice / relay), shown in the verb slot in place of a
// parsed method/verb — which only exists for inspected connections.
export function LockGlyph() {
  return (
    <span
      title="passed through — gateway did not inspect this connection"
      className="text-text-subtle"
    >
      <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
        <path d="M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V7a3 3 0 1 0-6 0v3Z" />
      </svg>
    </span>
  );
}
