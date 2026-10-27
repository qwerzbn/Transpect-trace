/* Request-body observation only. No request modification, blocking or CDP. */
importScripts("enrollment.js", "core.js");
"use strict";
const core = TTBrowserCore, config = TTEnrollment;
const session = crypto.randomUUID(), pending = new Map(), stages = new Map();
const queue = [];
let port = null, ready = false, stopped = false, finishing = false, inFlight = null;
let sequence = 0, lost = 0, pendingBytes = 0, queuedBytes = 0;
const gaps = new Set();
const filter = {urls: [config.origin.replace(/:\d+$/, "") + "/*"]};
function badge(text) { chrome.action.setBadgeText({text}); }
function gap(reason) { gaps.add(reason); lost++; badge("!"); }
function flush() {
  if (!port || inFlight || !queue.length) return;
  const row = queue.shift(); queuedBytes -= row.size;
  const message = {protocol: "BWO1", browser_run_id: config.browser_run_id,
    enrollment_token: config.enrollment_token, extension_session_id: session, sequence: ++sequence, ...row.data};
  inFlight = message.sequence;
  try { port.postMessage(message); } catch (_) { gap("host_disconnected"); port = null; inFlight = null; }
}
function enqueue(data) {
  const size = data.body_base64 ? data.body_base64.length : 1024;
  if (queue.length >= 8 || queuedBytes + size > 8 * 1024 * 1024) { gap("queue_overflow"); return false; }
  queue.push({data, size}); queuedBytes += size; flush(); return true;
}
function emit(row) { enqueue({kind: "request", ...core.wire(row)}); }
function release(key) {
  const row = pending.get(key);
  if (row) { pending.delete(key); pendingBytes -= row.bytes ? row.bytes.length : 0; }
  return row;
}
function finishIfDrained() {
  if (finishing && !inFlight && !queue.length && !stopped) {
    stopped = true;
    enqueue({kind: "terminal", lost_events: lost, gaps: [...gaps]});
    badge("STOP");
  }
}
chrome.webRequest.onBeforeRequest.addListener(details => {
  if (finishing || !core.permitted(details, config.origin)) return;
  if (!ready) { gap("host_disconnected"); return; }
  if (stages.size >= 4096 && !stages.has(details.requestId)) { gap("pending_overflow"); return; }
  const stage = (stages.get(details.requestId) || 0) + 1;
  stages.set(details.requestId, stage);
  const replaced = release(details.requestId);
  if (replaced) { replaced.gaps.push("missing_header_event"); replaced.event_phase = "request_aborted_before_headers"; emit(replaced); }
  const row = core.snapshot(details, stage);
  if (pending.size >= 32 || pendingBytes + (row.bytes ? row.bytes.length : 0) > 8 * 1024 * 1024) { gap("pending_overflow"); return; }
  pending.set(details.requestId, row); pendingBytes += row.bytes ? row.bytes.length : 0;
}, filter, ["requestBody"]);
chrome.webRequest.onBeforeSendHeaders.addListener(details => {
  const row = release(details.requestId);
  if (row) emit(core.beforeHeaders(row, details));
}, filter, ["requestHeaders"]);
function lifecycle(details, event) {
  const stage = stages.get(details.requestId);
  if (!stage || stopped) return;
  const row = release(details.requestId);
  if (row) { row.event_phase = "request_aborted_before_headers"; row.gaps.push("headers_unavailable"); emit(row); }
  enqueue({kind: "lifecycle", request_id: String(details.requestId), request_stage: stage, event});
  // Keep stage counters for redirects; request IDs are unique for the browser session.
}
chrome.webRequest.onCompleted.addListener(d => lifecycle(d, "completed"), filter);
chrome.webRequest.onErrorOccurred.addListener(d => lifecycle(d, "error"), filter);
chrome.webRequest.onBeforeRedirect.addListener(d => lifecycle(d, "redirect"), filter);
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return;
  if (message && message.action === "finish") {
    finishing = true;
    for (const key of [...pending.keys()]) {
      const row = release(key); row.gaps.push("pending_at_shutdown"); row.event_phase = "request_aborted_before_headers"; emit(row);
    }
    finishIfDrained();
  }
  reply({ready, stopped, lost_events: lost, pending: pending.size, queued: queue.length,
         can_enforce: false, network_process_binding: "unknown"});
});
(async () => {
  const prior = await chrome.storage.session.get("worker_seen");
  if (prior.worker_seen) gaps.add("worker_restarted");
  await chrome.storage.session.set({worker_seen: true});
  try {
    port = chrome.runtime.connectNative(config.host_name);
    port.onMessage.addListener(message => {
      if (message.protocol !== "BWO1" || message.ack !== inFlight) { gap("host_disconnected"); port.disconnect(); return; }
      if (message.ack === 1) { ready = true; badge(gaps.size ? "!" : "OBS"); }
      inFlight = null; flush(); finishIfDrained();
    });
    port.onDisconnect.addListener(() => {
      void chrome.runtime.lastError;
      if (!stopped) gap("host_disconnected");
      ready = false; port = null; pending.clear(); queue.length = 0;
      pendingBytes = 0; queuedBytes = 0; inFlight = null;
    });
    enqueue({kind: "ready", extension_id: chrome.runtime.id, lost_events: lost, gaps: [...gaps]});
  } catch (_) { gap("host_disconnected"); }
})();
