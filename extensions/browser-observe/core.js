/* Pure request extraction, also exercised under Node without browser mocks. */
(function (root) {
  "use strict";
  const LIMIT = 1024 * 1024;
  function origin(value) {
    const url = new URL(value);
    const port = url.port || "443";
    return `${url.protocol}//${url.hostname}:${port}`;
  }
  function permitted(details, enrolled) {
    try {
      const url = new URL(details.url);
      return url.protocol === "https:" && !url.username && !url.password &&
        origin(details.url) === origin(enrolled) && ["/upload", "/chat"].includes(url.pathname) &&
        ["POST", "PUT"].includes(details.method);
    } catch (_) { return false; }
  }
  function snapshot(details, stage) {
    const url = new URL(details.url);
    const row = {request_id: String(details.requestId), request_stage: stage,
      tab_id: details.tabId, frame_id: details.frameId, document_id: details.documentId || null,
      url: origin(details.url) + url.pathname, method: details.method,
      body_bytes: 0, raw_complete: false, gaps: [], bytes: null};
    const body = details.requestBody;
    if (!body || body.error) { row.gaps.push(body && body.error ? "capture_error" : "raw_unavailable"); return row; }
    if (body.formData) { row.gaps.push("form_data_unsupported"); return row; }
    if (!Array.isArray(body.raw)) { row.gaps.push("raw_unavailable"); return row; }
    const segments = [];
    for (const part of body.raw) {
      if (part.file !== undefined) { row.gaps.push("file_reference"); continue; }
      if (!(part.bytes instanceof ArrayBuffer)) { row.gaps.push("raw_segment_unsupported"); continue; }
      row.body_bytes += part.bytes.byteLength;
      if (row.body_bytes <= LIMIT) segments.push(new Uint8Array(part.bytes).slice());
    }
    if (row.body_bytes > LIMIT) row.gaps.push("body_limit");
    if (row.gaps.length) return row;
    row.bytes = new Uint8Array(row.body_bytes);
    let offset = 0;
    for (const part of segments) { row.bytes.set(part, offset); offset += part.byteLength; }
    row.raw_complete = true;
    return row;
  }
  function beforeHeaders(row, details) {
    const kinds = (details.requestHeaders || []).filter(h => h.name.toLowerCase() === "content-type");
    const encodings = (details.requestHeaders || []).filter(h => h.name.toLowerCase() === "content-encoding");
    row.content_type = kinds.length === 1 ? String(kinds[0].value || "").slice(0, 128) : "unsupported";
    row.content_encoding = encodings.length === 0 ? "identity" : encodings.length === 1 ? String(encodings[0].value || "").slice(0, 64) : "unsupported";
    row.event_phase = "before_send_headers";
    return row;
  }
  function wire(row) {
    let encoded = "";
    if (row.bytes) {
      for (let i = 0; i < row.bytes.length; i += 8192)
        encoded += String.fromCharCode(...row.bytes.subarray(i, i + 8192));
    }
    const result = {...row, body_base64: btoa(encoded)};
    delete result.bytes;
    return result;
  }
  const api = {LIMIT, origin, permitted, snapshot, beforeHeaders, wire};
  root.TTBrowserCore = api;
  if (typeof module !== "undefined") module.exports = api;
})(globalThis);
