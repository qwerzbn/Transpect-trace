# Target-bound ECW2 audit pipe overlay

This additive `target-bound-v1` patch is opt-in. It leaves the original enhanced
patches and all existing build identities intact. Build with
`build_ecapture_windows.py --variant enhanced --target-bound-pipe` into a new
output directory. It changes only the collector-side local audit pipe ACL.

The collector first verifies the chosen target PID and creation time, opens that
exact process token with query-only access, and reads a bounded token user and at
most 256 restricted SIDs. Only SYSTEM, the collector user, the target token user
and SIDs actually present in that token can receive DACL entries. A low mandatory
integrity label permits an explicitly selected restricted child to write audit
frames. No target token, sandbox, certificate policy or security setting changes.

The existing local-only pipe, first-instance ownership, client PID and creation
time verification, random session identity and ECW2 frame validation remain in
force. An ACL alone does not authenticate the writer. Token or identity lookup
failure refuses initialization; unknown patch sets and mismatched overlay hashes
refuse build verification. Diagnostics contain fixed reason codes only.

`target_pipe_windows_test.go` checks actual current-process token lookup and stale
generation refusal, as well as malformed SID ranges. It is copied into the
derived build tree for component tests and is excluded by `go build` naturally.
These component checks do not replace a real restricted Codex child capture.
