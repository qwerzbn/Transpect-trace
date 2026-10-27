# Chromium Content Analysis SDK pin

The Native Content Analysis Agent is built against the exact upstream commit
recorded in `manifest.json`. The build refuses a different or dirty checkout
and verifies every SDK source file used by the Windows agent.

The SDK is BSD-3-Clause licensed. No SDK source is copied into this repository.
The ignored `.external/content-analysis-sdk` checkout is only a local source
cache; it is not a build input until its commit, cleanliness and hashes pass.

The selected commit contains the upstream Windows fix for named-pipe responses
larger than 4 KiB. A later untagged commit is intentionally not used because its
demo client references a protobuf field absent from the matching schema.

`local_user_agent` / `path_user` is a Chrome test provider, not a production
provider identity. Production deployment requires formal provider onboarding
or another supported integration. The Chrome connector policies are cloud-only
and must be delivered through Chrome Enterprise management.
