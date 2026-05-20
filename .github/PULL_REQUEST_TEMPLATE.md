<!--
Thanks for the PR. Keep this template short — only fill in what's relevant.
See CONTRIBUTING.md for the full guidelines.
-->

## What

<!-- One-line summary. The detailed "why" goes in the commits themselves. -->

## How verified

- [ ] `npm run typecheck` passes
- [ ] `npm test` passes (KAT + AEAD + handshake)
- [ ] `npm audit --omit=dev --audit-level=critical` passes
- [ ] Manual smoke test on the touched path (web / CLI / server / docker)

## Notes for the reviewer

<!-- Anything unusual: protocol change, behavior change, dropped feature,
     deferred follow-up. Leave empty if nothing surprising. -->
