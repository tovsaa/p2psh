# Contributing

Thanks for picking this up. P2PSH is a small project; the contributor
process is light.

## Dev environment

You need:

- **Node.js 22+** (`node --version`)
- **npm 11+** ships with node 22
- A **`nym-client`** binary reachable on `ws://127.0.0.1:1977` for any
  end-to-end testing. Easiest path: `docker run` the published image
  (`ghcr.io/tovsaa/p2psh:latest`) and tail its logs to get a connect
  string — that exposes the same gateway you'd hit locally. To run a
  free-standing `nym-client`, grab the upstream release from
  <https://github.com/nymtech/nym/releases>, then:
  ```bash
  nym-client init --id p2psh
  nym-client run --id p2psh
  ```

Clone + install:

```bash
git clone https://github.com/tovsaa/p2psh
cd p2psh
npm ci
```

## Running locally

Three things you can run, each in its own terminal:

```bash
npm run server          # the Node server, prints a p2psh1:// connect string
npm run web             # Vite dev server at http://127.0.0.1:5173
P2PSH_CONNECT=… npm run client   # the CLI probe
```

The server needs a live `nym-client` at `P2PSH_NYM_URL` (default
`ws://127.0.0.1:1977`); the web client speaks Nym directly over WASM in the
browser.

## Tests

```bash
npm run typecheck       # strict TS, no emit
npm test                # ML-KEM KAT + AEAD + handshake regression suites
npm audit --omit=dev --audit-level=critical   # CI gates on this
```

`tests/ml-kem-kat.ts` carries hardcoded expected bytes; if you bump
`@noble/post-quantum` (kept exact-pinned in `package.json` on purpose),
run `node tests/_compute-kat.mjs` and paste the new values back in.

Add tests when you touch the wire or the crypto layer. They are cheap to
write — see the existing files for the pattern.

## Style + conventions

- `tsc --strict`; the existing code is type-clean and the CI workflow
  runs `npm run typecheck` on every PR.
- New `.ts` files start with `// SPDX-License-Identifier: Apache-2.0`.
- LF line endings everywhere (`.gitattributes` enforces this on
  `*.sh` and `Dockerfile`).
- Conventional commit prefixes: `feat`, `fix`, `docs`, `test`, `build`,
  `perf`, `refactor`, `chore`. Look at `git log --oneline` for the tone.
- Commit messages should explain the *why* in the body, not just the
  *what*. Pull-request descriptions can be terser if the commits already
  carry the explanation.
- **Do not add `Co-Authored-By` trailers** to commits — the maintainer
  doesn't want AI-attribution noise in the history.

## Pull requests

- Branch off `main`, push, open the PR.
- CI must be green (`test` + `container` + `pages`) before merge.
- If you're changing the wire protocol, update `src/shared/protocol.ts`
  comments + `SECURITY.md` + `tests/handshake.ts` in the same PR.
- For deploy-affecting changes, smoke-test `deploy/docker-compose.yml`
  locally and mention the result in the PR.

## Security issues

See [`SECURITY.md`](SECURITY.md) for the report channel and threat model.
