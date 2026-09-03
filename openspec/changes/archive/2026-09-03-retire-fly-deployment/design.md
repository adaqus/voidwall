## Context

See `proposal.md` — Why.

Three facts shape the approach.

**The build cannot move into a Dockerfile.** The landing page's `build.sh` orchestrates
sibling containers — Babel in `node:lts-alpine`, then `nginx:alpine` plus
`zenika/alpine-chrome` on a throwaway Docker network to pre-render each route with
`--dump-dom` and screenshot the OG card. A Fly remote builder cannot run that. The model
therefore stays as it already is: run `build.sh` locally, commit the artifacts, and let
the image serve only files.

**The pages carry no absolute asset paths.** `build.sh` rewrites asset URLs to
depth-correct relative paths and keeps navigation links root-absolute. That is what makes
nginx a drop-in: no rewriting, no base tag, no router config. `try_files $uri $uri/`
resolves `/blog/` and `/blog/<slug>/` exactly as tower-http's `ServeDir` did.

**Fly IP allocations and TLS certificates belong to the app, not to `fly.toml`.**

## Goals / Non-Goals

**Goals:**

- `voidwall.io` keeps its anycast IP and certificate across the switch, with no window
  where the site is dark.
- The product repo carries no Fly-specific code, config, or build file afterwards.
- The code matches the `http-api` four-route requirement it had been contradicting.

**Non-Goals:**

- The "AI firewall" repositioning of the page's title, hero, features, and coverage. That
  is content work and it now belongs to the `voidwall-website` repo. This change moves
  the page as it is.
- A public API on a subdomain. If a hosted API returns — the pivot's `/v1/guard` endpoint —
  it gets its own app and its own decision. Nothing here forecloses that.
- CI. There is none today and this adds none. Both repos stay on manual `fly deploy`.

## Decisions

**Retire the public proxy deployment outright, rather than splitting it onto a second
host.** `voidwall.io` becomes purely static: no public API, no public demo. The
alternative — keep the API on `api.voidwall.io` and reverse-proxy or CORS between the two
— costs a second Fly app, a split-brain config, and CORS work, to serve an endpoint with
no users. Retiring it is what makes everything else cheap, and it is what removes the
`fly-rate-limit` justification.

**Reuse the Fly app slot `voidwall` rather than creating a new app.** Deploying a
different image to the same app keeps the anycast IP and the `voidwall.io` certificate,
so the Cloudflare A record needs no change and there is no certificate-issuance window.
The alternative — create a new app, `fly certs add`, repoint A and AAAA, destroy the old
app — costs a propagation window and buys only a tidier app name.

**Keep `docker/demo/` as a local development tool.** It is a hand-maintained API
playground that reads `window.PII_API_URL`, injected by `30-render-config.sh` under
`docker compose`. That path never touched `Dockerfile.fly` and keeps working. Only its
Fly presence goes — the `[[statics]]` block and two `COPY` lines. Deleting it as well
would remove a working local tool for no gain.

**Remove `fly-rate-limit` rather than renaming or generalizing it.** Making it a
general-purpose rate limiter would mean choosing a client-identification strategy that
does not assume Fly's edge, which is a design question with no current caller. Deleting
it now and adding a real one later, if a hosted endpoint returns, is cheaper than
carrying a half-general feature nobody builds.

**Extract with `git subtree split`, not by copying files.** `git-filter-repo` is not
installed on this machine and `subtree` is sufficient: it lands the 60 files at the new
repo's root with their 28 commits intact. Copying would lose the history of a page that
has been edited across half the project's life.

## Risks / Trade-offs

**A broken landing image replaces the running proxy image on the same app, so there is no
"old site" to fall back to.** → Verify the image locally first — build it, run it, and
curl every route plus the expected 404s and the `/blog` redirect — before `fly deploy`.
Recovery, if it is still wrong, is `fly releases rollback`.

**The product-repo deletions are irreversible in effect if the new site does not work.**
→ Order the work: build the new repo, deploy it, verify the live site, and only then
delete from the product repo. The content is also safe in the new repo's git history
either way.

**The demo page links to `/privacy/`, which only ever resolved because Fly unified the
two concerns under one hostname.** → Accept it. On `localhost:8088` that link 404s, as it
already did before this change. Fixing it would mean duplicating the privacy page into a
repo that no longer owns it.

**Removing a requirement narrows the spec, and a future hosted endpoint may want a rate
limit back.** → The removal records its reason and migration. A future public endpoint
proposes its own requirement, with a client-identification strategy suited to wherever it
runs, rather than inheriting one written for Fly's edge.

## Migration Plan

1. Extract `docker/landing/` into `voidwall-website` with history; drop dead files.
2. Build the nginx image and verify every route locally.
3. `fly deploy` from the new repo, then verify the live site — including that `/v1/info`
   and `/demo` now return 404 and the OG image still resolves.
4. Only then delete and edit in the product repo, and run the workspace checks.

Rollback: `fly releases rollback` restores the previous image on the same app. The
product-repo changes are a normal revert.
