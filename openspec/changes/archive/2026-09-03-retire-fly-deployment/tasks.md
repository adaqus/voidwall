## 1. Extract the marketing site

- [x] 1.1 Split `docker/landing/` into `~/Projects/voidwall/voidwall-website` with
      `git subtree split`, history intact — verify: 28 commits, 60 files, `src/00-base.jsx`
      through `src/16-app.jsx`
- [x] 1.2 Delete the dead files — `Voidwall Landing _standalone_.html` and the two
      superseded blog PNGs — verify: `./build.sh` still succeeds and nothing references them
- [x] 1.3 Remove the three `/demo` CTAs and the "Live demo available" hero badge, and drop
      the now-dead `external-link` icon — verify: `grep -rn '/demo' index.html blog/ privacy/`
      returns nothing
- [x] 1.4 Correct the privacy policy: the "Live demo" processing activity and the per-IP
      rate-limiting clause describe processing that no longer happens — verify: neither
      appears in `privacy/index.html`, and the last-updated date moves
- [x] 1.5 Add `nginx.conf`, `Dockerfile`, `.dockerignore`, `.gitignore`, and `fly.toml`
      (app `voidwall`, internal port 80, 256 MB / 1 CPU) — verify: `docker build` succeeds
- [x] 1.6 Move the `update-landing-piis` skill, repoint it at
      `../voidwall/crates/pii/src/lib.rs`, and fix its stale `03-metrics` / `05-coverage`
      filenames — verify: no path in it names `docker/landing`
- [x] 1.7 Refresh the README — a Deploying section, the committed-build-output list, and
      the stale worked example — verify: no README instruction names a `docker/landing` path

## 2. Verify and deploy the new site

- [x] 2.1 Run `./build.sh`, build the image, and curl every route locally — verify: `/`,
      `/blog/`, `/privacy/`, `/robots.txt`, `/sitemap.xml`, a post, and the assets answer
      200; `/demo` answers 404; `/blog` redirects
- [x] 2.2 Check the page in a browser — verify: the bundle hydrates, the format tabs
      switch, and no "Try the live demo" button appears
- [x] 2.3 `fly deploy` from `voidwall-website` — verify: `https://voidwall.io/` answers
      200, `/v1/info` and `/demo` answer 404, and `/assets/og-image.png` answers 200

## 3. Remove Fly from the product repo

**Do not start before task 2.3 passes.**

- [x] 3.1 Delete `docker/landing/`, `fly.toml`, `fly.io/`, `docker/Dockerfile.fly`, and
      `docker/Dockerfile.fly.dockerignore` — verify: no Fly build file remains
- [x] 3.2 Delete `crates/proxy/src/rate_limit.rs` and drop its gated `pub mod` from
      `crates/proxy/src/lib.rs` — verify: `cargo check --workspace` passes
- [x] 3.3 Drop the `ServeDir` import and both `#[cfg]` blocks from
      `crates/proxy/src/http_api.rs` — verify: the API serves exactly the four specified
      routes and `router` needs no rebinding
- [x] 3.4 Drop the `fly-rate-limit` and `fly-landing` features and the optional
      `tower_governor` / `governor` dependencies from `crates/proxy/Cargo.toml`, keeping
      `tower-http`'s `cors` feature — verify: `Cargo.lock` no longer lists either crate
- [x] 3.5 Delete `.agents/skills/update-landing-piis/` and its `.claude/skills/` symlink —
      verify: no skill in the product repo names `docker/landing`
- [x] 3.6 Update `ARCHITECTURE.md` (drop `rate_limit` from the module list) and `AGENTS.md`
      (drop "the landing page" from the OpenSpec exclusion list) — verify: neither names a
      file this change deleted
- [x] 3.7 Add an integration test asserting the API listener 404s on an unrouted path.
      The requirement the removed catch-all contradicted had no regression test —
      verify: the test fails when a `fallback` is present, passes when it is not

## 4. Verify the product repo

- [x] 4.1 Run `cargo check`, `cargo test`, and `cargo clippy --all-targets` across the
      workspace — verify: all pass, with clippy warnings treated as errors
- [x] 4.2 Sweep for leftovers — verify:
      `grep -rn "fly-landing\|fly-rate-limit\|srv/landing\|Fly-Client-IP" crates/ docker/ openspec/`
      returns nothing
- [x] 4.3 Confirm the demo still runs locally — verify: `docker/ctl start` serves it on
      `localhost:8088`
- [x] 4.4 Run `openspec validate retire-fly-deployment --strict`, review the diff against
      the spec delta, then `openspec archive retire-fly-deployment` — verify:
      `openspec/specs/http-api/spec.md` names no `fly-*` feature
