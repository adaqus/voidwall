---
name: docs-sync
description: Bring the Voidwall user docs in docs/ up to date with a code change, or bump the website docs link after a release. Use after openspec-apply-change, after add-pii, after a bug fix that changes what a page says, after docker/ctl release, or when asked to check or update the docs.
---

# Sync the User Docs

Read `docs/AGENTS.md` first. It holds the rules for every page. This skill finds the pages
that a change makes old, updates them, and checks them.

Do not edit `openspec/specs/`. Do not commit. Propose a commit message that follows
`CONTRIBUTING.md#commit-messages`.

## 1. Find the change

- After `openspec-apply-change`: read the change's `proposal.md` and spec deltas, and the
  diff.
- After any other change: read the diff (`git diff`, or `git diff main...HEAD` on a branch).
- After a release: go to step 5.

List what a user can see change: a config key or default, an endpoint, a status, a body,
a guard, a kind, a country, a language, a model, a platform, a port.

## 2. Map the change to pages

| The change touches | Check these pages |
|---|---|
| `crates/voidwall/src/config.rs`, `validate.rs` | `configuration.md` |
| `http_api.rs`, `docs/openapi.json`, `admin.rs` | `api-reference.md` |
| The LiteLLM route | `api-reference.md`, `recipes/litellm.md` |
| `reverse_proxy` or the `openai-chat` format | `configuration.md`, `recipes/anythingllm.md`, `recipes/odysseus.md` |
| `voidwall-pii` kinds, countries, languages, custom rules (`add-pii` too) | `guards/pii-regex.md` |
| `voidwall-ml` adapters, model guard fields | `guards/model-guards.md`, `guards/custom-guard.md` |
| The `hidden_context` guard | `guards/hidden-context.md` |
| A new guard, or a guard that covers a new risk | `guards/`, `owasp-coverage.md`, `../voidwall-website/src/06-coverage.jsx` |
| The default models, `docker/voidwall-image.toml` | `about.md`, `quick-start.md`, `hardware.md` |
| The CPU check, ONNX Runtime, memory use | `hardware.md`, `about.md` |
| Outcomes, statuses, `on_error` | `guards/README.md`, `api-reference.md` |
| A built backlog item | Remove it from `docs/dev/backlog.md` |

For a change outside this map, find the page in `docs/README.md` that covers it. If no
page covers it, say so in the report. Do not add a page unless the user agrees.

Also check the root `README.md`. It holds a short quick start and links only.

## 3. Update the pages

- Change only what the change made old. Keep the style of the page.
- Keep every rule in `docs/AGENTS.md`. The rules that are easy to miss: one source for
  each topic, fake data only, "HTTP API", built behavior only, the tested app versions in
  a recipe.
- Take facts from the code and `openspec/specs/`, not from an old page.
- A page that `docs/AGENTS.md` lists but that does not exist yet: report it. Do not write
  it unless the task asks for it.

## 4. Check

Every relative link in `docs/` and `README.md` resolves. Run from the workspace root; it
prints nothing when all links resolve:

```bash
grep -rnoE '\]\([^)#[:space:]]+(#[^)]*)?\)' docs README.md \
  | grep -vE '\]\((https?|mailto):' \
  | while IFS= read -r hit; do
      file=${hit%%:*}; target=${hit#*](}; target=${target%)}; target=${target%%#*}
      [ -e "$(dirname "$file")/$target" ] || echo "broken: $hit"
    done
```

Then:

- Run `cargo test --workspace`. It holds the `openapi.json` test and, once
  `configuration.md` exists, the test of its keys.
- Run each example you changed, and compare its output with the page.

## 5. After a release

The website "Docs" link points to `docs/` at the latest release tag. Move it to the new
tag.

1. Find the tag: `git tag --sort=-v:refname | head -n 1`, for example `v0.6.0`.
2. In `../voidwall-website`, work in a worktree. Set the docs link constant in
   `src/00-base.jsx` to `https://github.com/adaqus/voidwall/tree/<tag>/docs`. If the
   constant does not exist yet, report it and stop.
3. Run `./build.sh` in the website worktree, and check the link in the top bar.
4. Do not deploy. `fly deploy` runs only when the user says so.

## 6. Report

- The pages you changed, and the reason for each.
- The pages you checked and left as they were.
- The pages the change needs that do not exist yet.
- The check results.
- A proposed commit message.
