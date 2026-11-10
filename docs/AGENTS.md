# Documentation Instructions

`docs/` holds the user documentation of Voidwall. `docs/dev/` holds the material for
contributors. The website top bar links to `docs/` at the latest release tag, so a user
reads the docs of the image they run.

Keep these rules when you edit `docs/`. The `docs-sync` skill finds the pages that a code
change makes old. Run it after a change, and read this file first.

## Layout

| Path | Holds |
|---|---|
| `README.md` | The index, and the target of the website "Docs" link |
| `about.md` | What Voidwall is, its guards, ONNX Runtime, project status, licence |
| `quick-start.md` | The first run of the image |
| `hardware.md` | CPU, memory, disk, and platforms |
| `recipes/` | One page per integration: `litellm.md`, `anythingllm.md`, `odysseus.md` |
| `configuration.md` | Every configuration key, its default, and validation |
| `api-reference.md` | The HTTP API and the admin server; it links `openapi.json` |
| `guards/` | `README.md`, `pii-regex.md`, `model-guards.md`, `hidden-context.md`, `custom-guard.md` |
| `owasp-coverage.md` | OWASP Top 10 for LLM Applications (2026) coverage |
| `dev/` | Contributor material: the backlog, the TODO list, load testing |

More topics come later. Add a page to the index when you add it to `docs/`.

## Rules

1. Describe only behavior that is built and tested. Unbuilt work goes in
   `docs/dev/backlog.md`.
2. Put contributor material in `docs/dev/` or `ARCHITECTURE.md`, never in a user page. How
   to declare a model guard in configuration is user material. How to write a Rust `Guard`
   is contributor material.
3. Give each topic one source. Other places link to it and do not copy it.
   - The root `README.md` stays short: the pitch, a short quick start, and links here.
   - `owasp-coverage.md` is the source of the website coverage table
     (`../voidwall-website/src/06-coverage.jsx`). Change both in the same change.
4. Call the API on port 8083 the "HTTP API", never the "REST API". It is not REST.
5. `configuration.md` lists every key with its description and its default value. A
   test checks the keys against the config types; add the test with the page.
6. Test each recipe end to end, and name the version of each app you tested. A proxy-mode
   recipe states that the reverse proxy reaches plain-HTTP upstreams only. A hosted model,
   such as OpenAI, goes through LiteLLM.
7. A platform that was not tested carries a "not tested yet" notice. Today that is Docker
   Desktop on macOS and on Windows.
8. Update the docs in the same change as the behavior they describe.
9. Use only fake data in examples: `example.com` addresses, invented names, and invented
   numbers. A doc never holds a real detected value.
10. Write simple English (ASD-STE100): short sentences, one instruction in each, common
    words.
11. `owasp-coverage.md` names categories of controls only, never tools, products, or
    competitors. Use the website scale: Direct, Partly, Not covered, Other layer. State
    that Voidwall is not affiliated with OWASP.

## Checks

- Every relative link resolves (see the `docs-sync` skill).
- The examples in a page give the output the page shows. Run them against the image of
  the release the page describes.
- Claims match `openspec/specs/`. When they differ, the spec and the code are right, and
  the page is wrong.
