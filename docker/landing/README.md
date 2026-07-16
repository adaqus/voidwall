# Voidwall landing page

Static landing page rendered from a small React/JSX source. Editing means
changing a `.jsx` file under `src/`, running `./build.sh`, and reloading
`index.html` in a browser.

## Prerequisites

- Docker (the build runs entirely inside containers — no host Node/npm/Chrome).
- Internet access on the first run (Docker pulls `node:lts-alpine`,
  `nginx:alpine`, `curlimages/curl`, and `zenika/alpine-chrome`).

## Where to change what

Each section of the page lives in its own JSX file under `src/`, numbered in
the order it appears on the page.

| File                       | Section                                                            |
| -------------------------- | ------------------------------------------------------------------ |
| `src/00-base.jsx`          | Asset-path base + `vwAsset` helper (loaded first)                  |
| `src/01-icons.jsx`         | Shared SVG icon set used by every other section                    |
| `src/02-nav.jsx`           | Top navigation bar                                                 |
| `src/03-hero.jsx`          | Hero ("invisible wall…") + headline variants                       |
| `src/04-metrics.jsx`       | Metrics strip below the hero                                       |
| `src/05-features.jsx`      | "Inspect → Enforce → Sanitize → Audit" feature row                 |
| `src/06-coverage.jsx`      | Detection coverage — PII types, languages, **countries**           |
| `src/07-analytics.jsx`     | GA4 / Matomo example                                               |
| `src/08-formats.jsx`       | Tabbed JSON / CSV / TSV / plain-text panel (only interactive part) |
| `src/09-performance.jsx`   | Performance numbers                                                |
| `src/10-blog.jsx`          | Blog teaser cards (home page) + the shared `PostCard`              |
| `src/11-cta.jsx`           | Bottom call-to-action                                              |
| `src/12-footer.jsx`        | Footer                                                             |
| `src/13-blog-index.jsx`    | Blog listing page rendered at `/blog/`                             |
| `src/14-privacy.jsx`       | Privacy policy page rendered at `/privacy/`                        |
| `src/15-blog-post.jsx`     | Single blog post rendered at `/blog/<slug>/`                       |
| `src/16-app.jsx`           | Top-level component order + path router; hydrates the page         |
| `src/blog/posts/*.md`      | Blog post content (markdown + frontmatter). Filename = URL slug.   |
| `build-posts.cjs`          | Build step: markdown → `assets/posts.js` (`window.POSTS`).         |
| `src/index.template.html`  | HTML shell (title, meta/OG tags, asset links). No content goes here. |
| `src/og-image.html`        | Social share card; screenshot to `assets/og-image.png` (1200×630). |
| `assets/styles.css`        | All design-system styles. Hand-edit for layout/color tweaks.       |

The `16-app.jsx` entry point must stay the highest-numbered file: it calls
`hydrateRoot`, which renders the view components, so every component file has to
be concatenated before it.

## Editing workflow

1. Open the relevant file under `src/` and change the copy or markup.
2. From `docker/landing/`:
   ```sh
   ./build.sh
   ```
3. Reload `index.html` in a browser.

The build does two things:

1. **Transpiles** every `src/*.jsx` into `assets/app.js` (Babel in
   `node:lts-alpine`).
2. **Pre-renders** the page with headless Chromium and writes the rendered
   DOM to `index.html`. The bundle uses `ReactDOM.hydrateRoot`, so React
   reuses the snapshot at runtime without flicker.

Pre-rendering is what makes the page indexable by Google and visible to
crawlers / social previews that don't run JavaScript. After the build,
`index.html` is the canonical artifact to serve — it contains the full page
content directly, not just a `<div id="root">`.

The build pre-renders **one file per route**: the home page (`index.html`),
the blog index (`blog/index.html`), and one page per post
(`blog/<slug>/index.html`). All of them are build artifacts — commit them
alongside `assets/app.js`. In production, tower-http `ServeDir` resolves a
directory request (`/blog/`, `/blog/<slug>/`) to that directory's
`index.html`, so no router config is needed; `docker/Dockerfile.fly` copies the
whole `blog/` tree into the image.

Each generated page links its assets with **relative** paths (`assets/…`,
`../assets/…`, …), rewritten by `build.sh` to match how deep the file sits.
That keeps the files openable directly from disk (`file://`) as well as when
served. Navigation links between pages stay root-absolute (`/blog/`) so served
URLs stay clean. (Cross-page navigation via `file://` won't resolve those clean
URLs — to click through the blog locally, serve the folder, e.g.
`python3 -m http.server` from `docker/landing/`.)

## The blog

Posts live as markdown files under `src/blog/posts/`. The **filename is the
slug** and the URL segment: `src/blog/posts/why-proxy.md` → `/blog/why-proxy/`.
Each file starts with a frontmatter block:

```markdown
---
title: Why we built Voidwall as a proxy, not a library.
tag: Engineering
date: 2026-05-12
read: 8 min read
excerpt: One-sentence summary shown on the cards.
---

Markdown body. `##` becomes a section heading, lists and code fences are
styled by `.vw-prose` in assets/styles.css.
```

`build.sh` converts every post to HTML and writes `assets/posts.js`
(`window.POSTS`), the single source the home-page teaser, the `/blog/` index,
and each post page all read from.

### Add a post

1. Create `src/blog/posts/<slug>.md` with the frontmatter above.
2. Run `./build.sh`.
3. The post appears at `/blog/<slug>/`, in the `/blog/` index, and (if it's one
   of the three newest) in the home-page teaser — all automatically.

All five frontmatter fields are required; the build fails loudly if one is
missing. Posts are ordered newest-first by `date`.

## Worked example — update the supported-country count

The country list is split across two places in `src/06-coverage.jsx`:

1. The headline copy (currently `"Eleven countries."`):
   ```jsx
   Over 80 PII types.<br/>Three languages.<br/>Eleven countries.
   ```
2. The strip rendered below it:
   ```jsx
   const countries = [
     "United States", "United Kingdom", "France", "Germany",
     "Netherlands", "Italy", "Spain", "Poland",
     "Belgium", "Canada", "Switzerland",
   ];
   ```

To add Sweden as the twelfth country:

1. Change the headline to `Twelve countries.`
2. Append `"Sweden"` to the `countries` array.
3. Run `./build.sh`.
4. Reload `index.html`.

## Adding a whole new section

1. Create e.g. `src/NN-new-section.jsx` (use a number that places it where you
   want in the page, but **below `16-app.jsx`**). Define one React component and
   publish it on `window`, matching the pattern in the existing files:
   ```jsx
   function NewSection() {
     return <section className="vw-container">…</section>;
   }
   window.NewSection = NewSection;
   ```
2. Add `<NewSection/>` to the `App` JSX in `src/16-app.jsx` at the right spot.
3. `./build.sh`.

## Styling

All CSS lives in `assets/styles.css`. It's hand-edited — there's no
preprocessor. The design tokens are CSS variables at the top of the file
(`--vw-paper`, `--vw-void-ink`, `--vw-violet-400`, etc.); prefer those over
literal colors. Component classes (`.vw-container`, `.vw-btn`, …) live at
the bottom.

## Output

`./build.sh` writes:

- `assets/app.js` — transpiled bundle
- `index.html` (+ `blog/`, `privacy/` pages) — pre-rendered, contains the full page content
- `assets/og-image.png` — 1200×630 social card, screenshot of `src/og-image.html`
- `sitemap.xml` — absolute URLs for every route (home, blog index, privacy, each post)

Everything else under `assets/` (fonts, SVGs, vendor React builds, the
existing logo files) is static and not regenerated. `robots.txt` is a static
file that points crawlers at `sitemap.xml`.

## Troubleshooting

- **Build complains about missing docker images** — the first run pulls
  ~600 MB across three images; subsequent runs reuse the cache.
- **Page renders blank after build** — open the browser console. A
  hydration mismatch usually means a JSX file references a variable that
  isn't defined yet at load time; remember the files are concatenated in
  filename order, so a component used in `03-hero.jsx` must be declared in
  a file with a lower prefix (e.g. `01-icons.jsx`).
- **`index.html` no longer matches the JSX after editing** — you forgot to
  run `./build.sh`. The HTML is a build artifact, not a hand-edited file.
