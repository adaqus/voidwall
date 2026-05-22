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
| `src/00-icons.jsx`         | Shared SVG icon set used by every other section                    |
| `src/01-nav.jsx`           | Top navigation bar                                                 |
| `src/02-hero.jsx`          | Hero ("invisible wall…") + headline variants                       |
| `src/03-metrics.jsx`       | Metrics strip below the hero                                       |
| `src/04-features.jsx`      | "Inspect → Enforce → Sanitize → Audit" feature row                 |
| `src/05-coverage.jsx`      | Detection coverage — PII types, languages, **countries**           |
| `src/06-analytics.jsx`     | GA4 / Matomo example                                               |
| `src/07-formats.jsx`       | Tabbed JSON / CSV / TSV / plain-text panel (only interactive part) |
| `src/08-custom-pii.jsx`    | Custom PII detector demo                                           |
| `src/09-performance.jsx`   | Performance numbers                                                |
| `src/10-blog.jsx`          | Blog teaser cards                                                  |
| `src/11-cta.jsx`           | Bottom call-to-action                                              |
| `src/12-footer.jsx`        | Footer                                                             |
| `src/13-app.jsx`           | Top-level component order; hydrates the page                       |
| `src/index.template.html`  | HTML shell (title, viewport, asset links). No content goes here.   |
| `assets/styles.css`        | All design-system styles. Hand-edit for layout/color tweaks.       |

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

## Worked example — update the supported-country count

The country list is split across two places in `src/05-coverage.jsx`:

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

1. Create `src/14-new-section.jsx` (use a number that places it where you
   want in the page). Define one React component and publish it on
   `window`, matching the pattern in the existing files:
   ```jsx
   function NewSection() {
     return <section className="vw-container">…</section>;
   }
   window.NewSection = NewSection;
   ```
2. Add `<NewSection/>` to the JSX in `src/13-app.jsx` at the right spot.
3. `./build.sh`.

## Styling

All CSS lives in `assets/styles.css`. It's hand-edited — there's no
preprocessor. The design tokens are CSS variables at the top of the file
(`--vw-paper`, `--vw-void-ink`, `--vw-violet-400`, etc.); prefer those over
literal colors. Component classes (`.vw-container`, `.vw-btn`, …) live at
the bottom.

## Output

`./build.sh` writes two files:

- `assets/app.js` — transpiled bundle
- `index.html` — pre-rendered, ~100 KB, contains the full page content

Everything else under `assets/` (fonts, SVGs, vendor React builds, the
existing logo files) is static and not regenerated.

## Troubleshooting

- **Build complains about missing docker images** — the first run pulls
  ~600 MB across three images; subsequent runs reuse the cache.
- **Page renders blank after build** — open the browser console. A
  hydration mismatch usually means a JSX file references a variable that
  isn't defined yet at load time; remember the files are concatenated in
  filename order, so a component used in `02-hero.jsx` must be declared in
  a file with a lower prefix (e.g. `00-icons.jsx`).
- **`index.html` no longer matches the JSX after editing** — you forgot to
  run `./build.sh`. The HTML is a build artifact, not a hand-edited file.
