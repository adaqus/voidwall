#!/bin/sh
# Build pipeline:
#   1) Transpile src/*.jsx into assets/app.js (Babel in node:lts-alpine) and
#      generate assets/posts.js from src/blog/posts/*.md (markdown → HTML).
#   2) Spin up nginx on a private docker network and pre-render every page
#      (home + /blog/ + one per post) with headless Chromium, writing each
#      rendered DOM to its own index.html. The bundle uses ReactDOM.hydrateRoot,
#      so React reuses the snapshot for interactivity without a flash-replace.
set -eu
cd "$(dirname "$0")"
mkdir -p assets

# ── 1) Transpile JSX + build blog post data ─────────────────────────────────
echo "[1/3] transpiling src/*.jsx → assets/app.js, building assets/posts.js"
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/src":/src:ro \
  -v "$PWD/build-posts.cjs":/build-posts.cjs:ro \
  -v "$PWD/assets":/out \
  node:lts-alpine sh -c '
    set -eu
    cd /tmp
    npm init -y >/dev/null 2>&1
    npm install --silent --no-fund --no-audit \
      @babel/cli@7 @babel/core@7 @babel/preset-react@7 marked@4 >/dev/null
    : > bundle.jsx
    for f in /src/*.jsx; do
      printf "\n/* === %s === */\n" "$(basename "$f")" >> bundle.jsx
      cat "$f" >> bundle.jsx
    done
    npx --no babel bundle.jsx --presets=@babel/preset-react --out-file /out/app.js
    echo "  built assets/app.js ($(wc -c < /out/app.js) bytes)"
    NODE_PATH=/tmp/node_modules node /build-posts.cjs
  '

# ── 2) Pre-render via headless Chromium ─────────────────────────────────────
echo "[2/3] pre-rendering with headless Chromium"

# NOTE: the demo page (docker/demo/index.html) is NOT built here. It is a
# standalone, hand-maintained page shipped via Dockerfile.fly / docker-compose.
# Any site-wide <head>/analytics change made to src/index.template.html — e.g.
# the Cloudflare beacon, meta tags — must be mirrored into it by hand.
#
# Route list: home, blog index, one page per post. The output path mirrors the
# URL (/blog/<slug>/ → blog/<slug>/index.html) so both nginx (here) and
# tower-http ServeDir (in production) resolve <route> to <route>/index.html.
# The router in src/15-app.jsx picks the view from location.pathname.
routes="/ /blog/ /privacy/"
for f in src/blog/posts/*.md; do
  [ -e "$f" ] || continue
  routes="$routes /blog/$(basename "$f" .md)/"
done

route_to_out() {
  case "$1" in
    /) printf 'index.html' ;;
    *) printf '%sindex.html' "${1#/}" ;;
  esac
}

# Seed every output file with the unrendered template so nginx can serve the
# page (and the bundle can load) before Chromium snapshots the rendered DOM.
for route in $routes; do
  out=$(route_to_out "$route")
  mkdir -p "$(dirname "$out")"
  cp src/index.template.html "$out"
done

NET="landing-prerender-$$"
NGINX="landing-prerender-nginx-$$"

cleanup() {
  docker stop "$NGINX" >/dev/null 2>&1 || true
  docker network rm "$NET"  >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$NET" >/dev/null
docker run --rm -d --name "$NGINX" --network "$NET" \
  -v "$PWD":/usr/share/nginx/html:ro nginx:alpine >/dev/null

# Wait for nginx to be reachable.
for _ in 1 2 3 4 5; do
  docker run --rm --network "$NET" curlimages/curl:latest \
    -fsS "http://$NGINX/index.html" >/dev/null 2>&1 && break
  sleep 0.3
done

# --dump-dom prints the serialized DOM after the load event. virtual-time-budget
# lets the event loop run further so React's hydrate/render finishes before dump.
for route in $routes; do
  out=$(route_to_out "$route")
  docker run --rm --network "$NET" \
    --user "$(id -u):$(id -g)" \
    -v "$PWD":/work -w /work zenika/alpine-chrome \
    --no-sandbox --headless --disable-gpu \
    --virtual-time-budget=8000 \
    --dump-dom "http://$NGINX$route" > "$out.tmp" 2>/dev/null

  # --dump-dom emits the <html> element only; re-prepend the doctype.
  { printf '<!DOCTYPE html>\n'; cat "$out.tmp"; } > "$out"
  rm "$out.tmp"

  # Asset URLs are authored root-absolute (/assets/…) so nginx can serve them
  # while pre-rendering any route depth above. Rewrite them to depth-correct
  # relative paths in the final file so the page also renders when opened
  # straight from disk (file://), where a leading "/" points at the filesystem
  # root. One "../" per directory the file sits below the landing root:
  #   index.html              -> assets/…
  #   blog/index.html         -> ../assets/…
  #   blog/<slug>/index.html  -> ../../assets/…
  # Navigation links stay root-absolute, keeping clean URLs when served.
  prefix=""
  i=$(printf '%s' "$out" | tr -cd '/' | wc -c)
  while [ "$i" -gt 0 ]; do prefix="../$prefix"; i=$((i - 1)); done
  sed -i "s#\"/assets/#\"${prefix}assets/#g" "$out"

  # Fill the per-page canonical/OG URL. The template ships one placeholder so
  # every route self-canonicalizes to its own absolute URL (a hard-coded home
  # URL would make /blog/ and each post look like duplicates of the home page).
  sed -i "s#PAGE_URL_PLACEHOLDER#https://voidwall.io${route}#g" "$out"

  echo "  wrote $out ($(wc -c < "$out") bytes)"
done

# Open Graph card → assets/og-image.png. Same nginx (for the Geist webfont) and
# headless Chromium, but --screenshot at a fixed 1200×630 viewport instead of
# --dump-dom. Social platforms don't rasterize SVG og:images, so this must be a
# real PNG. Source: src/og-image.html.
echo "  screenshotting src/og-image.html → assets/og-image.png"
docker run --rm --network "$NET" \
  --user "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work zenika/alpine-chrome \
  --no-sandbox --headless --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=1 --window-size=1200,630 \
  --virtual-time-budget=8000 \
  --screenshot=/work/assets/og-image.png \
  "http://$NGINX/src/og-image.html" >/dev/null 2>&1
echo "  wrote assets/og-image.png ($(wc -c < assets/og-image.png) bytes)"

# ── 3) Generate sitemap.xml ─────────────────────────────────────────────────
# Same route list as the pre-render loop, mapped to absolute URLs. robots.txt
# (static, alongside this script) points crawlers here.
echo "[3/3] writing sitemap.xml"
{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n'
  printf '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
  for route in $routes; do
    printf '  <url><loc>https://voidwall.io%s</loc></url>\n' "$route"
  done
  printf '</urlset>\n'
} > sitemap.xml
echo "  wrote sitemap.xml ($(wc -c < sitemap.xml) bytes)"
