#!/bin/sh
# Build pipeline:
#   1) Transpile src/*.jsx into assets/app.js (Babel in node:lts-alpine).
#   2) Spin up nginx on a private docker network and pre-render the page
#      with headless Chromium, writing the rendered DOM to index.html.
#      The bundle uses ReactDOM.hydrateRoot, so React reuses the snapshot
#      for interactivity without a flash-replace.
set -eu
cd "$(dirname "$0")"
mkdir -p assets

# ── 1) Transpile JSX ────────────────────────────────────────────────────────
echo "[1/2] transpiling src/*.jsx → assets/app.js"
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/src":/src:ro \
  -v "$PWD/assets":/out \
  node:lts-alpine sh -c '
    set -eu
    cd /tmp
    npm init -y >/dev/null 2>&1
    npm install --silent --no-fund --no-audit \
      @babel/cli@7 @babel/core@7 @babel/preset-react@7 >/dev/null
    : > bundle.jsx
    for f in /src/*.jsx; do
      printf "\n/* === %s === */\n" "$(basename "$f")" >> bundle.jsx
      cat "$f" >> bundle.jsx
    done
    npx --no babel bundle.jsx --presets=@babel/preset-react --out-file /out/app.js
    echo "  built assets/app.js ($(wc -c < /out/app.js) bytes)"
  '

# ── 2) Pre-render via headless Chromium ─────────────────────────────────────
echo "[2/2] pre-rendering with headless Chromium"

# Use the unrendered template while Chromium loads the page.
cp src/index.template.html index.html

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
docker run --rm --network "$NET" \
  --user "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work zenika/alpine-chrome \
  --no-sandbox --headless --disable-gpu \
  --virtual-time-budget=8000 \
  --dump-dom "http://$NGINX/index.html" > index.html.tmp

# --dump-dom emits the <html> element only; re-prepend the doctype.
{ printf '<!DOCTYPE html>\n'; cat index.html.tmp; } > index.html
rm index.html.tmp

echo "  wrote index.html ($(wc -c < index.html) bytes)"
