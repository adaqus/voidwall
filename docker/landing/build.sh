#!/bin/sh
# Transpiles src/*.jsx into a single assets/app.js using Babel in
# node:lts-alpine. Re-run whenever the JSX sources change.
set -eu
cd "$(dirname "$0")"
mkdir -p assets

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
    echo "Built assets/app.js ($(wc -c < /out/app.js) bytes)"
  '
