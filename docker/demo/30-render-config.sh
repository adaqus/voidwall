#!/bin/sh
set -eu
: "${PII_API_URL:?PII_API_URL must be set}"
envsubst '${PII_API_URL}' \
  < /usr/share/nginx/html/config.js.template \
  > /usr/share/nginx/html/config.js
