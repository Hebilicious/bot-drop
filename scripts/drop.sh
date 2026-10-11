#!/usr/bin/env bash
# Upload a file to bot-drop and print the JSON response (key, url, viewUrl).
#
# Usage: scripts/drop.sh <bot> <file> [name]
# Env:   BOT_DROP_URL           e.g. https://bot-drop.<account>.workers.dev
#        CF_ACCESS_CLIENT_ID    Cloudflare Access service token client id
#        CF_ACCESS_CLIENT_SECRET  Cloudflare Access service token secret
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <bot> <file> [name]" >&2
  exit 2
fi
bot=$1
file=$2
name=${3:-$(basename "$file")}

: "${BOT_DROP_URL:?set BOT_DROP_URL}"
[[ -f $file ]] || { echo "no such file: $file" >&2; exit 2; }

auth=()
if [[ -n ${CF_ACCESS_CLIENT_ID:-} || -n ${CF_ACCESS_CLIENT_SECRET:-} ]]; then
  : "${CF_ACCESS_CLIENT_ID:?set CF_ACCESS_CLIENT_ID}"
  : "${CF_ACCESS_CLIENT_SECRET:?set CF_ACCESS_CLIENT_SECRET}"
  auth=(-H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}")
fi

urlencode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

curl --fail-with-body -sS -X POST \
  "${auth[@]}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${file}" \
  "${BOT_DROP_URL%/}/api/upload?bot=$(urlencode "$bot")&name=$(urlencode "$name")"
echo
