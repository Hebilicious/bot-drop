#!/usr/bin/env bash
# Upload a file to bot-drop and print its viewUrl (or the full JSON with --json).
#
# Usage: drop.sh [--json] <bot> <file> [name]
# Env:   BOT_DROP_URL             e.g. https://bot-drop.<account>.workers.dev
#        CF_ACCESS_CLIENT_ID      Cloudflare Access service token client id
#        CF_ACCESS_CLIENT_SECRET  Cloudflare Access service token secret
# If BOT_DROP_URL is unset, the script sources $BOT_DROP_ENV, or else a file
# called "env" next to the (symlink-resolved) script, if one exists.
set -euo pipefail

json=0
if [[ ${1:-} == --json ]]; then json=1; shift; fi
if [[ $# -lt 2 ]]; then
  echo "usage: $(basename "$0") [--json] <bot> <file> [name]" >&2
  exit 2
fi
bot=$1
file=$2
name=${3:-$(basename "$file")}

if [[ -z ${BOT_DROP_URL:-} || -z ${CF_ACCESS_CLIENT_ID:-} ]]; then
  envfile=${BOT_DROP_ENV:-$(dirname "$(readlink -f "$0")")/env}
  # shellcheck disable=SC1090
  [[ -r $envfile ]] && source "$envfile"
fi

: "${BOT_DROP_URL:?set BOT_DROP_URL (or provide an env file)}"
[[ -f $file ]] || { echo "no such file: $file" >&2; exit 2; }

auth=()
if [[ -n ${CF_ACCESS_CLIENT_ID:-} || -n ${CF_ACCESS_CLIENT_SECRET:-} ]]; then
  : "${CF_ACCESS_CLIENT_ID:?set CF_ACCESS_CLIENT_ID}"
  : "${CF_ACCESS_CLIENT_SECRET:?set CF_ACCESS_CLIENT_SECRET}"
  auth=(-H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}")
fi

urlencode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

out=$(mktemp)
trap 'rm -f "$out"' EXIT
code=$(curl -sS -o "$out" -w '%{http_code}' -X POST \
  "${auth[@]}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${file}" \
  "${BOT_DROP_URL%/}/api/upload?bot=$(urlencode "$bot")&name=$(urlencode "$name")") || { echo "upload failed: network error" >&2; exit 1; }
resp=$(cat "$out")
if [[ $code != 201 ]]; then
  if [[ $code == 302 || $code == 401 || $code == 403 ]] && ! grep -q '"error"' "$out"; then
    echo "upload failed: HTTP $code from Cloudflare Access (missing or rejected service token?)" >&2
  else
    echo "upload failed: HTTP $code ${resp:0:500}" >&2
  fi
  exit 1
fi

if [[ $json == 1 ]]; then
  printf '%s\n' "$resp"
else
  printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["viewUrl"])'
fi
