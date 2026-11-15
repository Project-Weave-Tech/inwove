#!/usr/bin/env bash
# The verdict for verify-setup-token-dead (Security, bus 17720).
# Usage: token-verdict.sh <http_code> <bodyfile>
# Railway refuses a token with HTTP 200, data null and errors[0].message "Not Authorized" (not 401),
# so a 401-only check could never show a dead key. Prints one line, never the body, headers,
# extensions or token. Exit 0 = DEAD, 1 = ALIVE or UNCLEAR.
set +x
set -u
code="${1:-}"
body="${2:-}"

if [ "$code" = "401" ]; then
  echo "OK: Railway refused the setup token (HTTP 401, Not Authorized)"
  exit 0
fi

valid=false
if [ -n "$body" ] && [ -f "$body" ] && jq -e 'type == "object"' "$body" >/dev/null 2>&1; then
  valid=true
fi

if [ "$code" = "200" ] && [ "$valid" = true ]; then
  if jq -e '(.data == null or .data.projects == null) and (.errors[0].message? == "Not Authorized")' "$body" >/dev/null 2>&1; then
    echo "OK: Railway refused the setup token (HTTP 200, Not Authorized)"
    exit 0
  fi
  if jq -e '.data != null and .data.projects != null' "$body" >/dev/null 2>&1; then
    n=$(jq -r '(.data.projects.edges // []) | length' "$body" 2>/dev/null || echo "?")
    case "$n" in ''|*[!0-9]*) n="?";; esac
    echo "KEY STILL ALIVE: Railway answered with ${n} project(s)"
    exit 1
  fi
fi

data_is_null=false
msg="(message withheld)"
if [ "$valid" = true ]; then
  if jq -e '.data == null' "$body" >/dev/null 2>&1; then data_is_null=true; fi
  raw=$(jq -r '.errors[0].message? // empty | tostring' "$body" 2>/dev/null | head -n1 | head -c 200)
  if printf '%s' "$raw" | grep -Eq "^[A-Za-z .,'-]{1,80}$"; then
    if [ "$(printf '%s' "$raw" | wc -l)" = "0" ]; then msg="$raw"; fi
  fi
fi
safe_code=$(printf '%s' "$code" | tr -cd '0-9' | head -c 3)
echo "UNCLEAR: HTTP ${safe_code:-none}, data_is_null=${data_is_null}, message: ${msg}"
exit 1
