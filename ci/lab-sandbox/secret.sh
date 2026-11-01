#!/bin/bash
# Put a value in the lab's secret store (ClusterSecretStore app-secrets: Secrets in namespace
# containerizer-secrets), as the appliance does with cz_store_put.
#
#   secret.sh <remote-key> '{"username":"app","password":"s3cret"}'   # a JSON object: one key per property
#   secret.sh <remote-key> 's3cret'                                    # anything else: key "value"
#   secret.sh <remote-key> @file.json                                  # the JSON or literal from a file
#   secret.sh <remote-key> -                                           # ... or from stdin (keeps it out of ps)
#
# Remote keys are <namespace>--<name> (docs/external-secrets.md); the generated flux/tenant.yaml of each
# app grants its namespace the keys it uses. Values never appear on a command line passed to kubectl.
# Property names that YAML 1.1 reads as booleans (y, n, yes, no, on, off) do not survive cz_store_put.
. "$(dirname "$0")/lib.sh"
[ $# -eq 2 ] || { sed -n '2,12p' "$0" >&2; exit 2; }
key=$1 val=$2
case "$val" in -) val=$(cat);; @*) val=$(cat "${val:1}");; esac
tmp=$(mktemp -d)
trap 'find "$tmp" -type f -delete; rmdir "$tmp"' EXIT
args=()
if printf %s "$val" | jq -e 'type == "object"' >/dev/null 2>&1; then
  while IFS= read -r p; do
    printf %s "$val" | jq -j --arg p "$p" '.[$p] | if type == "string" then . else tojson end' > "$tmp/$p"
    args+=("$p=@$tmp/$p")
  done < <(printf %s "$val" | jq -r 'keys[]')
else
  printf %s "$val" > "$tmp/value"
  args+=("value=@$tmp/value")
fi
cz_store_put "$key" --manager lab-sandbox "${args[@]}"
names=("${args[@]%%=*}")
echo "stored $key (${names[*]}) in $CZ_STORE_NS"
