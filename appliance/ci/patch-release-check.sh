#!/bin/bash
# A patch release (vX.Y.Z, Z > 0) is installed on appliances as an app update: only the application changes,
# the OS image they run (vX.Y.0 or a later patch) stays. So since vX.Y.0 nothing that goes into the OS image may
# change: appliance/ (the Dockerfile, rootfs, Elemental, the Python packages' lock) and monitoring/. Such changes
# need a minor (or major) release.
#   appliance/ci/patch-release-check.sh vX.Y.Z      (in a checkout with the tags)
set -euo pipefail
v="$1"
[[ "$v" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo "the version is vX.Y.Z, got $v" >&2; exit 1; }
[ "${BASH_REMATCH[3]}" = 0 ] && { echo "$v: a minor or major release, the OS may change"; exit 0; }
base="v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.0"
git rev-parse -q --verify "refs/tags/$base" >/dev/null || { echo "$v is a patch release, but there is no $base to patch" >&2; exit 1; }
paths=(appliance/ monitoring/ ':!appliance/ci/' ':!appliance/app/')
if ! git diff --quiet "$base" HEAD -- "${paths[@]}"; then
  echo "$v is a patch release (installed as an app update, without an OS upgrade), but the OS image changed since $base:" >&2
  git diff --stat "$base" HEAD -- "${paths[@]}" >&2
  echo "Release these changes as a minor version instead." >&2
  exit 1
fi
echo "$v: no OS change since $base, appliances of the series install it as an app update"
