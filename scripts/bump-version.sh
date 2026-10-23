#!/usr/bin/env bash
# Sets the workspace version (the one `version =` line in Cargo.toml) and
# refreshes Cargo.lock. Every crate inherits it.
#
#   scripts/bump-version.sh patch|minor|major      bump and write
#   scripts/bump-version.sh 1.4.2                  set an exact version
#   scripts/bump-version.sh --print minor          print the next version only
set -euo pipefail
cd "$(dirname "$0")/.."

print_only=false
if [ "${1:-}" = "--print" ]; then
  print_only=true
  shift
fi

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
core=${current%%-*}
IFS=. read -r major minor patch <<<"$core"

case "${1:-patch}" in
  major) next="$((major + 1)).0.0" ;;
  minor) next="$major.$((minor + 1)).0" ;;
  patch) next="$major.$minor.$((patch + 1))" ;;
  [0-9]*.[0-9]*.[0-9]*) next="$1" ;;
  *) echo "usage: $0 [--print] patch|minor|major|X.Y.Z" >&2; exit 2 ;;
esac

if $print_only; then
  echo "$next"
  exit 0
fi

# Replace only the first `version = "..."` line: the [workspace.package] one.
perl -0pi -e "s/^version = \"\\Q$current\\E\"/version = \"$next\"/m" Cargo.toml
cargo update --workspace --quiet
echo "$current -> $next"
