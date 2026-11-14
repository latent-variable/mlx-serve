#!/usr/bin/env bash
# The dependency gate, run before every merge: every committed lockfile checked
# against the OSV vulnerability database (npm, Python, Rust, Go, Swift and more),
# plus the OpenSSF malicious-package list. Under a second.
# Exit 0 clean, non-zero on a known vulnerability or on a scan that could not run.
# A finding is fixed first; one that cannot reach us goes in osv-scanner.toml with
# its reason and an expiry. A repo with no lockfile at all fails too: commit one
# (npm install writes it; uv lock for Python), because an unlocked project is
# invisible to the scan. The one exception is a repo with no dependency manifest
# at all (no package.json, requirements*.txt, pyproject.toml, Pipfile, Cargo.toml,
# go.mod, Gemfile, composer.json, setup.py): a repo of scripts and prose has
# nothing to lock, so it passes. A repo whose lockfile lists zero packages is clean:
# osv-scanner exits 128 "No package sources found" there, so that one outcome is
# accepted, but only when the scanner reported reading a lockfile ("Scanned <file>
# and found 0 packages").
#
# The lockfiles come from git (tracked, plus new files git does not ignore), never
# from osv-scanner's own recursive walk. The walk applies every .gitignore from the
# filesystem root down, across repo boundaries, so a repo nested in a folder whose
# .gitignore lists it (the Adjutant workspace) scanned nothing at all. Asking git
# also keeps build output and node_modules out of the scan.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v osv-scanner >/dev/null || { echo "osv-scanner not installed: brew install osv-scanner" >&2; exit 1; }

# Lockfile and manifest names osv-scanner 2.x reads. A name missing here is a
# lockfile the gate never sees, so add it the day a repo needs it.
lock_re='(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|deno\.lock|requirements[^/]*\.txt|Pipfile\.lock|poetry\.lock|pdm\.lock|uv\.lock|pylock\.toml|Cargo\.lock|go\.mod|Gemfile\.lock|gems\.locked|composer\.lock|Package\.resolved|Podfile\.lock|pubspec\.lock|mix\.lock|conan\.lock|renv\.lock|gradle\.lockfile|buildscript-gradle\.lockfile|pom\.xml|packages\.lock\.json|packages\.config|cabal\.project\.freeze|stack\.yaml\.lock)$'
# Two calls: --recurse-submodules (a submodule's dependencies ship with this repo)
# cannot be combined with --others. A submodule that is not checked out lists nothing.
# NUL-separated (-z), so git never quotes a path: a quoted one would not match the
# names below and its lockfile would drop out of the scan in silence. The list goes
# through a temp file because $(...) cannot hold a NUL.
listing="$(mktemp)"; trap 'trash "$listing" 2>/dev/null || true' EXIT
{ git ls-files -z --cached --recurse-submodules && git ls-files -z --others --exclude-standard; } >"$listing" \
  || { echo "audit-deps: could not list files from git; a scan we could not take is never a pass" >&2; exit 1; }
manifest_re='(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|Cargo\.toml|go\.mod|Gemfile|composer\.json|setup\.py)$'
args=(); manifest=0
while IFS= read -r -d '' f; do
  [[ -f "$f" ]] || continue   # a tracked file deleted in the tree
  [[ "$f" =~ $lock_re ]] && args+=(-L "./$f")
  [[ "$f" =~ $manifest_re ]] && manifest=1
done <"$listing"
if (( ${#args[@]} == 0 )); then
  if (( ! manifest )); then
    echo "audit-deps: no dependency manifest and no lockfile, nothing to scan: clean"
    exit 0
  fi
  echo "audit-deps: dependencies declared but no lockfile; commit one so the scan can see them" >&2
  exit 1
fi

rc=0
out="$(osv-scanner scan source --config osv-scanner.toml "${args[@]}" 2>&1)" || rc=$?
printf '%s\n' "$out"
if [ "$rc" -eq 128 ] && grep -q 'No package sources found' <<<"$out" \
  && grep -qE '^Scanned .* and found 0 packages' <<<"$out"; then
  echo "audit-deps: lockfile present with 0 packages, nothing to scan: clean"
  exit 0
fi
exit "$rc"
