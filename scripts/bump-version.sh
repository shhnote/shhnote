#!/usr/bin/env bash
# Bump the project version everywhere it is written, commit, and tag.
#
#   scripts/bump-version.sh patch|minor|major     next stable version
#   scripts/bump-version.sh rc                    next pre-release of the next minor
#                                                 (0.3.0 -> 0.4.0-rc.1, 0.4.0-rc.1 -> 0.4.0-rc.2)
#   scripts/bump-version.sh release               drop the pre-release suffix (0.4.0-rc.2 -> 0.4.0)
#   scripts/bump-version.sh 1.2.3                 set an exact version
#   scripts/bump-version.sh <mode> --yes          skip the confirmation prompt
#
# Preconditions: on main, clean working tree, not behind origin/main, and the versions in
# Cargo.toml, client/package.json and client/package-lock.json agree (the server and the
# client package are versioned in lockstep). Touches those files, Cargo.lock and the first
# "## <version> — unreleased" heading in CHANGELOG.md (stable bumps only), then commits as
# "release: <version>" and creates the annotated tag v<version>. Push with:
#   git push origin main --follow-tags
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-}"; yes="${2:-}"
[ -n "$mode" ] || { sed -n '2,16p' "$0"; exit 2; }

# ---- preconditions -------------------------------------------------------------------
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || { echo "on '$branch'; releases are cut from main" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean" >&2; exit 1; }
git fetch --quiet origin main
behind=$(git rev-list --count HEAD..origin/main)
[ "$behind" = 0 ] || { echo "main is $behind commit(s) behind origin/main; pull first" >&2; exit 1; }

cargo_v=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
npm_v=$(node -p "require('./client/package.json').version")
lock_v=$(node -p "require('./client/package-lock.json').version")
if [ "$cargo_v" != "$npm_v" ] || [ "$cargo_v" != "$lock_v" ]; then
  echo "versions disagree: Cargo.toml=$cargo_v package.json=$npm_v package-lock.json=$lock_v" >&2
  exit 1
fi
current="$cargo_v"
git rev-parse -q --verify "refs/tags/v$current" >/dev/null && tagged="(tagged)" || tagged="(not tagged)"

# ---- next version --------------------------------------------------------------------
next=$(python3 - "$current" "$mode" <<'PY'
import re, sys
cur, mode = sys.argv[1], sys.argv[2]
m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", cur)
if not m:
    sys.exit(f"cannot parse current version {cur!r}")
major, minor, patch, rc = (int(x) if x else None for x in m.groups())
if re.fullmatch(r"\d+\.\d+\.\d+(-rc\.\d+)?", mode):
    print(mode)
elif mode == "patch":
    print(f"{major}.{minor}.{patch + 1}" if rc is None else f"{major}.{minor}.{patch}")
elif mode == "minor":
    print(f"{major}.{minor + 1}.0" if rc is None else f"{major}.{minor}.{patch}")
elif mode == "major":
    print(f"{major + 1}.0.0")
elif mode == "rc":
    print(f"{major}.{minor}.{patch}-rc.{rc + 1}" if rc is not None else f"{major}.{minor + 1}.0-rc.1")
elif mode == "release":
    if rc is None:
        sys.exit(f"{cur} is not a pre-release")
    print(f"{major}.{minor}.{patch}")
else:
    sys.exit(f"unknown mode {mode!r}")
PY
)
git rev-parse -q --verify "refs/tags/v$next" >/dev/null && { echo "tag v$next already exists" >&2; exit 1; }

echo "branch:  main (up to date with origin)"
echo "current: $current $tagged"
echo "next:    $next"
if [ "$yes" != "--yes" ]; then
  read -r -p "Bump to $next, commit and tag v$next? [y/N] " answer
  case "$answer" in y|Y|yes) ;; *) echo "aborted"; exit 1;; esac
fi

# ---- write ---------------------------------------------------------------------------
python3 - "$next" <<'PY'
import json, re, sys, datetime
new = sys.argv[1]

s = open("Cargo.toml").read()
s, n = re.subn(r'^version = "[^"]+"', f'version = "{new}"', s, count=1, flags=re.M)
assert n == 1, "Cargo.toml: workspace version not found"
open("Cargo.toml", "w").write(s)

for path in ("client/package.json", "client/package-lock.json"):
    data = json.load(open(path))
    data["version"] = new
    if "packages" in data and "" in data["packages"]:
        data["packages"][""]["version"] = new
    open(path, "w").write(json.dumps(data, indent=2) + "\n")

if "-rc." not in new:
    today = datetime.date.today().isoformat()
    s = open("CHANGELOG.md").read()
    s2, n = re.subn(r"^## [^\n]* — unreleased$", f"## {new} — {today}", s, count=1, flags=re.M)
    if n:
        open("CHANGELOG.md", "w").write(s2)
    else:
        print("CHANGELOG.md: no '— unreleased' heading; add the release notes by hand", file=sys.stderr)
PY

# Cargo.lock records the workspace crates' version; a metadata-only command refreshes it.
cargo metadata --format-version 1 --offline >/dev/null

git add Cargo.toml Cargo.lock client/package.json client/package-lock.json CHANGELOG.md
git --no-pager diff --cached --stat
git commit --quiet -m "release: $next"
git tag -a "v$next" -m "v$next"
echo
echo "committed and tagged v$next. Push with:"
echo "  git push origin main --follow-tags"
