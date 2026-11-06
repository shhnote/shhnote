#!/usr/bin/env bash
# Cut a release in one command, through a pull request, with signed commit and tag.
#
#   scripts/release.sh patch|minor|major     next stable version
#   scripts/release.sh rc                    next pre-release of the next minor
#                                                 (0.3.0 -> 0.4.0-rc.1, 0.4.0-rc.1 -> 0.4.0-rc.2)
#   scripts/release.sh release               drop the pre-release suffix (0.4.0-rc.2 -> 0.4.0)
#   scripts/release.sh 1.2.3                 set an exact version
#   scripts/release.sh tag                   resume: tag the version main already carries
#                                                 (after a merged release PR, or a hand bump)
#   options: --yes (no prompt)  --no-wait (open the PR and stop; finish later with `tag`)
#
# What it does, from an up-to-date main:
#   1. computes the next version and asks once;
#   2. creates release/<version>, updates Cargo.toml, Cargo.lock, client/package.json,
#      client/package-lock.json and dates the "— unreleased" headings in CHANGELOG.md and
#      client/CHANGELOG.md (stable versions only); signed commit "release: <version>";
#   3. pushes the branch, opens the PR with gh, enables auto-merge (rebase);
#   4. waits for the checks and the merge;
#   5. pulls main, signs tag v<version> on the merged commit, pushes the tag, deletes the branch.
# main is never pushed directly, so the branch ruleset is satisfied. Needs `gh` logged in.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-}"; shift || true
yes=""; nowait=""
for arg in "$@"; do
  case "$arg" in
    --yes) yes=1 ;;
    --no-wait) nowait=1 ;;
    *) echo "unknown option $arg" >&2; exit 2 ;;
  esac
done
[ -n "$mode" ] || { sed -n '2,22p' "$0"; exit 2; }
command -v gh >/dev/null || { echo "gh (GitHub CLI) is required and must be logged in" >&2; exit 1; }

# ---- preconditions -------------------------------------------------------------------
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || { echo "on '$branch'; run this from main" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean" >&2; exit 1; }
git fetch --quiet origin main
behind=$(git rev-list --count HEAD..origin/main)
[ "$behind" = 0 ] || { echo "main is $behind commit(s) behind origin/main; pull first" >&2; exit 1; }
ahead=$(git rev-list --count origin/main..HEAD)
[ "$ahead" = 0 ] || { echo "main has $ahead local commit(s) not on origin; main is PR-only" >&2; exit 1; }

cargo_v=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
npm_v=$(node -p "require('./client/package.json').version")
lock_v=$(node -p "require('./client/package-lock.json').version")
if [ "$cargo_v" != "$npm_v" ] || [ "$cargo_v" != "$lock_v" ]; then
  echo "versions disagree: Cargo.toml=$cargo_v package.json=$npm_v package-lock.json=$lock_v" >&2
  exit 1
fi
current="$cargo_v"
git rev-parse -q --verify "refs/tags/v$current" >/dev/null && tagged="(tagged)" || tagged="(not tagged)"

# ---- resume: tag what main already carries -------------------------------------------
tag_current() {
  git rev-parse -q --verify "refs/tags/v$current" >/dev/null && { echo "tag v$current already exists" >&2; exit 1; }
  git verify-commit HEAD >/dev/null 2>&1 || { echo "HEAD is not signed; releases are tagged on signed commits" >&2; exit 1; }
  git tag -s "v$current" -m "v$current"
  git verify-tag "v$current" >/dev/null 2>&1 || { echo "tag is not signed; check user.signingkey here" >&2; exit 1; }
  git push origin "v$current"
  echo "tagged and pushed v$current at $(git rev-parse --short HEAD)"
}

if [ "$mode" = "tag" ]; then
  echo "current: $current $tagged"
  if [ -z "$yes" ]; then
    read -r -p "Tag v$current on main at $(git rev-parse --short HEAD) and push the tag? [y/N] " answer
    case "$answer" in y|Y|yes) ;; *) echo "aborted"; exit 1;; esac
  fi
  tag_current
  exit 0
fi

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
if [ "$tagged" = "(not tagged)" ]; then
  echo "note: $current has no tag; 'scripts/release.sh tag' would tag it as is" >&2
fi

echo "current: $current $tagged"
echo "next:    $next"
if [ -z "$yes" ]; then
  read -r -p "Release $next (branch, PR, auto-merge, tag)? [y/N] " answer
  case "$answer" in y|Y|yes) ;; *) echo "aborted"; exit 1;; esac
fi

# ---- branch + files ------------------------------------------------------------------
rb="release/$next"
git switch -c "$rb" --quiet

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
    for path in ("CHANGELOG.md", "client/CHANGELOG.md"):
        s = open(path).read()
        s2, n = re.subn(r"^## [^\n]* — unreleased$", f"## {new} — {today}", s, count=1, flags=re.M)
        if n:
            open(path, "w").write(s2)
        else:
            print(f"{path}: no '— unreleased' heading; add the release notes by hand", file=sys.stderr)
PY

cargo metadata --format-version 1 --offline >/dev/null   # refreshes Cargo.lock
git add Cargo.toml Cargo.lock client/package.json client/package-lock.json CHANGELOG.md client/CHANGELOG.md
git --no-pager diff --cached --stat
git commit --quiet -S -m "release: $next"
git verify-commit HEAD >/dev/null 2>&1 || { echo "commit is not signed; check user.signingkey here" >&2; exit 1; }

# ---- PR ------------------------------------------------------------------------------
git push --quiet -u origin "$rb"
pr_url=$(gh pr create --base main --head "$rb" --title "release: $next" \
  --body "Version bump to $next. Tag v$next is created on main after this merges.")
echo "PR: $pr_url"
gh pr merge "$rb" --auto --rebase --delete-branch >/dev/null
echo "auto-merge enabled (rebase); waiting for checks and merge"

if [ -n "$nowait" ]; then
  echo "left the PR to merge on its own. When it has merged: git switch main && git pull && scripts/release.sh tag"
  exit 0
fi

# ---- wait, then tag on main ----------------------------------------------------------
gh pr checks "$rb" --watch --fail-fast >/dev/null || { echo "checks failed; fix on $rb and merge by hand, then run 'tag'" >&2; exit 1; }
for _ in $(seq 1 60); do
  state=$(gh pr view "$rb" --json state --jq .state)
  [ "$state" = "MERGED" ] && break
  sleep 5
done
[ "$state" = "MERGED" ] || { echo "PR not merged yet (state $state); when it is: git switch main && git pull && scripts/release.sh tag" >&2; exit 1; }

git switch main --quiet
git pull --ff-only --quiet
git branch -D "$rb" --quiet 2>/dev/null || true
current="$next"
tag_current
