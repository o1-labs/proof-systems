#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# gh-auto-rebase.sh
#
# Rebases PR branches (with auto-merge enabled and behind base) using:
# - git clone via SSH
# - git rebase + push --force-with-lease
#
# Usage:
#   ./gh-auto-rebase.sh [--dry-run] [--interactive] [<owner/repo>]
# -----------------------------------------------------------------------------

DRY_RUN=0
INTERACTIVE=0
REPO=""

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --interactive) INTERACTIVE=1 ;;
    *) REPO="$arg" ;;
  esac
done

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
fi

echo "Checking repository: $REPO"
[[ "$DRY_RUN" == 1 ]] && echo "(dry-run mode enabled)"
[[ "$INTERACTIVE" == 1 ]] && echo "(interactive mode enabled)"

# Fetch PRs that need rebasing
prs=$(gh pr list --repo "$REPO" --state open \
  --json number,title,headRefName,baseRefName,mergeable,mergeStateStatus,autoMergeRequest \
  | jq -c '[.[] | select(.autoMergeRequest != null and .mergeStateStatus == "BEHIND" and .mergeable == "MERGEABLE")]')

count=$(echo "$prs" | jq 'length')
echo "Found $count outdated auto-merge PR(s)"

if [[ "$count" -eq 0 ]]; then
  echo "Nothing to do."
  exit 0
fi

mapfile -t pr_array < <(echo "$prs" | jq -c '.[]')

for pr in "${pr_array[@]}"; do
  number=$(echo "$pr" | jq -r '.number')
  head=$(echo "$pr" | jq -r '.headRefName')
  base=$(echo "$pr" | jq -r '.baseRefName')
  title=$(echo "$pr" | jq -r '.title')

  echo
  echo "PR #$number: $title"
  echo "Branch: $head → $base"

  if [[ "$DRY_RUN" == 1 ]]; then
    echo "[dry-run] Would rebase $head onto $base"
    continue
  fi

  if [[ "$INTERACTIVE" == 1 ]]; then
    read -r -p "Trigger rebase for PR #$number? [y/N] " reply
    if [[ ! "$reply" =~ ^[Yy]$ ]]; then
      echo "Skipped PR #$number"
      continue
    fi
  fi

  # Perform actual rebase in a temporary clone
  tmpdir=$(mktemp -d)
  pushd "$tmpdir" > /dev/null

  echo "Cloning repository via SSH..."
  git clone "git@github.com:$REPO.git" repo
  cd repo

  git config user.name "$(git config --global user.name || echo auto-rebase)"
  git config user.email "$(git config --global user.email || echo noreply@example.com)"

  echo "Fetching base and head branches..."
  git fetch origin "$base" "$head"

  echo "Checking out head branch $head"
  git checkout "$head"

  echo "Rebasing onto origin/$base..."
  if git rebase "origin/$base"; then
    echo "Pushing rebased branch..."
    git push --force-with-lease origin "$head"
    echo "✅ Rebased and pushed PR #$number"
  else
    echo "❌ Rebase failed for PR #$number. Aborting."
    git rebase --abort || true
  fi

  popd > /dev/null
  rm -rf "$tmpdir"
done
