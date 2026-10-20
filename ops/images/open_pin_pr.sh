#!/usr/bin/env bash
# Called only after the workflow verifies a successful, public main publication.
set -euo pipefail
[[ ${SOURCE:-} =~ ^[0-9a-f]{40}$ ]]
: "${MANIFEST:?verified publication manifest required}"
branch=automation/image-pins
values=charts/aks-durable-agents/values.yaml
export GIT_AUTHOR_NAME='github-actions[bot]'
export GIT_AUTHOR_EMAIL='41898282+github-actions[bot]@users.noreply.github.com'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

# Reuse normal history: no force update, no growing set of superseded PRs.
remote=$(git ls-remote --heads origin "refs/heads/$branch")
if [[ -n "$remote" ]]; then
  git fetch origin "refs/heads/$branch"
  base=$(git merge-base origin/main FETCH_HEAD)
  changed=$(git diff --name-only "$base" FETCH_HEAD)
  if [[ -n "$changed" && "$changed" != "$values" ]]; then
    echo 'Refusing automation branch with unrelated changes' >&2
    exit 1
  fi
  git switch --detach FETCH_HEAD
  # Conflicts require human review. Never reset or silently choose image pins.
  git merge --no-edit origin/main
else
  git switch --detach origin/main
fi
python3 ops/images/update_pins.py update --manifest "$MANIFEST" --values "$values"
changed=$(git diff --name-only origin/main)
if [[ -z "$changed" ]]; then exit 0; fi
if [[ "$changed" != "$values" ]]; then
  echo 'Refusing a non-image-only PR' >&2
  exit 1
fi
if ! git diff --quiet; then
  git add "$values"
  git commit -m 'chore: pin published reference images'
fi
# Credential helper lives only for this command, not in checkout configuration.
git -c 'credential.helper=!gh auth git-credential' push origin "HEAD:refs/heads/$branch"
body="Pin the host and reference fixture images published from $SOURCE. Both digests are anonymously pullable, carry SBOMs and have verified GitHub OIDC signatures. This replaces the previously proposed pins. Production host credentials and required operator inputs are unchanged. Approve workflows to run, then review the Helm checks before merging."
number=$(gh pr list --repo Azure/aks-durable-agents --state open --head "$branch" --json number --jq '.[0].number // empty')
if [[ -n "$number" ]]; then
  gh pr edit "$number" --repo Azure/aks-durable-agents --body "$body"
else
  gh pr create --repo Azure/aks-durable-agents --head "$branch" --base main --title 'Pin signed reference images' --body "$body"
fi
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "Updated image pin PR for $SOURCE; approve its workflows and review before merging." >> "$GITHUB_STEP_SUMMARY"
fi
