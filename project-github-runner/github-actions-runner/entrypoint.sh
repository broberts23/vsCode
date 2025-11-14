#!/bin/bash
set -euo pipefail

RUNNER_ROOT="/actions-runner"

cleanup() {
  if [[ -x "${RUNNER_ROOT}/config.sh" && -n "${RUNNER_TOKEN:-}" ]]; then
    ./config.sh remove --unattended --token "${RUNNER_TOKEN}" || true
  fi
}

trap cleanup EXIT

if [[ -z "${GH_URL:-}" ]]; then
  echo "GH_URL environment variable is required." >&2
  exit 1
fi

if [[ -z "${RUNNER_TOKEN:-}" ]]; then
  if [[ -z "${GITHUB_PAT:-}" || -z "${REGISTRATION_TOKEN_API_URL:-}" ]]; then
    echo "Either RUNNER_TOKEN or both GITHUB_PAT and REGISTRATION_TOKEN_API_URL must be supplied." >&2
    exit 1
  fi

  echo "Requesting registration token from GitHub..."
  RUNNER_TOKEN=$(curl -fsSL -X POST "${REGISTRATION_TOKEN_API_URL}" \
    -H "Authorization: token ${GITHUB_PAT}" \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: azure-container-apps-runner" \
    | jq -r '.token')

  if [[ -z "${RUNNER_TOKEN}" || "${RUNNER_TOKEN}" == "null" ]]; then
    echo "Failed to retrieve runner registration token." >&2
    exit 1
  fi
fi

RUNNER_NAME=${RUNNER_NAME:-$(hostname)}
if [[ -f ".runner" ]]; then
  rm -f .runner
fi

CONFIG_ARGS=(
  --unattended
  --url "${GH_URL}"
  --token "${RUNNER_TOKEN}"
  --name "${RUNNER_NAME}"
)

if [[ -n "${RUNNER_LABELS:-}" ]]; then
  CONFIG_ARGS+=(--labels "${RUNNER_LABELS}")
fi

echo "Configuring runner ${RUNNER_NAME} for ${GH_URL}"
./config.sh "${CONFIG_ARGS[@]}"

echo "Starting runner..."
exec ./run.sh --once