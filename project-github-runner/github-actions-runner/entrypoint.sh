#!/bin/bash
set -euo pipefail

RUNNER_ROOT="/actions-runner"
GITHUB_API_URL="${GITHUB_API_URL:-https://api.github.com}"

cleanup() {
  if [[ -x "${RUNNER_ROOT}/config.sh" && -n "${RUNNER_TOKEN:-}" ]]; then
    ./config.sh remove --unattended --token "${RUNNER_TOKEN}" || true
  fi
}

trap cleanup EXIT

b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

generate_app_jwt() {
  local key_path=$1
  local now
  now=$(date +%s)
  local iat=$((now - 60))
  local exp=$((now + 540))
  local header payload unsigned signature
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  payload=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' "${iat}" "${exp}" "${APP_ID}" | b64url)
  unsigned="${header}.${payload}"
  signature=$(printf '%s' "${unsigned}" | openssl dgst -sha256 -sign "${key_path}" | b64url)
  printf '%s.%s\n' "${unsigned}" "${signature}"
}

normalize_private_key() {
  printf '%s' "${APP_PRIVATE_KEY}" | sed 's/\\n/\n/g' | sed 's/\r$//'
}

request_runner_token_with_github_app() {
  local key_file jwt installation_token

  key_file=$(mktemp)
  normalize_private_key >"${key_file}"
  jwt=$(generate_app_jwt "${key_file}")
  rm -f "${key_file}"

  installation_token=$(curl -sS -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: azure-container-apps-runner" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Authorization: Bearer ${jwt}" \
    "${GITHUB_API_URL}/app/installations/${APP_INSTALLATION_ID}/access_tokens" | jq -r '.token')

  RUNNER_TOKEN=$(curl -sS -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: azure-container-apps-runner" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Authorization: Bearer ${installation_token}" \
    "${REGISTRATION_TOKEN_API_URL}" | jq -r '.token')
}

request_runner_token_with_pat() {
  RUNNER_TOKEN=$(curl -sS -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: azure-container-apps-runner" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Authorization: token ${GITHUB_PAT}" \
    "${REGISTRATION_TOKEN_API_URL}" | jq -r '.token')
}

if [[ -z "${GH_URL:-}" ]]; then
  echo "GH_URL environment variable is required." >&2
  exit 1
fi

if [[ -z "${RUNNER_TOKEN:-}" ]]; then
  if [[ -z "${REGISTRATION_TOKEN_API_URL:-}" ]]; then
    echo "REGISTRATION_TOKEN_API_URL must be provided." >&2
    exit 1
  fi

  if [[ -n "${APP_PRIVATE_KEY:-}" ]]; then
    if [[ -z "${APP_ID:-}" || -z "${APP_INSTALLATION_ID:-}" ]]; then
      echo "APP_ID and APP_INSTALLATION_ID must be provided when APP_PRIVATE_KEY is set." >&2
      exit 1
    fi
    request_runner_token_with_github_app
  else
    if [[ -z "${GITHUB_PAT:-}" ]]; then
      echo "Either RUNNER_TOKEN or a GitHub PAT (GITHUB_PAT) must be supplied when APP_PRIVATE_KEY is not set." >&2
      exit 1
    fi
    request_runner_token_with_pat
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

./config.sh "${CONFIG_ARGS[@]}"
exec ./run.sh --once