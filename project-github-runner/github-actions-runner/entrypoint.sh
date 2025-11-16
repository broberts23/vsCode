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
  # Handle secrets that preserve literal \n sequences or real newlines
  printf '%s' "${APP_PRIVATE_KEY}" | sed 's/\\n/\n/g' | sed 's/\r$//'
}

github_api_request() {
  local method=$1
  local url=$2
  local auth_header=$3
  local data=${4:-}
  local tmp status body

  tmp=$(mktemp)
  local curl_args=(-sS -o "${tmp}" -w '%{http_code}' -X "${method}" "${url}" \
    -H 'Accept: application/vnd.github+json' \
    -H 'User-Agent: azure-container-apps-runner' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    -H "${auth_header}")

  if [[ -n "${data}" ]]; then
    curl_args+=(-d "${data}")
  fi

  if ! status=$(curl "${curl_args[@]}"); then
    rm -f "${tmp}"
    echo "Failed to reach GitHub API (${method} ${url})." >&2
    return 1
  fi

  body=$(<"${tmp}")
  rm -f "${tmp}"

  status=$(printf '%s' "${status}" | tr -d '\r\n')
  if [[ ! "${status}" =~ ^[0-9]+$ ]]; then
    echo "GitHub API ${method} ${url} returned an invalid status: ${status}" >&2
    return 1
  fi

  if (( status < 200 || status >= 300 )); then
    echo "GitHub API ${method} ${url} failed (${status}): ${body}" >&2
    return 1
  fi

  printf '%s' "${body}"
}

request_runner_token_with_github_app() {
  if [[ -z "${APP_ID:-}" || -z "${APP_INSTALLATION_ID:-}" ]]; then
    echo "APP_ID and APP_INSTALLATION_ID must be provided when APP_PRIVATE_KEY is set." >&2
    exit 1
  fi

  local key_file
  key_file=$(mktemp)
  normalize_private_key >"${key_file}"

  local jwt
  if ! jwt=$(generate_app_jwt "${key_file}"); then
    rm -f "${key_file}"
    echo "Failed to generate GitHub App JWT." >&2
    exit 1
  fi

  rm -f "${key_file}"

  local installation_response
  if ! installation_response=$(github_api_request POST "${GITHUB_API_URL}/app/installations/${APP_INSTALLATION_ID}/access_tokens" "Authorization: Bearer ${jwt}"); then
    echo "Failed to exchange GitHub App JWT for an installation token." >&2
    exit 1
  fi

  local installation_token
  installation_token=$(printf '%s' "${installation_response}" | jq -r '.token')

  if [[ -z "${installation_token}" || "${installation_token}" == "null" ]]; then
    echo "Failed to exchange GitHub App JWT for an installation token: ${installation_response}" >&2
    exit 1
  fi

  local registration_response
  if ! registration_response=$(github_api_request POST "${REGISTRATION_TOKEN_API_URL}" "Authorization: Bearer ${installation_token}"); then
    echo "Failed to retrieve runner registration token using GitHub App authentication." >&2
    exit 1
  fi

  local token
  token=$(printf '%s' "${registration_response}" | jq -r '.token')

  if [[ -z "${token}" || "${token}" == "null" ]]; then
    echo "Failed to retrieve runner registration token using GitHub App authentication: ${registration_response}" >&2
    exit 1
  fi

  RUNNER_TOKEN="${token}"
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
    echo "Requesting registration token via GitHub App authentication..."
    request_runner_token_with_github_app
  else
    if [[ -z "${GITHUB_PAT:-}" ]]; then
      echo "Either RUNNER_TOKEN or a GitHub PAT (GITHUB_PAT) must be supplied when APP_PRIVATE_KEY is not set." >&2
      exit 1
    fi

    echo "Requesting registration token from GitHub using PAT..."
    if ! registration_response=$(github_api_request POST "${REGISTRATION_TOKEN_API_URL}" "Authorization: token ${GITHUB_PAT}"); then
      echo "Failed to retrieve runner registration token using PAT authentication." >&2
      exit 1
    fi

    RUNNER_TOKEN=$(printf '%s' "${registration_response}" | jq -r '.token')

    if [[ -z "${RUNNER_TOKEN}" || "${RUNNER_TOKEN}" == "null" ]]; then
      echo "Failed to retrieve runner registration token using PAT authentication." >&2
      exit 1
    fi
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