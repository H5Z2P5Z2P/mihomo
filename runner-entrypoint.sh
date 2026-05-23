#!/usr/bin/env bash
set -euo pipefail

cd /home/runner/actions-runner

REPO_URL="${REPO_URL:-}"
RUNNER_NAME="${RUNNER_NAME:-mihomo-local}"
RUNNER_LABELS="${RUNNER_LABELS:-mihomo-local}"
RUNNER_WORKDIR="${RUNNER_WORKDIR:-_work}"

mkdir -p /home/runner/go/bin /home/runner/go/pkg/mod /home/runner/.cache/go-build
chown -R runner:runner /home/runner/actions-runner /home/runner/go /home/runner/.cache

if [ -S /var/run/docker.sock ]; then
  docker_gid="$(stat -c '%g' /var/run/docker.sock)"
  docker_group="$(getent group "${docker_gid}" | cut -d: -f1 || true)"
  if [ -z "${docker_group}" ]; then
    docker_group=docker-host
    groupadd -g "${docker_gid}" "${docker_group}"
  fi
  usermod -aG "${docker_group}" runner
fi

cleanup() {
  if [ "${RUNNER_REMOVE_ON_EXIT:-false}" = "true" ] && [ -n "${RUNNER_TOKEN:-}" ] && [ -f .runner ]; then
    runuser -u runner -- ./config.sh remove --unattended --token "${RUNNER_TOKEN}" || true
  fi
}
trap cleanup EXIT

if [ ! -f .runner ]; then
  if [ -z "${REPO_URL}" ]; then
    echo 'REPO_URL is required' >&2
    exit 1
  fi
  if [ -z "${RUNNER_TOKEN:-}" ]; then
    echo 'RUNNER_TOKEN is required for first-time runner registration' >&2
    exit 1
  fi

  config_args=(
    ./config.sh
    --unattended
    --url "${REPO_URL}"
    --token "${RUNNER_TOKEN}"
    --name "${RUNNER_NAME}"
    --labels "${RUNNER_LABELS}"
    --work "${RUNNER_WORKDIR}"
    --replace
  )

  if [ "${RUNNER_EPHEMERAL:-false}" = "true" ]; then
    config_args+=(--ephemeral)
  fi

  runuser -u runner -- "${config_args[@]}"
fi

exec runuser -u runner -- ./run.sh
