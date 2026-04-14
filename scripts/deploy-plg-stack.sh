#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose -f plg-stack/docker-compose.plg.yml up -d
