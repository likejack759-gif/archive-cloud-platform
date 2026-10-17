#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "已生成 .env，请编辑 SECRET_KEY 和 ADMIN_PASSWORD 后重新运行。"
  exit 1
fi
docker compose up -d --build
docker compose ps
