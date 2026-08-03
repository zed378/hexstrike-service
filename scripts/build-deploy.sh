#!/usr/bin/env bash
# ============================================================================
# HexStrike AI — Build & Deploy (Bash)
#
# Dockerfiles & compose live in deploy/. Build CONTEXT is the REPO ROOT
# (the Dockerfiles COPY the app from there). This script resolves the repo
# root from its own location, so it works from anywhere.
#
# Usage:  scripts/build-deploy.sh <command> [arg]
#   build [latest|predeploy|postdeploy]   Build all 3 images, or one
#   push  [latest|predeploy|postdeploy]   Push all images, or one
#   pull                                  Pull all images from registry
#   up | down | logs                      Dev compose (deploy/docker-compose.yml)
#   vps-up | vps-down                     VPS endpoints (deploy/docker-compose.vps.yml)
#   clean                                 Remove images + compose volumes
#   help
#
# Env: REGISTRY_IMAGE (default zed378/hexstrike-ai)
# ============================================================================
set -euo pipefail

# Repo root = parent of this script's dir
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REGISTRY_IMAGE="${REGISTRY_IMAGE:-zed378/hexstrike-ai}"
IMAGE_LATEST="${REGISTRY_IMAGE}:latest"
IMAGE_PREDEPLOY="${REGISTRY_IMAGE}:predeploy"
IMAGE_POSTDEPLOY="${REGISTRY_IMAGE}:postdeploy"

COMPOSE_DEV="deploy/docker-compose.yml"
COMPOSE_VPS="deploy/docker-compose.vps.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
success(){ echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# docker compose with repo-root .env when present
compose() {
  local file="$1"; shift
  if [ -f .env ]; then
    docker compose --env-file .env -f "$file" "$@"
  else
    docker compose -f "$file" "$@"
  fi
}

# --- build (context = repo root ".") ---------------------------------------
build_latest()     { info "Building $IMAGE_LATEST (full arsenal)…";  docker build -f deploy/Dockerfile            -t "$IMAGE_LATEST"     . ; success "$IMAGE_LATEST"; }
build_predeploy()  { info "Building $IMAGE_PREDEPLOY (code-scan)…";   docker build -f deploy/Dockerfile.predeploy  -t "$IMAGE_PREDEPLOY"  . ; success "$IMAGE_PREDEPLOY"; }
build_postdeploy() { info "Building $IMAGE_POSTDEPLOY (pentest)…";    docker build -f deploy/Dockerfile.postdeploy -t "$IMAGE_POSTDEPLOY" . ; success "$IMAGE_POSTDEPLOY"; }

build_dispatch() {
  case "${1:-all}" in
    all|"")     build_predeploy; build_postdeploy; build_latest ;;
    latest|full) build_latest ;;
    predeploy)  build_predeploy ;;
    postdeploy) build_postdeploy ;;
    *) error "Unknown image: ${1} (latest|predeploy|postdeploy)"; exit 1 ;;
  esac
}

push_dispatch() {
  case "${1:-all}" in
    all|"")     docker push "$IMAGE_LATEST"; docker push "$IMAGE_PREDEPLOY"; docker push "$IMAGE_POSTDEPLOY" ;;
    latest|full) docker push "$IMAGE_LATEST" ;;
    predeploy)  docker push "$IMAGE_PREDEPLOY" ;;
    postdeploy) docker push "$IMAGE_POSTDEPLOY" ;;
    *) error "Unknown image: ${1}"; exit 1 ;;
  esac
  success "push done"
}

do_pull()   { docker pull "$IMAGE_LATEST"; docker pull "$IMAGE_PREDEPLOY"; docker pull "$IMAGE_POSTDEPLOY"; success "pull done"; }
do_up()     { compose "$COMPOSE_DEV" pull; compose "$COMPOSE_DEV" up -d hexstrike-server; success "dev services up"; }
do_down()   { compose "$COMPOSE_DEV" down; success "dev services down"; }
do_logs()   { compose "$COMPOSE_DEV" logs -f; }
vps_up()    { compose "$COMPOSE_VPS" pull; compose "$COMPOSE_VPS" up -d; success "VPS endpoints up"; }
vps_down()  { compose "$COMPOSE_VPS" down; success "VPS endpoints down"; }
do_clean()  {
  compose "$COMPOSE_DEV" down --volumes 2>/dev/null || true
  for img in "$IMAGE_LATEST" "$IMAGE_PREDEPLOY" "$IMAGE_POSTDEPLOY"; do docker rmi "$img" 2>/dev/null || true; done
  success "clean done"
}

show_help() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

case "${1:-help}" in
  build)   build_dispatch "${2:-all}" ;;
  push)    push_dispatch  "${2:-all}" ;;
  pull)    do_pull ;;
  up)      do_up ;;
  down)    do_down ;;
  logs)    do_logs ;;
  vps-up)  vps_up ;;
  vps-down) vps_down ;;
  clean)   do_clean ;;
  help|-h|--help) show_help ;;
  *) error "Unknown command: ${1}"; show_help; exit 1 ;;
esac
