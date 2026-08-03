# ============================================================================
# HexStrike AI — Build & Deploy Makefile
# Dockerfiles/compose live in deploy/ ; build CONTEXT = repo ROOT.
# Run from anywhere:  make -C scripts <target>   (or `cd scripts && make <target>`)
#
# Targets:
#   build            Build all 3 images (predeploy, postdeploy, latest)
#   build-latest | build-predeploy | build-postdeploy
#   push | push-latest | push-predeploy | push-postdeploy
#   pull             Pull all images from registry
#   up | down | logs         Dev compose (deploy/docker-compose.yml)
#   vps-up | vps-down        VPS endpoints (deploy/docker-compose.vps.yml)
#   clean            Remove images + compose volumes
#
# Vars: REGISTRY_IMAGE (default zed378/hexstrike-ai)
# ============================================================================

REGISTRY_IMAGE ?= zed378/hexstrike-ai
IMG_LATEST     := $(REGISTRY_IMAGE):latest
IMG_PRE        := $(REGISTRY_IMAGE):predeploy
IMG_POST       := $(REGISTRY_IMAGE):postdeploy

# Repo root = parent of this Makefile's directory
ROOT    := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
CDEV    := deploy/docker-compose.yml
CVPS    := deploy/docker-compose.vps.yml
ENVF    := $(if $(wildcard $(ROOT)/.env),--env-file .env,)
COMPOSE := docker compose $(ENVF)

.PHONY: help build build-latest build-predeploy build-postdeploy \
        push push-latest push-predeploy push-postdeploy pull \
        up down logs vps-up vps-down clean

help:
	@sed -n '2,18p' $(lastword $(MAKEFILE_LIST)) | sed 's/^# \{0,1\}//'

# --- build (context = repo root) ------------------------------------------
build: build-predeploy build-postdeploy build-latest
build-latest:
	cd $(ROOT) && docker build -f deploy/Dockerfile            -t $(IMG_LATEST) .
build-predeploy:
	cd $(ROOT) && docker build -f deploy/Dockerfile.predeploy  -t $(IMG_PRE)    .
build-postdeploy:
	cd $(ROOT) && docker build -f deploy/Dockerfile.postdeploy -t $(IMG_POST)   .

# --- push ------------------------------------------------------------------
push: push-latest push-predeploy push-postdeploy
push-latest:     ; docker push $(IMG_LATEST)
push-predeploy:  ; docker push $(IMG_PRE)
push-postdeploy: ; docker push $(IMG_POST)
pull:
	docker pull $(IMG_LATEST) && docker pull $(IMG_PRE) && docker pull $(IMG_POST)

# --- compose (dev + vps) ---------------------------------------------------
up:
	cd $(ROOT) && $(COMPOSE) -f $(CDEV) pull && $(COMPOSE) -f $(CDEV) up -d hexstrike-server
down:
	cd $(ROOT) && $(COMPOSE) -f $(CDEV) down
logs:
	cd $(ROOT) && $(COMPOSE) -f $(CDEV) logs -f
vps-up:
	cd $(ROOT) && $(COMPOSE) -f $(CVPS) pull && $(COMPOSE) -f $(CVPS) up -d
vps-down:
	cd $(ROOT) && $(COMPOSE) -f $(CVPS) down

clean:
	-cd $(ROOT) && $(COMPOSE) -f $(CDEV) down --volumes
	-docker rmi $(IMG_LATEST) $(IMG_PRE) $(IMG_POST)
