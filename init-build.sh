#!/usr/bin/env bash
set -e
SCRIPT=$(realpath "$0")
SOURCES=$(dirname "${SCRIPT}")

. ${SOURCES}/.build_settings.sh

docker exec ${IMAGE} ${BUILD_DIR_DOCKER}/build.sh -b ${RELEASE_BUILD_DIR} -t Release -g 1 && \
	docker exec ${IMAGE} ${BUILD_DIR_DOCKER}/build.sh -b ${DEBUG_BUILD_DIR} -t Debug -g 1
