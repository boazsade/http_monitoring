#!/usr/bin/env bash
BUILD_DIR_DOCKER=$PWD
IMAGE=http_monitoring

set -e

docker exec ${IMAGE} ${BUILD_DIR_DOCKER}/build.sh -b ${BUILD_DIR_DOCKER}/build-Release -t Release -g 1 && \
	docker exec ${IMAGE} ${BUILD_DIR_DOCKER}/build.sh -b ${BUILD_DIR_DOCKER}/build-Debug -t Debug -g 1
