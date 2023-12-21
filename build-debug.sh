#!/usr/bin/env bash

SCRIPT=$(realpath "$0")
SOURCES=$(dirname "${SCRIPT}")

. ${SOURCES}/.build_settings.sh

BUILD_DIR_DOCKER=$PWD
echo "building debug version"
docker exec  ${IMAGE} ${BUILD_DIR_DOCKER}/build.sh -b ${DEBUG_BUILD_DIR} -t Debug
