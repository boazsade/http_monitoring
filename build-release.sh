#!/usr/bin/env bash

SCRIPT=$(realpath "$0")
SOURCES=$(dirname "${SCRIPT}")

. ${SOURCES}/.build_settings.sh

BUILD_DIR_DOCKER=$PWD
echo "building release version"
docker exec ${IMAGE}  ${BUILD_DIR_DOCKER}/build.sh -b ${RELEASE_BUILD_DIR} -t Release
