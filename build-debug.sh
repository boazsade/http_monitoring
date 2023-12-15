#!/usr/bin/env bash
BUILD_DIR_DOCKER=$PWD
echo "building debug version"
docker exec  http_monitoring ${BUILD_DIR_DOCKER}/build.sh -b ${BUILD_DIR_DOCKER}/build-Debug -t Debug
