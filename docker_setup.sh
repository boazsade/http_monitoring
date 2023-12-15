#!/usr/bin/env bash

set -e

echo "building docker image so we would be able to build the source code"
docker build http_monitoring . || {
	echo "failed to build the docker image"
	exit 1
}

THIS_PATH=$PWD

echo "starting the docker image - this docker name is [http_monitoring]"
export GID=$(id -g)
docker run --rm -t -d --user $UID:$GID \
    --workdir="/home/$USER" --volume="/etc/group:/etc/group:ro" \
    --name http_monitoring -v ${THIS_PATH}:${THIS_PATH}
    --volume="/etc/passwd:/etc/passwd:ro" \
    --volume="/etc/shadow:/etc/shadow:ro" \
    http_monitoring

echo "successfully started the docker image"
echo "you can now build debug version using the script [build-debug.sh]"
echo "you can now build release version using the script [build-release.sh]"
