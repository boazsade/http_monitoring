# HTTP Packet Monitoring
This code allow to monitor packets on a given interface and interfept those that are in HTTP 1/1.1 format

## Building
You can use the dockerfile here with
```
docker build -t http_monitor .
```
Then you can run the container and build inside it:
```
export GID=$(id -g)
docker run --rm -t -d --user $UID:$GID \
    --workdir="/home/$USER" --volume="/etc/group:/etc/group:ro" \
    --name http_monitor -v <path to this repo>:/builds
    --volume="/etc/passwd:/etc/passwd:ro" \
    --volume="/etc/shadow:/etc/shadow:ro" \
    http_monitor
```
