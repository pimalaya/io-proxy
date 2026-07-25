#!/usr/bin/env bash
# Bootstrap local proxies for io-proxy integration tests.
#
# Spawns two containers on a private Docker network:
#
#   - echo:  a TCP target that greets every connection with a fixed
#            banner, then closes (alpine/socat). Reachable by the proxy
#            as "echo:7"; never exposed to the host.
#   - proxy: 3proxy serving SOCKS5 and HTTP CONNECT, each on a no-auth
#            and an authenticated port.
#
# Host port map (proxy):
#   1080 -> SOCKS5,       no auth
#   1081 -> SOCKS5,       user "test" / pass "secret"
#   3128 -> HTTP CONNECT, no auth
#   3129 -> HTTP CONNECT, user "test" / pass "secret"
#
# Then run the (ignored) integration tests against them:
#
#   ./tests/proxy.sh
#   cargo test --test proxy -- --ignored
#
# The 3proxy config path and cfg argument below suit the 3proxy/3proxy
# image; adjust the pinned tags if the images move.

set -eu

NET="io-proxy-tests"
ECHO="io-proxy-echo"
PROXY="io-proxy-proxy"
BANNER="io-proxy-tunnel-ok"
PROXY_IMAGE="3proxy/3proxy:0.9.4"
ECHO_IMAGE="alpine/socat:latest"

docker rm -f "$ECHO" "$PROXY" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

# Target: greet every connection with the banner, then close. Quote the
# whole SYSTEM address so the space in the command stays one argv element.
# The network alias "echo" is the hostname the proxy resolves (the
# container name itself, io-proxy-echo, is only used for cleanup).
docker run -d --name "$ECHO" --rm --network "$NET" --network-alias echo \
    "$ECHO_IMAGE" \
    TCP-LISTEN:7,fork,reuseaddr "SYSTEM:echo ${BANNER}" >/dev/null

# 3proxy config: a no-auth section, then an authenticated one. Directives
# are positional; each socks/proxy service snapshots the auth state above
# it. 127.0.0.11 is Docker's embedded DNS, so the proxy can resolve the
# "echo" container name (socks5h / CONNECT host resolution).
#
# The image's default entrypoint chroots to /usr/local/3proxy and drops
# privileges before `include`-ing /conf/3proxy.cfg, so the config is
# mounted at that in-chroot path and the default command is left intact.
CONFIG=$(mktemp)
trap 'rm -f "$CONFIG"' EXIT
cat > "$CONFIG" <<'CFG'
nserver 127.0.0.11
nscache 4096
timeouts 1 5 30 60 180 1800 15 60
auth none
socks -p1080
proxy -p3128
users test:CL:secret
auth strong
allow test
socks -p1081
proxy -p3129
CFG
# mktemp defaults to mode 600; the dropped-privilege 3proxy UID needs read
# access on the bind-mounted config.
chmod 644 "$CONFIG"

docker run -d --name "$PROXY" --rm --network "$NET" \
    -v "${CONFIG}:/usr/local/3proxy/conf/3proxy.cfg:ro" \
    -p 1080:1080 -p 1081:1081 -p 3128:3128 -p 3129:3129 \
    "$PROXY_IMAGE" >/dev/null

# Wait for every proxy listener to accept connections.
for port in 1080 1081 3128 3129; do
    ready=""
    for _ in $(seq 1 30); do
        if (echo > "/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    if [ -z "$ready" ]; then
        echo "proxy port ${port} never came up" >&2
        docker logs "$PROXY" >&2 || true
        exit 1
    fi
done

echo "proxies ready:"
echo "  socks5://127.0.0.1:1080              (no auth)"
echo "  socks5://test:secret@127.0.0.1:1081"
echo "  http://127.0.0.1:3128               (no auth)"
echo "  http://test:secret@127.0.0.1:3129"
echo "  target banner \"${BANNER}\" via echo:7"
