#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 mp0rta
#
# HTTP/3 interop matrix and h3spec (docs/interop.md).
#
#   interop/run.sh            build both images, then run
#   SKIP_BUILD=1 interop/run.sh   reuse the images already built
#
# Runs every `mandatory` row of interop/cells.tsv and h3spec against our server, and
# writes target/interop-report.md (scratch files: target/interop/). Exits non-zero on a
# mandatory failure, or on an h3spec failure not listed in interop/h3spec-allowlist.
#
# A cell's command runs as `sh -ec` in the image of its client side (peers image for
# peer->h3wire, h3wire image for h3wire->peer) and passes when it exits 0. A
# peer->h3wire cell also needs every connection it opened to have closed cleanly at our
# server (graceful shutdown, or the peer's H3_NO_ERROR or transport NO_ERROR close). In
# a GOAWAY cell seeing the final GOAWAY is not required, since quinn's close may discard
# it (it is best-effort).
# Variables for commands: H3WIRE, NGTCP2, QUICHE (server URLs), CA (our certificate),
# POST (10 MiB of 'a'), SHA_1M and SHA_8M (SHA-256 of 1 MiB and 8 MiB of 'a', served as
# /bytes/1048576 and /bytes/8388608 by every server), HEX_POST (SHA-256 of POST, which
# our /sha256 returns), OUT (an empty directory for the cell).
set -euo pipefail
start=$SECONDS
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
set -a
# shellcheck source=interop/versions.env
. interop/versions.env
set +a

PEERS=h3wire-interop-peers
OURS=h3wire-interop-h3wire
if [ -z "${SKIP_BUILD:-}" ]; then
    args=()
    while IFS='=' read -r k _; do
        if [[ $k =~ ^[A-Z0-9_]+$ ]]; then args+=(--build-arg "$k"); fi
    done < interop/versions.env
    docker build "${args[@]}" -f interop/Dockerfile.peers -t "$PEERS" interop
    docker build "${args[@]}" -f interop/Dockerfile.h3wire -t "$OURS" .
fi

W=$root/target/interop
rm -rf "$W"
mkdir -p "$W/htdocs/bytes" "$W/out"
NET=h3wire-interop-$$
U="$(id -u):$(id -g)"
docker network create "$NET" >/dev/null
cleanup() {
    docker logs "$NET-h3wire" >"$W/h3wire-server.log" 2>&1 || true
    docker rm -f "$NET-h3wire" "$NET-ngtcp2" "$NET-quiche" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Run a one-off container on the network, with target/interop at /work.
run() { docker run --rm --network "$NET" --user "$U" -v "$W:/work" "$@"; }

run "$PEERS" openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -days 7 -subj /CN=h3wire -addext "subjectAltName=DNS:h3wire,DNS:ngtcp2,DNS:quiche" \
    -addext "basicConstraints=critical,CA:FALSE" -keyout /work/key.pem -out /work/cert.pem \
    2>/dev/null
a() { head -c "$1" /dev/zero | tr '\0' a; }
a 1048576 >"$W/htdocs/bytes/1048576"
a 8388608 >"$W/htdocs/bytes/8388608"
a 10485760 >"$W/post.bin"
sha() { sha256sum "$1" | cut -d' ' -f1; }
SHA_1M=$(sha "$W/htdocs/bytes/1048576")
SHA_8M=$(sha "$W/htdocs/bytes/8388608")
HEX_POST=$(sha "$W/post.bin")

# Start a server as `$NET-<name>`, reachable as <name>:4433, and wait for its socket.
serve() {
    local name=$1
    shift
    docker run -d --name "$NET-$name" --network "$NET" --network-alias "$name" --user "$U" \
        -v "$W:/work:ro" "$@" >/dev/null
    timeout 30 sh -c "until docker exec $NET-$name grep -q ':1151 ' /proc/net/udp; do sleep 0.1; done"
}
serve h3wire "$OURS" h3wire-server --listen 0.0.0.0:4433 --cert /work/cert.pem \
    --key /work/key.pem --masque-echo
serve ngtcp2 "$PEERS" ngtcp2-server -q --send-trailers -d /work/htdocs 0.0.0.0 4433 \
    /work/key.pem /work/cert.pem
serve quiche "$PEERS" quiche-server --listen 0.0.0.0:4433 --cert /work/cert.pem \
    --key /work/key.pem --root /work/htdocs/

server_log() { docker logs "$NET-h3wire" 2>&1; }

# Every connection our server accepted after log line $1 closed cleanly. Waits up to
# 10 s for each accepted connection to be logged as closed.
closed_cleanly() {
    local log acc=0 cls=0
    for _ in $(seq 100); do
        log=$(server_log | tail -n +"$(($1 + 1))")
        acc=$(grep -c ': accepted$' <<<"$log" || true)
        cls=$(grep -c ': closed' <<<"$log" || true)
        if [ "$acc" -gt 0 ] && [ "$acc" = "$cls" ]; then break; fi
        sleep 0.1
    done
    printf '%s\n' '--- h3wire server log for this cell' "$log"
    [ "$acc" -gt 0 ] && [ "$acc" = "$cls" ] && ! grep -q 'closed with error' <<<"$log"
}

report=$root/target/interop-report.md
rows=()
mandatory_failed=0
while IFS=$'\t' read -r cap peer version dir cmd status; do
    [ "$cap" = capability ] && continue
    version=$(eval "echo \"$version\"")
    id=$(printf '%s-%s-%s' "$cap" "$peer" "$dir" | tr -cs 'A-Za-z0-9' '-')
    secs=-
    if [ "$status" != mandatory ]; then
        result=unsupported
    else
        mkdir -p "$W/out/$id"
        image=$PEERS
        if [ "$dir" = "h3wire->peer" ]; then image=$OURS; fi
        before=$(server_log | wc -l)
        t0=$SECONDS
        if run -e H3WIRE=https://h3wire:4433 -e NGTCP2=https://ngtcp2:4433 \
            -e QUICHE=https://quiche:4433 -e CA=/work/cert.pem -e POST=/work/post.bin \
            -e SHA_1M="$SHA_1M" -e SHA_8M="$SHA_8M" -e HEX_POST="$HEX_POST" \
            -e OUT="/work/out/$id" "$image" timeout 60 sh -ec "$cmd" \
            >"$W/out/$id.log" 2>&1 \
            && { [ "$dir" != "peer->h3wire" ] || closed_cleanly "$before" >>"$W/out/$id.log"; }; then
            result=pass
        else
            result=fail
            mandatory_failed=$((mandatory_failed + 1))
        fi
        secs=$((SECONDS - t0))
    fi
    echo "$result: $cap, $peer, $dir"
    rows+=("| $cap | $peer | $version | $dir | $result | $secs |")
done <interop/cells.tsv

# h3spec: failures are `<file>.hs:<line>:<col>: ` followed by `  <n>) <description>`.
# Bounded: 77 cases take a few seconds, each at most 2 s.
run "$PEERS" timeout 300 h3spec -n h3wire 4433 >"$W/h3spec.txt" 2>&1 || true
summary=$(grep -E '^[0-9]+ examples, [0-9]+ failures?' "$W/h3spec.txt" || echo "no summary: h3spec did not finish")
h3_rows=()
h3spec_new=0
while IFS=$'\t' read -r case desc; do
    entry=$(grep -E "^${case}[[:space:]]" interop/h3spec-allowlist || true)
    if [ -n "$entry" ]; then
        layer=$(awk '{print $2}' <<<"$entry")
        why=$(sed -E 's/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+//' <<<"$entry")
    else
        layer="?"
        why="NOT ALLOWLISTED"
        h3spec_new=$((h3spec_new + 1))
    fi
    h3_rows+=("| \`$case\` | $desc | $layer | $why |")
done < <(awk '/^  [A-Za-z0-9]+\.hs:[0-9]+:[0-9]+: *$/ { c = $1; sub(/:$/, "", c); getline;
    sub(/^ *[0-9]+\) /, ""); print c "\t" $0 }' "$W/h3spec.txt")
# The parse must account for every failure h3spec itself counts.
reported=$(sed -nE 's/^[0-9]+ examples, ([0-9]+) failures?.*/\1/p' "$W/h3spec.txt")
h3spec_problem=""
if [ -z "$reported" ]; then
    h3spec_problem="h3spec did not finish (no summary line)"
elif [ "$reported" != "${#h3_rows[@]}" ]; then
    h3spec_problem="h3spec counts $reported failures but ${#h3_rows[@]} were parsed"
fi
stale=$(grep -vE '^(#|$)' interop/h3spec-allowlist | awk '{print $1}' \
    | while read -r c; do grep -qF "$c" "$W/h3spec.txt" || echo "$c"; done)

total=$((SECONDS - start))
{
    echo "# Interop report"
    echo
    echo "$(date -u '+%Y-%m-%d %H:%M UTC'), h3wire $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- || echo ' (dirty)'), total run time ${total} s."
    echo
    echo "## Matrix"
    echo
    echo "| capability | peer | version | direction | result | seconds |"
    echo "|---|---|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
    echo
    echo "Mandatory failures: $mandatory_failed. Logs: \`target/interop/out/<cell>.log\`."
    echo
    echo "## h3spec"
    echo
    echo "h3spec $H3SPEC_URL (sha256 $H3SPEC_SHA256): $summary."
    echo
    if [ ${#h3_rows[@]} -gt 0 ]; then
        echo "| case | description | layer | allowlist rationale |"
        echo "|---|---|---|---|"
        printf '%s\n' "${h3_rows[@]}"
        echo
    fi
    echo "Failures not allowlisted: $h3spec_new. Allowlisted cases that passed: ${stale:-none}."
    if [ -n "$h3spec_problem" ]; then echo "**h3spec check failed: $h3spec_problem.**"; fi
    echo "Output: \`target/interop/h3spec.txt\`."
} >"$report"
echo "wrote $report (${total} s)"
if [ -n "$h3spec_problem" ]; then echo "h3spec check failed: $h3spec_problem" >&2; fi
[ "$mandatory_failed" = 0 ] && [ "$h3spec_new" = 0 ] && [ -z "$h3spec_problem" ]
