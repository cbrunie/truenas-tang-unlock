#!/bin/sh
# Unlock passphrase-encrypted TrueNAS datasets at boot, with the passphrase
# sealed by clevis against a tang server. The NAS only holds the sealed blob:
# stolen and booted away from the tang server, it cannot open its datasets.
#
# The passphrase never goes through argv or the environment: it is piped from
# `clevis decrypt` into jq and curl, both reading stdin.
set -eu

: "${DATASETS:?space-separated list of datasets to unlock}"
: "${TRUENAS_URL:=https://127.0.0.1}"
: "${JWE_FILE:=/config/passphrase.jwe}"   # or the blob itself in JWE
: "${INTERVAL:=60}"

if [ -n "${TRUENAS_API_KEY_FILE:-}" ]; then
    TRUENAS_API_KEY=$(cat "$TRUENAS_API_KEY_FILE")
fi
: "${TRUENAS_API_KEY:?set TRUENAS_API_KEY or TRUENAS_API_KEY_FILE}"

# The key goes to curl through a header file, not on its command line.
AUTH=$(mktemp)
chmod 600 "$AUTH"
printf 'Authorization: Bearer %s\n' "$TRUENAS_API_KEY" > "$AUTH"
unset TRUENAS_API_KEY

# The sealed blob is not a secret on its own (useless without tang), so it may
# come inline, which spares writing files on the NAS.
decrypt() {
    if [ -n "${JWE:-}" ]; then printf %s "$JWE" | clevis decrypt
    else clevis decrypt < "$JWE_FILE"; fi
}

log() { echo "$(date -Iseconds) $*"; }

# ponytail: -k because TrueNAS ships a self-signed certificate. Meant to reach
# the API over loopback (network_mode: host). Set CURL_CA_BUNDLE, which curl
# reads itself, before pointing TRUENAS_URL anywhere else.
INSECURE=-k
[ -n "${CURL_CA_BUNDLE:-}" ] && INSECURE=
api() { curl -fsS $INSECURE -H @"$AUTH" "$@"; }

is_locked() {
    id=$(printf %s "$1" | jq -sRr @uri)
    if ! info=$(api "$TRUENAS_URL/api/v2.0/pool/dataset/id/$id"); then
        log "$1: cannot read state, will retry"
        return 1
    fi
    printf %s "$info" | jq -e '.locked' > /dev/null
}

# pool.dataset.unlock is a job: wait for it, then report what it says.
unlock() {
    job=$(printf %s "$2" \
        | jq -Rs --arg ds "$1" '{id: $ds, options: {datasets: [{name: $ds, passphrase: .}]}}' \
        | api -X POST -H 'Content-Type: application/json' --data-binary @- \
            "$TRUENAS_URL/api/v2.0/pool/dataset/unlock") || { log "$1: unlock request failed"; return 0; }
    i=0
    while [ $i -lt 60 ]; do
        state=$(api "$TRUENAS_URL/api/v2.0/core/get_jobs?id=$job" | jq -r '.[0].state') || state=
        case $state in
            SUCCESS)
                res=$(api "$TRUENAS_URL/api/v2.0/core/get_jobs?id=$job" | jq -c '.[0].result')
                log "$1: $res"
                return 0 ;;
            FAILED|ABORTED)
                log "$1: job $job $state"
                return 0 ;;
        esac
        i=$((i + 1))
        sleep 2
    done
    log "$1: job $job still running, giving up"
}

log "watching: $DATASETS"
# Loops forever: a dataset locked by hand is unlocked again on the next round.
# Stop the app to keep one locked.
while :; do
    todo=
    for ds in $DATASETS; do
        if is_locked "$ds"; then todo="$todo $ds"; fi
    done
    if [ -n "$todo" ]; then
        if phrase=$(decrypt); then
            for ds in $todo; do unlock "$ds" "$phrase"; done
        else
            log "clevis decrypt failed (tang unreachable?), will retry"
        fi
        phrase=
    fi
    sleep "$INTERVAL"
done
