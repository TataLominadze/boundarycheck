#!/usr/bin/env bash

set -uo pipefail

READY_TIMEOUT_SECONDS=90
READY_POLL_SECONDS=2
FAILURES=0
secure_started=0
insecure_started=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/compose/compose.yaml"
INSECURE_FILE="$REPO_ROOT/docker/compose/compose.insecure.yaml"
RUN_ID="${BASHPID:-$$}-${RANDOM}"
SECURE_PROJECT="boundarycheck-demo-secure-$RUN_ID"
INSECURE_PROJECT="boundarycheck-demo-insecure-$RUN_ID"
SECURE_DB_NETWORK="${SECURE_PROJECT}_db_network"
INSECURE_DB_NETWORK="${INSECURE_PROJECT}_db_network"
ENV_FILE="$REPO_ROOT/.env"
SECURE_COMPOSE=(docker compose --env-file "$ENV_FILE" -p "$SECURE_PROJECT" -f "$COMPOSE_FILE")
INSECURE_COMPOSE=(docker compose --env-file "$ENV_FILE" -p "$INSECURE_PROJECT" -f "$COMPOSE_FILE" -f "$INSECURE_FILE")

pass() {
    printf 'PASS: %s\n' "$1"
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

cleanup() {
    local exit_status=$?
    local cleanup_failed=0
    trap - EXIT

    if [[ "$secure_started" -eq 1 ]]; then
        if ! "${SECURE_COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
            printf 'FAIL: Could not clean up secure demo project %s.\n' "$SECURE_PROJECT" >&2
            cleanup_failed=1
        fi
    fi
    if [[ "$insecure_started" -eq 1 ]]; then
        if ! "${INSECURE_COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
            printf 'FAIL: Could not clean up insecure demo project %s.\n' "$INSECURE_PROJECT" >&2
            cleanup_failed=1
        fi
    fi

    if [[ "$cleanup_failed" -eq 1 && "$exit_status" -eq 0 ]]; then
        exit_status=1
    fi
    exit "$exit_status"
}

trap cleanup EXIT

for required_command in docker curl; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        fail "Required command '$required_command' was not found; install it and rerun this script."
        exit 1
    fi
done

if [[ ! -f "$ENV_FILE" ]]; then
    fail "Local configuration was not found. Copy .env.example to .env, review its development-only values, then rerun this script."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    fail "Docker is installed, but its daemon is unavailable. Start Docker Desktop or the Docker Engine, then rerun this script."
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    fail "Docker Compose V2 is unavailable. Install or enable Docker Compose V2."
    exit 1
fi

if [[ ! -f "$COMPOSE_FILE" || ! -f "$INSECURE_FILE" ]]; then
    fail "Compose files were not found. Run this script from the BoundaryCheck checkout or restore its docker/compose files."
    exit 1
fi

service_ready() {
    local service=""
    local argument
    local -a compose=()
    local container_id state_health state health

    for argument in "$@"; do
        case "$argument" in
            proxy|api|db) service="$argument"; break ;;
            *) compose+=("$argument") ;;
        esac
    done
    container_id="$("${compose[@]}" ps -q "$service" 2>/dev/null)" || return 1
    [[ -n "$container_id" ]] || return 1

    state_health="$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id" 2>/dev/null)" || return 1
    IFS='|' read -r state health <<< "$state_health"
    [[ "$state" == "running" && ( "$health" == "none" || "$health" == "healthy" ) ]]
}

wait_for_stack() {
    local -a compose=("$@")
    local deadline=$((SECONDS + READY_TIMEOUT_SECONDS))

    while (( SECONDS < deadline )); do
        if service_ready "${compose[@]}" proxy \
            && service_ready "${compose[@]}" api \
            && service_ready "${compose[@]}" db; then
            pass "proxy, api, and db are running; configured health checks are healthy."
            return 0
        fi
        sleep "$READY_POLL_SECONDS"
    done

    printf 'Container status at readiness timeout:\n' >&2
    "${compose[@]}" ps >&2 || true
    fail "proxy, api, and db did not all become ready within ${READY_TIMEOUT_SECONDS}s."
    return 1
}

http_check() {
    local label="$1"
    local url="$2"
    local expected="$3"
    local expected2="${4:-}"
    local response

    if response="$(curl --fail --silent --show-error --max-time 5 "$url" 2>&1)" \
        && [[ "$response" == *"$expected"* ]] \
        && { [[ -z "$expected2" ]] || [[ "$response" == *"$expected2"* ]]; }; then
        pass "$label"
    else
        fail "$label (request failed or response did not contain '$expected'; output: $response)"
    fi
}

inspect_container() {
    local service=""
    local argument
    local -a compose=()

    for argument in "$@"; do
        case "$argument" in
            proxy|api|db) service="$argument"; break ;;
            *) compose+=("$argument") ;;
        esac
    done
    "${compose[@]}" ps -q "$service" 2>/dev/null
}

check_not_published() {
    local label="$1"
    local container_id="$2"
    local published

    if published="$(docker inspect --format '{{if .HostConfig.PortBindings}}published{{else}}not-published{{end}}' "$container_id" 2>&1)" \
        && [[ "$published" == "not-published" ]]; then
        pass "$label has no host-published ports."
    else
        fail "$label unexpectedly has a host-published port or could not be inspected (result: $published)."
    fi
}

probe_database_tcp() {
    local mode="$1"
    local proxy_id="$2"
    local db_ip="$3"
    local output result

    if output="$(docker run --rm --network "container:$proxy_id" --entrypoint pg_isready postgres:16-alpine -h "$db_ip" -p 5432 -t 3 2>&1)"; then
        result=0
    else
        result=$?
    fi

    if [[ "$mode" == "secure" ]]; then
        if [[ "$result" -eq 2 ]]; then
            pass "direct TCP connection from secure proxy to PostgreSQL is blocked (database IP $db_ip:5432; $output)."
        else
            fail "secure proxy should not reach PostgreSQL at $db_ip:5432; pg_isready exit=$result; output: $output"
        fi
    elif [[ "$result" -eq 0 ]]; then
        pass "direct TCP connection from insecure proxy to PostgreSQL succeeds ($db_ip:5432)."
    else
        fail "insecure proxy should reach PostgreSQL at $db_ip:5432; pg_isready exit=$result; output: $output"
    fi
}

run_environment() {
    local mode="$1"
    local -a compose
    local project db_network proxy_id api_id db_id proxy_on_db db_ip

    if [[ "$mode" == "secure" ]]; then
        compose=("${SECURE_COMPOSE[@]}")
        project="$SECURE_PROJECT"
        db_network="$SECURE_DB_NETWORK"
        secure_started=1
    else
        compose=("${INSECURE_COMPOSE[@]}")
        project="$INSECURE_PROJECT"
        db_network="$INSECURE_DB_NETWORK"
        insecure_started=1
    fi

    printf '\n=== %s environment (%s) ===\n' "$mode" "$project"
    if ! "${compose[@]}" up --build -d; then
        fail "$mode Compose services could not start. Check the Docker daemon, image/build output, and whether localhost:8080 is already in use."
        if "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
            if [[ "$mode" == "secure" ]]; then secure_started=0; else insecure_started=0; fi
        fi
        return 0
    fi

    if ! wait_for_stack "${compose[@]}"; then
        if "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
            if [[ "$mode" == "secure" ]]; then secure_started=0; else insecure_started=0; fi
        fi
        return 0
    fi

    http_check "NGINX forwards /health to FastAPI." \
        "http://127.0.0.1:8080/health" '"status":"ok"'
    http_check "FastAPI /db-check successfully queries PostgreSQL (SELECT 1)." \
        "http://127.0.0.1:8080/db-check" '"database":"connected"' '"query_result":1'

    proxy_id="$(inspect_container "${compose[@]}" proxy)"
    api_id="$(inspect_container "${compose[@]}" api)"
    db_id="$(inspect_container "${compose[@]}" db)"
    if [[ -z "$proxy_id" || -z "$api_id" || -z "$db_id" ]]; then
        fail "Could not obtain all three container IDs for $mode network and port checks."
    else
        if proxy_on_db="$(docker inspect --format "{{if index .NetworkSettings.Networks \"$db_network\"}}yes{{else}}no{{end}}" "$proxy_id" 2>&1)"; then
            if [[ "$mode" == "secure" && "$proxy_on_db" == "no" ]]; then
                pass "secure proxy is not connected to $db_network."
            elif [[ "$mode" == "insecure" && "$proxy_on_db" == "yes" ]]; then
                pass "insecure proxy is connected to $db_network."
                printf 'INFO: This violates the intended isolation policy: NGINX now shares a network with PostgreSQL and has a direct network path to its port.\n'
            else
                fail "$mode proxy network membership is unexpected (db_network membership: $proxy_on_db)."
            fi
        else
            fail "Could not inspect $mode proxy network membership: $proxy_on_db"
        fi

        check_not_published "FastAPI" "$api_id"
        check_not_published "PostgreSQL" "$db_id"

        if db_ip="$(docker inspect --format "{{with index .NetworkSettings.Networks \"$db_network\"}}{{.IPAddress}}{{end}}" "$db_id" 2>&1)" \
            && [[ -n "$db_ip" ]]; then
            probe_database_tcp "$mode" "$proxy_id" "$db_ip"
        else
            fail "Could not obtain PostgreSQL's IP on $db_network (result: $db_ip)."
        fi
    fi

    if "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
        if [[ "$mode" == "secure" ]]; then secure_started=0; else insecure_started=0; fi
    else
        fail "Could not clean up the $mode demo project $project. Run its matching docker compose down --volumes command manually."
    fi
}

printf 'BoundaryCheck Phase 1 Step 6 infrastructure verification\n'
printf 'The script uses unique Compose projects, localhost:8080, and removes only its own containers and demo volumes.\n'

run_environment secure
run_environment insecure

if [[ "$FAILURES" -eq 0 ]]; then
    printf '\nRESULT: PASS — all secure and insecure demonstration checks passed.\n'
    exit 0
fi

printf '\nRESULT: FAIL — %s check(s) failed.\n' "$FAILURES" >&2
exit 1
