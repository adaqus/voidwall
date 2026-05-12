#!/usr/bin/env bash
#
# Run load-test scenarios.
#
# Usage:
#   benches/run.sh                              # run all scenarios
#   benches/run.sh baseline                      # run only "baseline"
#   benches/run.sh action_comparison body_size_scaling  # run two scenarios
#
# Available scenarios (matching k6/ file names):
#   baseline, action_comparison, body_size_scaling,
#   concurrency_scaling, scanner_thread_scaling
#
# 1. Builds release binaries
# 2. Starts echo server, waits for healthcheck
# 3. For each selected scenario config + k6 script:
#    a. Starts proxy with the scenario's config
#    b. Waits for /readyz
#    c. Runs k6
#    d. Stops proxy
# 4. Stops echo server
# 5. Prints summary table (req/s and p99 for each scenario)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RESULTS_DIR="$(mktemp -d)"
CONFIGS_DIR="$SCRIPT_DIR/configs"
K6_DIR="$SCRIPT_DIR/k6"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

ECHO_ADDR="127.0.0.1:8090"
PROXY_ADDR="127.0.0.1:8082"
API_ADDR="127.0.0.1:8083"
ADMIN_ADDR="127.0.0.1:9090"

DURATION="${DURATION:-30s}"

# PIDs to clean up
ECHO_PID=""
PROXY_PID=""

PAYLOADS_DIR="$SCRIPT_DIR/payloads"

ALL_SCENARIOS="baseline action_comparison body_size_scaling concurrency_scaling scanner_thread_scaling structured_scanning http_api"

# --- Parse scenario filter ---

SELECTED_SCENARIOS=("$@")
if [ ${#SELECTED_SCENARIOS[@]} -eq 0 ]; then
    read -ra SELECTED_SCENARIOS <<< "$ALL_SCENARIOS"
fi

# Validate scenario names
for s in "${SELECTED_SCENARIOS[@]}"; do
    case "$s" in
        baseline|action_comparison|body_size_scaling|concurrency_scaling|scanner_thread_scaling|structured_scanning|http_api) ;;
        *)
            echo "ERROR: unknown scenario '$s'" >&2
            echo "Available scenarios: $ALL_SCENARIOS" >&2
            exit 1
            ;;
    esac
done

should_run() {
    local name="$1"
    for s in "${SELECTED_SCENARIOS[@]}"; do
        [ "$s" = "$name" ] && return 0
    done
    return 1
}

echo "Scenarios to run: ${SELECTED_SCENARIOS[*]}"

# Results are written to a temp directory and cleaned up after the summary.

# --- Generate payloads if missing ---

if [ ! -d "$PAYLOADS_DIR" ] || [ -z "$(ls -A "$PAYLOADS_DIR" 2>/dev/null)" ]; then
    echo "Generating test payloads..."
    python3 "$SCRIPT_DIR/generate_payloads.py"
fi

# --- Helpers ---

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null && wait "$PROXY_PID" 2>/dev/null || true
    [ -n "$ECHO_PID" ]  && kill "$ECHO_PID"  2>/dev/null && wait "$ECHO_PID"  2>/dev/null || true
    rm -rf "$RESULTS_DIR"
}
trap cleanup EXIT

wait_for_port() {
    local addr="$1"
    local label="$2"
    local max_attempts=30
    for i in $(seq 1 "$max_attempts"); do
        if curl -sf "http://$addr/" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "ERROR: $label did not become ready at $addr after ${max_attempts} attempts" >&2
    return 1
}

wait_for_readyz() {
    local max_attempts=120
    for i in $(seq 1 "$max_attempts"); do
        if curl -sf "http://$ADMIN_ADDR/readyz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: proxy /readyz not ready after ${max_attempts} attempts" >&2
    return 1
}

start_proxy() {
    local config="$1"
    echo "  Starting proxy with config: $(basename "$config")"
    "$PROJECT_DIR/target/release/pii-proxy" --config "$config" &
    PROXY_PID=$!
    wait_for_readyz
}

stop_proxy() {
    if [ -n "$PROXY_PID" ]; then
        kill "$PROXY_PID" 2>/dev/null && wait "$PROXY_PID" 2>/dev/null || true
        PROXY_PID=""
        sleep 0.5
    fi
}

run_k6() {
    local script="$1"
    local name="$2"
    local output="$RESULTS_DIR/${name}_${TIMESTAMP}.csv"

    echo "  Running k6: $(basename "$script") -> $(basename "$output")"
    k6 run \
        --quiet \
        --summary-trend-stats "avg,p(50),p(95),p(99),max" \
        -e "PROXY_URL=http://$PROXY_ADDR" \
        -e "ECHO_URL=http://$ECHO_ADDR" \
        -e "DURATION=$DURATION" \
        "$script" 2>&1 | tee "$RESULTS_DIR/${name}_${TIMESTAMP}.log"

    echo "$output"
}

# Runs one scenario: start proxy, run k6, stop proxy.
run_scenario() {
    local config="$1"
    local script="$2"
    local name="$3"

    echo ""
    echo "=== Scenario: $name ==="
    start_proxy "$config"
    run_k6 "$script" "$name"
    stop_proxy
}

# --- Build ---

"$PROJECT_DIR/docker/ctl" compile

# --- Start echo server ---

echo ""
echo "Starting echo server on $ECHO_ADDR..."
"$PROJECT_DIR/target/release/echo-server" --listen "$ECHO_ADDR" &
ECHO_PID=$!
wait_for_port "$ECHO_ADDR" "echo-server"
echo "Echo server ready."

# --- Scenario 1: Baseline ---
# Split into individual k6 runs per (payload, concurrency, target) to reduce
# per-process memory — each run uses only one VU level instead of pre-allocating
# for the peak.

run_baseline() {
    local payload="$1"
    local vus="$2"
    local target="$3"  # proxy or direct
    local name="baseline_${target}_${payload}_c${vus}"

    echo ""
    echo "=== Scenario: $name ==="
    start_proxy "$CONFIGS_DIR/reverse_proxy_no_actions.toml"

    local output="$RESULTS_DIR/${name}_${TIMESTAMP}.csv"
    echo "  Running k6: baseline.js ($target, $payload, ${vus} VUs) -> $(basename "$output")"
    k6 run \
        --quiet \
        --summary-trend-stats "avg,p(50),p(95),p(99),max" \
        -e "PROXY_URL=http://$PROXY_ADDR" \
        -e "ECHO_URL=http://$ECHO_ADDR" \
        -e "DURATION=$DURATION" \
        -e "PAYLOAD=$payload" \
        -e "VUS=$vus" \
        -e "TARGET=$target" \
        "$K6_DIR/baseline.js" 2>&1 | tee "$RESULTS_DIR/${name}_${TIMESTAMP}.log"

    stop_proxy
}

if should_run baseline; then
    for payload in small medium large; do
        for vus in 10 50 200; do
            run_baseline "$payload" "$vus" "proxy"
        done
    done
    for vus in 10 50 200; do
        run_baseline "medium" "$vus" "direct"
    done
fi

# --- Scenario 2: Action Comparison ---

if should_run action_comparison; then
    for action in no_actions block redact header; do
        run_scenario \
            "$CONFIGS_DIR/reverse_proxy_${action}.toml" \
            "$K6_DIR/action_comparison.js" \
            "action_${action}"
    done
fi

# --- Scenario 3: Body Size Scaling ---

if should_run body_size_scaling; then
    for size in small medium large; do
        echo ""
        echo "=== Scenario: body_size_${size} ==="
        start_proxy "$CONFIGS_DIR/reverse_proxy_redact.toml"

        local_output="$RESULTS_DIR/body_size_${size}_${TIMESTAMP}.csv"
        k6 run \
            --quiet \
            --summary-trend-stats "avg,p(50),p(95),p(99),max" \
            -e "PROXY_URL=http://$PROXY_ADDR" \
            -e "DURATION=$DURATION" \
            -e "PAYLOAD=$size" \
            "$K6_DIR/body_size_scaling.js" 2>&1 | tee "$RESULTS_DIR/body_size_${size}_${TIMESTAMP}.log"

        stop_proxy
    done
fi

# --- Scenario 4: Concurrency Scaling ---

if should_run concurrency_scaling; then
    for vus in 1 10 50 100 200 500; do
        echo ""
        echo "=== Scenario: concurrency_c${vus} ==="
        start_proxy "$CONFIGS_DIR/reverse_proxy_no_actions.toml"

        local_output="$RESULTS_DIR/concurrency_c${vus}_${TIMESTAMP}.csv"
        k6 run \
            --quiet \
            --summary-trend-stats "avg,p(50),p(95),p(99),max" \
            -e "PROXY_URL=http://$PROXY_ADDR" \
            -e "DURATION=$DURATION" \
            -e "VUS=$vus" \
            "$K6_DIR/concurrency_scaling.js" 2>&1 | tee "$RESULTS_DIR/concurrency_c${vus}_${TIMESTAMP}.log"

        stop_proxy
    done
fi

# --- Scenario 5: Scanner Thread Scaling ---

if should_run scanner_thread_scaling; then
    for threads in 1 2 4 8; do
        run_scenario \
            "$CONFIGS_DIR/scanner_threads_${threads}.toml" \
            "$K6_DIR/scanner_thread_scaling.js" \
            "scanner_threads_${threads}"
    done
fi

# --- Scenario 6: Structured Scanning ---

if should_run structured_scanning; then
    for payload in json csv; do
        echo ""
        echo "=== Scenario: structured_${payload} ==="
        start_proxy "$CONFIGS_DIR/reverse_proxy_redact.toml"

        local_output="$RESULTS_DIR/structured_${payload}_${TIMESTAMP}.csv"
        k6 run \
            --quiet \
            --summary-trend-stats "avg,p(50),p(95),p(99),max" \
            -e "PROXY_URL=http://$PROXY_ADDR" \
            -e "DURATION=$DURATION" \
            -e "PAYLOAD=$payload" \
            "$K6_DIR/structured_scanning.js" 2>&1 | tee "$RESULTS_DIR/structured_${payload}_${TIMESTAMP}.log"

        stop_proxy
    done
fi

# --- Scenario 7: HTTP API ---
# Sweeps endpoint × content-type × body size, all against PII-bearing payloads.
# The http_api config enables only the API listener (no echo upstream needed).
# One k6 process per (endpoint, content_type, payload) combination keeps memory
# small and lines results up cleanly in the summary table.

run_http_api() {
    local endpoint="$1"
    local content_type="$2"
    local payload="$3"
    local name="http_api_${endpoint}_${content_type}_${payload}"

    echo ""
    echo "=== Scenario: $name ==="
    start_proxy "$CONFIGS_DIR/http_api.toml"

    echo "  Running k6: http_api.js ($endpoint, $content_type, $payload)"
    k6 run \
        --quiet \
        --summary-trend-stats "avg,p(50),p(95),p(99),max" \
        -e "API_URL=http://$API_ADDR" \
        -e "DURATION=$DURATION" \
        -e "ENDPOINT=$endpoint" \
        -e "CONTENT_TYPE=$content_type" \
        -e "PAYLOAD=$payload" \
        "$K6_DIR/http_api.js" 2>&1 | tee "$RESULTS_DIR/${name}_${TIMESTAMP}.log"

    stop_proxy
}

if should_run http_api; then
    for endpoint in scan redact; do
        for content_type in text json csv; do
            for payload in small medium large; do
                run_http_api "$endpoint" "$content_type" "$payload"
            done
        done
    done
fi

# --- Summary ---

echo ""
echo "============================================"
echo "  Load Test Summary — $TIMESTAMP"
echo "============================================"
echo ""
printf "%-40s %10s %10s %10s %10s %10s\n" "Scenario" "Requests" "Req/s" "p50" "p99" "Errors"
printf "%-40s %10s %10s %10s %10s %10s\n" "----------------------------------------" "----------" "----------" "----------" "----------" "----------"

for logfile in "$RESULTS_DIR"/*_"${TIMESTAMP}".log; do
    [ -f "$logfile" ] || continue
    name="$(basename "$logfile" "_${TIMESTAMP}.log")"

    # Parse k6 summary output for http_req_duration and http_reqs
    reqs=$(grep -oP 'http_reqs[^0-9]*\K[0-9]+' "$logfile" | tail -1)
    rps=$(grep -oP 'http_reqs[^0-9]*[0-9]+\s+\K[0-9.]+' "$logfile" | tail -1)
    p50=$(grep 'http_req_duration' "$logfile" | grep -oP 'p\(50\)=\K[0-9.]+(?:ms|µs|s)' | head -1)
    p99=$(grep 'http_req_duration' "$logfile" | grep -oP 'p\(99\)=\K[0-9.]+(?:ms|µs|s)' | head -1)
    errs=$(grep -oP 'http_req_failed[^0-9]*\K[0-9]+' "$logfile" | head -1)

    # µ is multi-byte (2 bytes) but 1 column wide; printf miscounts width.
    # Compensate by adding an extra space to the format width for each µ.
    p50_val="${p50:-?}"
    p99_val="${p99:-?}"
    rps_val="${rps:-?}"
    # Truncate req/s to integer for readability
    rps_val="${rps_val%%.*}"
    p50_width=10; [[ "$p50_val" == *µ* ]] && p50_width=11
    p99_width=10; [[ "$p99_val" == *µ* ]] && p99_width=11
    printf "%-40s %10s %10s %${p50_width}s %${p99_width}s %10s\n" "$name" "${reqs:-?}" "$rps_val" "$p50_val" "$p99_val" "${errs:-0}"
done

echo ""
echo "Done."
