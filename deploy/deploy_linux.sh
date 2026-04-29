#!/bin/bash
# =============================================================================
# Aralez Mass Deployment Script for Linux
# Deploy and execute Aralez on multiple Linux machines via SSH
# =============================================================================
#
# Usage:
#   ./deploy_linux.sh -t targets.txt -b aralez_x64_linux [-o /remote/output] [-j 50] [-u root]
#
# Requirements:
#   - SSH key-based authentication configured for all targets
#   - Root/sudo access on target machines
#   - aralez binary available locally
#
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
BINARY=""
TARGETS_FILE=""
SSH_USER="root"
SSH_KEY=""
SSH_PORT=22
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"
PARALLEL_JOBS=50
REMOTE_DIR="/tmp/aralez_deploy"
OUTPUT_DIR=""
COLLECT_DIR=""
LOG_DIR="./deploy_logs"
DRY_RUN=false
ARALEZ_ARGS=""

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    cat <<EOF
Aralez Mass Deployment — Linux

USAGE:
    $0 [OPTIONS]

REQUIRED:
    -t FILE       Target hosts file (one host/IP per line)
    -b FILE       Path to aralez binary

OPTIONS:
    -u USER       SSH user (default: root)
    -k FILE       SSH private key file
    -p PORT       SSH port (default: 22)
    -j N          Parallel jobs (default: 50)
    -o PATH       Remote output directory for --output flag
    -C DIR        Local directory to collect results back via SCP
    -a ARGS       Extra arguments to pass to aralez (quoted)
    -l DIR        Local log directory (default: ./deploy_logs)
    -n            Dry run — show what would be done
    -h            Show this help

EXAMPLES:
    # Basic deployment to all targets
    $0 -t targets.txt -b ./aralez_x64_linux

    # Deploy and collect results
    $0 -t targets.txt -b ./aralez_x64_linux -C ./results

    # Deploy with SFTP output and 100 parallel jobs
    $0 -t targets.txt -b ./aralez_x64_linux -a "--output sftp://user@server/triage" -j 100

    # Dry run
    $0 -t targets.txt -b ./aralez_x64_linux -n
EOF
    exit 0
}

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_task()  { echo -e "${BLUE}[TASK]${NC}  $1"; }

# ── Parse Arguments ───────────────────────────────────────────────────────────
while getopts "t:b:u:k:p:j:o:C:a:l:nh" opt; do
    case $opt in
        t) TARGETS_FILE="$OPTARG" ;;
        b) BINARY="$OPTARG" ;;
        u) SSH_USER="$OPTARG" ;;
        k) SSH_KEY="$OPTARG" ;;
        p) SSH_PORT="$OPTARG" ;;
        j) PARALLEL_JOBS="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        C) COLLECT_DIR="$OPTARG" ;;
        a) ARALEZ_ARGS="$OPTARG" ;;
        l) LOG_DIR="$OPTARG" ;;
        n) DRY_RUN=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ── Validate ──────────────────────────────────────────────────────────────────
if [[ -z "$TARGETS_FILE" || -z "$BINARY" ]]; then
    log_error "Both -t (targets) and -b (binary) are required."
    usage
fi

[[ ! -f "$TARGETS_FILE" ]] && { log_error "Targets file not found: $TARGETS_FILE"; exit 1; }
[[ ! -f "$BINARY" ]] && { log_error "Binary not found: $BINARY"; exit 1; }

if [[ -n "$SSH_KEY" ]]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
fi

mkdir -p "$LOG_DIR"

# Read targets (skip empty lines and comments)
mapfile -t TARGETS < <(grep -v '^\s*#' "$TARGETS_FILE" | grep -v '^\s*$')
TOTAL=${#TARGETS[@]}

if [[ $TOTAL -eq 0 ]]; then
    log_error "No targets found in $TARGETS_FILE"
    exit 1
fi

log_info "Aralez Mass Deployment"
log_info "Binary:     $BINARY"
log_info "Config:     <embedded>"
log_info "Targets:    $TOTAL hosts"
log_info "Parallel:   $PARALLEL_JOBS"
log_info "SSH User:   $SSH_USER"
log_info "Remote Dir: $REMOTE_DIR"
echo ""

if $DRY_RUN; then
    log_warn "DRY RUN — no changes will be made"
    for host in "${TARGETS[@]}"; do
        echo "  Would deploy to: $host"
    done
    exit 0
fi

# ── Deploy Function ───────────────────────────────────────────────────────────
deploy_to_host() {
    local host="$1"
    local log_file="${LOG_DIR}/${host}.log"
    local start_time=$(date +%s)

    {
        echo "=== Deployment started at $(date -Iseconds) ==="
        echo "Host: $host"
        echo ""

        # 1. Create remote directory
        echo "[1/5] Creating remote directory..."
        ssh $SSH_OPTS -p "$SSH_PORT" "${SSH_USER}@${host}" \
            "mkdir -p ${REMOTE_DIR}" 2>&1 || { echo "FAILED: SSH connection"; return 1; }

        # 2. Upload binary
        echo "[2/5] Uploading binary..."
        scp $SSH_OPTS -P "$SSH_PORT" "$BINARY" \
            "${SSH_USER}@${host}:${REMOTE_DIR}/aralez" 2>&1 || { echo "FAILED: SCP binary"; return 1; }

        # 3. Execute
        echo "[3/4] Executing aralez..."
        local remote_cmd="cd ${REMOTE_DIR} && chmod +x ./aralez && ./aralez"
        if [[ -n "$OUTPUT_DIR" ]]; then
            remote_cmd="$remote_cmd --output ${OUTPUT_DIR}"
        fi
        if [[ -n "$ARALEZ_ARGS" ]]; then
            remote_cmd="$remote_cmd $ARALEZ_ARGS"
        fi

        ssh $SSH_OPTS -p "$SSH_PORT" "${SSH_USER}@${host}" \
            "$remote_cmd" 2>&1 || { echo "FAILED: Execution"; return 1; }

        # 4. Collect results (if requested)
        if [[ -n "$COLLECT_DIR" ]]; then
            echo "[4/4] Collecting results..."
            mkdir -p "${COLLECT_DIR}/${host}"
            scp $SSH_OPTS -P "$SSH_PORT" \
                "${SSH_USER}@${host}:${REMOTE_DIR}/*.zip" \
                "${COLLECT_DIR}/${host}/" 2>&1 || echo "WARN: No zip files to collect"
        else
            echo "[4/4] Skipping result collection"
        fi

        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo ""
        echo "=== Deployment completed in ${duration}s ==="

    } > "$log_file" 2>&1

    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}✓${NC} $host ($(grep -c 'completed' "$log_file" 2>/dev/null || echo '?'))"
    else
        echo -e "${RED}✗${NC} $host — see $log_file"
    fi
    return $exit_code
}

export -f deploy_to_host
export SSH_OPTS SSH_PORT SSH_USER BINARY REMOTE_DIR OUTPUT_DIR COLLECT_DIR ARALEZ_ARGS LOG_DIR
export RED GREEN YELLOW BLUE NC

# ── Execute ───────────────────────────────────────────────────────────────────
log_task "Starting deployment to $TOTAL hosts (${PARALLEL_JOBS} parallel)..."
echo ""

SUCCEEDED=0
FAILED=0

# Use xargs for parallel execution
printf '%s\n' "${TARGETS[@]}" | xargs -P "$PARALLEL_JOBS" -I {} bash -c 'deploy_to_host "$@"' _ {}

# Count results
for host in "${TARGETS[@]}"; do
    if [[ -f "${LOG_DIR}/${host}.log" ]] && grep -q "completed" "${LOG_DIR}/${host}.log" 2>/dev/null; then
        SUCCEEDED=$((SUCCEEDED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "═══════════════════════════════════════════"
log_info "Deployment Summary"
echo "  Total:     $TOTAL"
echo -e "  ${GREEN}Succeeded: $SUCCEEDED${NC}"
echo -e "  ${RED}Failed:    $FAILED${NC}"
echo "  Logs:      $LOG_DIR/"
[[ -n "$COLLECT_DIR" ]] && echo "  Results:   $COLLECT_DIR/"
echo "═══════════════════════════════════════════"

[[ $FAILED -gt 0 ]] && exit 1 || exit 0
