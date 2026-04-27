#!/usr/bin/env bash
# KeyHog vs TruffleHog Recall Benchmark
#
# Runs both scanners against the test corpus and compares results.
# Requires: cargo (for keyhog), pip install trufflehog (for trufflehog)
#
# Usage: ./scripts/run_benchmark.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYHOG_BIN="${ROOT_DIR}/target/release/keyhog"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}KeyHog vs TruffleHog Recall Benchmark${NC}"
echo "======================================"
echo ""

# Build keyhog in release mode
echo -e "${YELLOW}Building keyhog (release)...${NC}"
cargo build --release --manifest-path "${ROOT_DIR}/Cargo.toml" -p keyhog 2>/dev/null
echo -e "${GREEN}✓ keyhog built${NC}"

# Check trufflehog availability
if ! command -v trufflehog &> /dev/null; then
    echo -e "${RED}✗ trufflehog not found. Install: pip install trufflehog${NC}"
    echo "  Continuing with keyhog-only results."
    HAS_TH=false
else
    TH_VERSION=$(trufflehog --version 2>&1 | head -1)
    echo -e "${GREEN}✓ trufflehog found: ${TH_VERSION}${NC}"
    HAS_TH=true
fi

echo ""

# Function to count findings
count_keyhog() {
    local dir="$1"
    "${KEYHOG_BIN}" scan --path "$dir" --format json 2>/dev/null | grep -c '"detector_id"' || echo 0
}

count_trufflehog() {
    local dir="$1"
    trufflehog filesystem "$dir" --json --no-verification 2>/dev/null | grep -c '"DetectorType"' || echo 0
}

# Blind test
BLIND_DIR="${ROOT_DIR}/tests/recall"
BLIND_BATCHES=("batch1" "batch2" "batch3" "batch4")

echo -e "${BOLD}── Blind Recall Test ──${NC}"
KH_BLIND_TOTAL=0
TH_BLIND_TOTAL=0

for batch in "${BLIND_BATCHES[@]}"; do
    batch_dir="${BLIND_DIR}/${batch}"
    if [[ ! -d "$batch_dir" ]]; then
        continue
    fi
    file_count=$(find "$batch_dir" -type f | wc -l)
    kh_count=$(count_keyhog "$batch_dir")
    KH_BLIND_TOTAL=$((KH_BLIND_TOTAL + kh_count))

    if [[ "$HAS_TH" == "true" ]]; then
        th_count=$(count_trufflehog "$batch_dir")
        TH_BLIND_TOTAL=$((TH_BLIND_TOTAL + th_count))
        echo "  ${batch}: ${file_count} files | keyhog: ${kh_count} | trufflehog: ${th_count}"
    else
        echo "  ${batch}: ${file_count} files | keyhog: ${kh_count}"
    fi
done

BLIND_FILES=$(find "${BLIND_DIR}"/batch* -type f 2>/dev/null | wc -l)
echo ""
echo -e "  ${BOLD}Blind Total:${NC} ${BLIND_FILES} files"
echo -e "    KeyHog:     ${GREEN}${KH_BLIND_TOTAL}${NC} findings"
if [[ "$HAS_TH" == "true" ]]; then
    echo -e "    TruffleHog: ${RED}${TH_BLIND_TOTAL}${NC} findings"
fi

# TruffleHog-favored test
echo ""
echo -e "${BOLD}── TruffleHog-Favored Test ──${NC}"
TH_FAVORED_DIR="${ROOT_DIR}/tests/recall/th_favored"
KH_TH_TOTAL=0
TH_TH_TOTAL=0

if [[ -d "$TH_FAVORED_DIR" ]]; then
    for batch_dir in "${TH_FAVORED_DIR}"/batch*; do
        if [[ ! -d "$batch_dir" ]]; then
            continue
        fi
        batch=$(basename "$batch_dir")
        file_count=$(find "$batch_dir" -type f | wc -l)
        kh_count=$(count_keyhog "$batch_dir")
        KH_TH_TOTAL=$((KH_TH_TOTAL + kh_count))

        if [[ "$HAS_TH" == "true" ]]; then
            th_count=$(count_trufflehog "$batch_dir")
            TH_TH_TOTAL=$((TH_TH_TOTAL + th_count))
            echo "  ${batch}: ${file_count} files | keyhog: ${kh_count} | trufflehog: ${th_count}"
        else
            echo "  ${batch}: ${file_count} files | keyhog: ${kh_count}"
        fi
    done
fi

TH_FILES=$(find "${TH_FAVORED_DIR}" -type f 2>/dev/null | wc -l)
echo ""
echo -e "  ${BOLD}TH-Favored Total:${NC} ${TH_FILES} files"
echo -e "    KeyHog:     ${GREEN}${KH_TH_TOTAL}${NC} findings"
if [[ "$HAS_TH" == "true" ]]; then
    echo -e "    TruffleHog: ${RED}${TH_TH_TOTAL}${NC} findings"
fi

# False positive check on clean code
echo ""
echo -e "${BOLD}── False Positive Check ──${NC}"
CLEAN_DIR="${ROOT_DIR}/tests/corpus/clean"
if [[ -d "$CLEAN_DIR" ]]; then
    kh_fp=$(count_keyhog "$CLEAN_DIR")
    echo -e "  Clean code: ${kh_fp} false positives"
    if [[ "$kh_fp" -eq 0 ]]; then
        echo -e "  ${GREEN}✓ Zero false positives${NC}"
    else
        echo -e "  ${RED}✗ Found ${kh_fp} false positives!${NC}"
    fi
fi

# Summary
echo ""
echo -e "${BOLD}======================================"
echo -e "Summary${NC}"
echo "======================================"
TOTAL_KH=$((KH_BLIND_TOTAL + KH_TH_TOTAL))
TOTAL_FILES=$((BLIND_FILES + TH_FILES))
echo -e "  KeyHog: ${GREEN}${TOTAL_KH}${NC} findings across ${TOTAL_FILES} test files"
if [[ "$HAS_TH" == "true" ]]; then
    TOTAL_TH=$((TH_BLIND_TOTAL + TH_TH_TOTAL))
    echo -e "  TruffleHog: ${RED}${TOTAL_TH}${NC} findings across ${TOTAL_FILES} test files"
    if [[ "$TOTAL_KH" -gt "$TOTAL_TH" ]]; then
        DIFF=$((TOTAL_KH - TOTAL_TH))
        echo -e "  ${GREEN}KeyHog finds ${DIFF} more credentials than TruffleHog${NC}"
    fi
fi
