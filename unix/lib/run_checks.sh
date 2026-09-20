#!/usr/bin/env bash
set -uo pipefail

RUNNER_PATH="$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
RUNNER_DIR="$(cd -P -- "$(dirname -- "$RUNNER_PATH")" &>/dev/null && pwd)"
RELEASE_DIR="$(cd -P -- "${RUNNER_DIR}/.." &>/dev/null && pwd)"
CHECK_DIR="${RELEASE_DIR}/check"

source "${RUNNER_DIR}/os_lib.sh"

readonly ITEM_TIMEOUT="${KISA_CHECK_ITEM_TIMEOUT:-120}"
if ! [[ "$ITEM_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    log_error "KISA_CHECK_ITEM_TIMEOUT은 1 이상의 정수여야 합니다: ${ITEM_TIMEOUT}"
    exit "$KISA_EXIT_FAIL"
fi

RELEASE_ID="unknown"
if [ -r "${RELEASE_DIR}/.release-id" ]; then
    read -r RELEASE_ID < "${RELEASE_DIR}/.release-id" || RELEASE_ID="unknown"
fi
[[ "$RELEASE_ID" =~ ^[a-f0-9]{64}$ ]] || RELEASE_ID="unknown"
if [ "$RELEASE_ID" != "unknown" ] && command -v flock >/dev/null 2>&1; then
    DEPLOY_ROOT="$(cd -P -- "${RELEASE_DIR}/../.." &>/dev/null && pwd)"
    exec 8>"${DEPLOY_ROOT}/.deploy.lock"
    if ! flock -s -w 60 8; then
        log_error "배포 잠금 대기 시간이 초과되었습니다."
        exit "$KISA_EXIT_FAIL"
    fi
fi

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kisa-check.XXXXXX")" || {
    log_error "배치 점검용 임시 디렉터리를 만들 수 없습니다."
    exit "$KISA_EXIT_FAIL"
}
chmod 0700 "$TMP_DIR"
cleanup() {
    [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

emit_failure_json() {
    local code="$1" detail="$2" duration="$3"
    local os_type timestamp
    os_type="$(get_os_type)"
    timestamp="$(get_timestamp)"

    printf '{"code":"%s","title":"점검 실행 오류","status":"fail","action":"점검","detail":"%s","evidence_data":{"점검 결과":"%s"},"os_type":"%s","timestamp":"%s","action_tag":"승인요청","impact":"점검 실행 실패로 별도 확인 필요","severity":"중","release_hash":"%s","duration_seconds":%s}\n' \
        "$(json_escape "$code")" \
        "$(json_escape "$detail")" \
        "$(json_escape "$detail")" \
        "$(json_escape "$os_type")" \
        "$(json_escape "$timestamp")" \
        "$(json_escape "$RELEASE_ID")" \
        "$duration"
}

normalize_result() {
    local code="$1" result_file="$2" duration="$3"
    [ -n "$PYTHON_BIN" ] || return 1

    "$PYTHON_BIN" -c '
import json, sys
code, path, release_hash, duration = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    value = json.load(stream)
if not isinstance(value, dict) or value.get("code") != code:
    raise ValueError("result code mismatch")
value["release_hash"] = release_hash
value["duration_seconds"] = int(duration)
print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
' "$code" "$result_file" "$RELEASE_ID" "$duration"
}

completed=0
for number in $(seq 1 67); do
    printf -v code 'U-%02d' "$number"
    script="${CHECK_DIR}/${code}_check.sh"
    result_file="${TMP_DIR}/${code}.json"
    start_epoch="$(date +%s)"

    log_info "[${code}] 점검 시작"
    rc=0
    if [ ! -x "$script" ]; then
        rc=127
    elif command -v timeout >/dev/null 2>&1; then
        timeout --signal=TERM --kill-after=5 "$ITEM_TIMEOUT" "$script" >"$result_file" || rc=$?
    else
        "$script" >"$result_file" || rc=$?
    fi

    end_epoch="$(date +%s)"
    duration=$((end_epoch - start_epoch))

    if [ "$rc" -eq 127 ]; then
        emit_failure_json "$code" "점검 스크립트가 없거나 실행할 수 없음: ${script}" "$duration"
    elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        emit_failure_json "$code" "점검 스크립트가 제한 시간 ${ITEM_TIMEOUT}초를 초과함(rc=${rc})" "$duration"
    elif [ "$rc" -ne "$KISA_EXIT_GOOD" ] && [ "$rc" -ne "$KISA_EXIT_VULN" ] && [ "$rc" -ne "$KISA_EXIT_FAIL" ]; then
        emit_failure_json "$code" "점검 스크립트가 규약 밖의 종료 코드 ${rc}을 반환함" "$duration"
    elif ! normalize_result "$code" "$result_file" "$duration"; then
        emit_failure_json "$code" "점검 스크립트가 유효한 단일 JSON 객체를 반환하지 않음(rc=${rc})" "$duration"
    fi

    completed=$((completed + 1))
    log_info "[${code}] 점검 종료(rc=${rc}, ${duration}초)"
done

if [ "$completed" -ne 67 ]; then
    log_error "배치 점검 결과 개수 불일치: ${completed}/67"
    exit "$KISA_EXIT_FAIL"
fi

exit "$KISA_EXIT_GOOD"
