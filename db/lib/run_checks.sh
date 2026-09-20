#!/usr/bin/env bash
set -uo pipefail

RUNNER_PATH="$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
RUNNER_DIR="$(cd -P -- "$(dirname -- "$RUNNER_PATH")" &>/dev/null && pwd)"
RELEASE_DIR="$(cd -P -- "${RUNNER_DIR}/.." &>/dev/null && pwd)"
CHECK_DIR="${RELEASE_DIR}/check"

get_timestamp() {
    local ts
    ts="$(date +'%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null)"
    if [ -z "$ts" ] || printf '%s' "$ts" | grep -qE '%:?z$'; then
        ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
    fi
    printf '%s' "$ts"
}
log_info()  { printf '[%s] [INFO] %s\n'  "$(get_timestamp)" "$*" >/dev/stderr; }
log_error() { printf '[%s] [ERROR] %s\n' "$(get_timestamp)" "$*" >/dev/stderr; }
json_escape() {
    local s="${1:-}"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

readonly ITEM_TIMEOUT="${KISA_CHECK_ITEM_TIMEOUT:-120}"
if ! [[ "$ITEM_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    log_error "KISA_CHECK_ITEM_TIMEOUT은 1 이상의 정수여야 합니다: ${ITEM_TIMEOUT}"
    exit 3
fi

D_CODES="D-01 D-02 D-03 D-04 D-06 D-07 D-08 D-10 D-11 D-25"
D_COUNT=10

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mysql-security-check.XXXXXX")" || {
    log_error "배치 점검용 임시 디렉터리를 만들 수 없습니다."
    exit 3
}
chmod 0700 "$TMP_DIR"
cleanup() {
    [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

emit_failure_json() {
    local code="$1" detail="$2"
    printf '{"code":"%s","title":"점검 실행 오류","status":"오류","action":"점검","detail":"%s","evidence_data":{"점검 결과":"%s"},"os_type":"unknown","timestamp":"%s","action_tag":"승인요청","impact":"점검 실행 실패로 별도 확인 필요","severity":"중"}\n' \
        "$(json_escape "$code")" "$(json_escape "$detail")" "$(json_escape "$detail")" "$(json_escape "$(get_timestamp)")"
}

completed=0
for code in $D_CODES; do
    script="${CHECK_DIR}/${code}_check.sh"
    result_file="${TMP_DIR}/${code}.json"

    log_info "[${code}] 점검 시작"
    rc=0
    if [ ! -x "$script" ]; then
        rc=127
    elif command -v timeout >/dev/null 2>&1; then
        timeout --signal=TERM --kill-after=5 "$ITEM_TIMEOUT" "$script" >"$result_file" 2>>/dev/stderr || rc=$?
    else
        "$script" >"$result_file" 2>>/dev/stderr || rc=$?
    fi

    if [ "$rc" -eq 127 ]; then
        emit_failure_json "$code" "점검 스크립트가 없거나 실행할 수 없음: ${script}"
    elif [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        emit_failure_json "$code" "점검 스크립트가 제한 시간 ${ITEM_TIMEOUT}초를 초과함(rc=${rc})"
    elif [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ] && [ "$rc" -ne 2 ] && [ "$rc" -ne 3 ]; then
        emit_failure_json "$code" "점검 스크립트가 규약 밖의 종료 코드 ${rc}을 반환함"
    elif [ ! -s "$result_file" ]; then
        emit_failure_json "$code" "점검 스크립트가 결과를 출력하지 않음(rc=${rc})"
    else
        cat "$result_file"
    fi

    completed=$((completed + 1))
    log_info "[${code}] 점검 종료(rc=${rc})"
done

if [ "$completed" -ne "$D_COUNT" ]; then
    log_error "배치 점검 결과 개수 불일치: ${completed}/${D_COUNT}"
    exit 3
fi

exit 0
