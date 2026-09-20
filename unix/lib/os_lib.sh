#!/usr/bin/env bash

if [ -n "${__KISA_OS_LIB_LOADED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi
__KISA_OS_LIB_LOADED=1

set -u

readonly KISA_EXIT_GOOD=0
readonly KISA_EXIT_VULN=1
readonly KISA_EXIT_FAIL=2

: "${KISA_APPROVAL:=false}"
KISA_STATUS=""
KISA_DUAL_MISMATCH=false
KISA_FIX_OUTCOME=

_kisa_log() {
    local level="$1"; shift
    local ts
    ts="$(get_timestamp 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)"
    printf '[%s] [%s] %s\n' "$ts" "$level" "$*" >/dev/stderr
}

log_debug() { [ "${KISA_DEBUG:-false}" = "true" ] && _kisa_log "DEBUG" "$@"; return 0; }
log_info()  { _kisa_log "INFO"  "$@"; }
log_warn()  { _kisa_log "WARN"  "$@"; }
log_error() { _kisa_log "ERROR" "$@"; }

get_os_type() {
    local id="" ver="" name=""

    if [ -r /etc/os-release ]; then
        id="$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '"')"
        ver="$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n1 | tr -d '"')"
        name="$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n1 | tr -d '"')"
    fi

    if [ -z "$name" ]; then
        if [ -r /etc/redhat-release ]; then
            name="$(cat /etc/redhat-release 2>/dev/null)"
        else
            name="$(uname -s 2>/dev/null)"
        fi
    fi

    if [ -n "$id" ] && [ -n "$ver" ]; then
        printf '%s %s' "$id" "$ver"
    elif [ -n "$name" ]; then
        printf '%s' "$name"
    else
        printf 'unknown'
    fi
}

get_timestamp() {
    local ts
    ts="$(date +'%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null)"
    if [ -z "$ts" ] || printf '%s' "$ts" | grep -qE '%:?z$'; then
        ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
    fi
    printf '%s' "$ts"
}

json_escape() {
    local s="${1:-}"

    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"

    s="$(printf '%s' "$s" | sed -e 's/[\x01-\x08\x0B\x0C\x0E-\x1F]//g')"

    printf '%s' "$s"
}

verify_and_get_status() {
    local check_func="$1"

    if ! declare -F "$check_func" >/dev/null 2>&1; then
        log_error "verify_and_get_status: 함수 '${check_func}' 가 정의되어 있지 않습니다."
        KISA_STATUS="fail"
        return "$KISA_EXIT_FAIL"
    fi

    local first second
    KISA_DUAL_MISMATCH=false

    "$check_func"; first=$?
    "$check_func"; second=$?

    if [ "$first" -ne "$second" ]; then
        log_warn "이중 검증 불일치 감지(1차=${first}, 2차=${second}). 상태를 fail 로 처리합니다."
        KISA_STATUS="fail"
        KISA_DUAL_MISMATCH=true
        return "$KISA_EXIT_FAIL"
    fi

    case "$first" in
        "$KISA_EXIT_GOOD") KISA_STATUS="양호" ;;
        "$KISA_EXIT_VULN")  KISA_STATUS="취약" ;;
        *)
            KISA_STATUS="fail"
            first="$KISA_EXIT_FAIL"
            ;;
    esac

    return "$first"
}

finalize_fix_status() {
    local fix_rc="${1:-$KISA_EXIT_FAIL}"
    KISA_FIX_OUTCOME=""

    case "$fix_rc" in
        "$KISA_EXIT_GOOD")
            KISA_FIX_OUTCOME="완료"
            case "$KISA_STATUS" in
                "양호") return "$KISA_EXIT_GOOD" ;;
                "취약") return "$KISA_EXIT_VULN" ;;
                *) return "$KISA_EXIT_FAIL" ;;
            esac
            ;;
        "$KISA_EXIT_VULN")
            KISA_FIX_OUTCOME="부분 조치/수동 조치 필요"
            KISA_STATUS="취약"
            return "$KISA_EXIT_VULN"
            ;;
        *)
            KISA_FIX_OUTCOME="조치 실패"
            KISA_STATUS="fail"
            return "$KISA_EXIT_FAIL"
            ;;
    esac
}

require_root() {
    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        log_error "root 권한이 필요합니다. (현재 UID: $(id -u 2>/dev/null))"
        return 1
    fi
    return 0
}

is_approved() {
    [ "${KISA_APPROVAL:-false}" = "true" ]
}

restart_active_services() {
    command -v systemctl >/dev/null 2>&1 || return 0
    local svc
    for svc in "$@"; do
        if systemctl is-active "$svc" >/dev/null 2>&1; then
            systemctl restart "$svc" >/dev/null 2>&1 || return 1
        fi
    done
    return 0
}

evidence_json() {
    local result="{" separator="" key value
    while [ "$#" -ge 2 ]; do
        key="$1"; value="$2"; shift 2
        result="${result}${separator}\"$(json_escape "$key")\":\"$(json_escape "$value")\""
        separator=","
    done
    printf '%s}' "$result"
}

print_json_result() {
    local code="$1" title="$2" status="$3" action="$4"
    local detail="$5" action_tag="$6" impact="$7" severity="$8"
    local evidence_data="${9:-}"

    case "$evidence_data" in
        \{*\}) ;;
        *) evidence_data="$(evidence_json "점검 결과" "${detail:--}")" ;;
    esac

    local os_type timestamp
    os_type="$(get_os_type)"
    timestamp="$(get_timestamp)"

    local e_code e_title e_status e_action e_detail e_os e_ts e_tag e_impact e_sev
    e_code="$(json_escape "$code")"
    e_title="$(json_escape "$title")"
    e_status="$(json_escape "$status")"
    e_action="$(json_escape "$action")"
    e_detail="$(json_escape "$detail")"
    e_os="$(json_escape "$os_type")"
    e_ts="$(json_escape "$timestamp")"
    e_tag="$(json_escape "$action_tag")"
    e_impact="$(json_escape "$impact")"
    e_sev="$(json_escape "$severity")"

    printf '{"code":"%s","title":"%s","status":"%s","action":"%s","detail":"%s","evidence_data":%s,"os_type":"%s","timestamp":"%s","action_tag":"%s","impact":"%s","severity":"%s"}\n' \
        "$e_code" "$e_title" "$e_status" "$e_action" "$e_detail" "$evidence_data" "$e_os" "$e_ts" "$e_tag" "$e_impact" "$e_sev"

    case "$status" in
        "양호") exit "$KISA_EXIT_GOOD" ;;
        "취약") exit "$KISA_EXIT_VULN" ;;
        *)      exit "$KISA_EXIT_FAIL" ;;
    esac
}
