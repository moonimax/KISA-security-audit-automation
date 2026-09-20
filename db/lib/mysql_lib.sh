#!/usr/bin/env bash

if [ -n "${__KISA_MYSQL_LIB_LOADED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi
__KISA_MYSQL_LIB_LOADED=1

set -u

MYSQL_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

readonly KISA_EXIT_GOOD=0
readonly KISA_EXIT_VULN=1
readonly KISA_EXIT_MANUAL=2
readonly KISA_EXIT_ERROR=3

: "${KISA_APPROVAL:=false}"
KISA_STATUS=""
KISA_DUAL_MISMATCH=false
KISA_FIX_OUTCOME=

CONF_FILE="${MYSQL_SECURITY_CONF:-${MYSQL_LIB_DIR}/../config/mysql_security.conf}"
if [ ! -f "$CONF_FILE" ]; then
    echo "[오류] 설정 파일을 찾을 수 없습니다: $CONF_FILE" >&2
    echo "       config/mysql_security.conf.example 을 복사하여 생성하세요." >&2
    exit 3
fi
source "$CONF_FILE"

: "${MYSQL_DEFAULTS_FILE:?MYSQL_DEFAULTS_FILE 이 설정되지 않았습니다}"
: "${MYSQL_HOST:=127.0.0.1}"
: "${MYSQL_PORT:=3306}"

if [ ! -f "$MYSQL_DEFAULTS_FILE" ]; then
    echo "[오류] MySQL 접속 정보 파일이 없습니다: $MYSQL_DEFAULTS_FILE" >&2
    exit 3
fi
DEFFILE_PERM="$(stat -c '%a' "$MYSQL_DEFAULTS_FILE" 2>/dev/null || stat -f '%Lp' "$MYSQL_DEFAULTS_FILE")"
if [ "$DEFFILE_PERM" != "600" ]; then
    echo "[오류] $MYSQL_DEFAULTS_FILE 권한이 600 이 아닙니다 (현재: $DEFFILE_PERM). chmod 600 후 재실행하세요." >&2
    exit 3
fi

get_timestamp() {
    local ts
    ts="$(date +'%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null)"
    if [ -z "$ts" ] || printf '%s' "$ts" | grep -qE '%:?z$'; then
        ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
    fi
    printf '%s' "$ts"
}

_kisa_log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' "$(get_timestamp)" "$level" "$*" >/dev/stderr
}
log_debug() { [ "${KISA_DEBUG:-false}" = "true" ] && _kisa_log "DEBUG" "$@"; return 0; }
log_info()  { _kisa_log "INFO"  "$@"; }
log_warn()  { _kisa_log "WARN"  "$@"; }
log_error() { _kisa_log "ERROR" "$@"; }

mysql_exec() {
    local sql="$1"
    local err_file
    err_file="$(mktemp)"
    local out
    out="$(mysql --defaults-extra-file="$MYSQL_DEFAULTS_FILE" -h "$MYSQL_HOST" -P "$MYSQL_PORT" \
                 -N -B -e "$sql" 2>"$err_file")"
    local rc=$?
    if [ $rc -ne 0 ]; then
        log_error "MYSQL 오류: $(cat "$err_file")"
    fi
    rm -f "$err_file"
    printf '%s' "$out"
    return $rc
}

KISA_MYSQL_OS_TYPE=""
get_mysql_os_type() {
    if [ -z "$KISA_MYSQL_OS_TYPE" ]; then
        local version
        version="$(mysql_exec "SELECT VERSION();" 2>/dev/null | sed -E 's/-.*$//')"
        KISA_MYSQL_OS_TYPE="mysql ${version:-unknown}"
    fi
    printf '%s' "$KISA_MYSQL_OS_TYPE"
}

normalize_account() {
    echo "$1" | tr -d "'"
}

sql_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"
}

list_contains() {
    local needle="$1"; shift
    local hay="$1"
    for item in $hay; do
        [ "$item" = "$needle" ] && return 0
    done
    return 1
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

random_password() {
    tr -dc 'A-Za-z0-9!@#%^*_+=' < /dev/urandom 2>/dev/null | head -c16
    echo
}

verify_and_get_status() {
    local check_func="$1"

    if ! declare -F "$check_func" >/dev/null 2>&1; then
        log_error "verify_and_get_status: 함수 '${check_func}' 가 정의되어 있지 않습니다."
        KISA_STATUS="오류"
        return "$KISA_EXIT_ERROR"
    fi

    local first second
    KISA_DUAL_MISMATCH=false

    "$check_func"; first=$?
    "$check_func"; second=$?

    if [ "$first" -ne "$second" ]; then
        log_warn "이중 검증 불일치 감지(1차=${first}, 2차=${second}). 상태를 오류로 처리합니다."
        KISA_STATUS="오류"
        KISA_DUAL_MISMATCH=true
        return "$KISA_EXIT_ERROR"
    fi

    case "$first" in
        "$KISA_EXIT_GOOD")   KISA_STATUS="양호" ;;
        "$KISA_EXIT_VULN")   KISA_STATUS="취약" ;;
        "$KISA_EXIT_MANUAL") KISA_STATUS="점검필요" ;;
        *)
            KISA_STATUS="오류"
            first="$KISA_EXIT_ERROR"
            ;;
    esac

    return "$first"
}

finalize_fix_status() {
    local fix_rc="${1:-$KISA_EXIT_ERROR}"
    KISA_FIX_OUTCOME=""

    case "$fix_rc" in
        "$KISA_EXIT_GOOD")
            KISA_FIX_OUTCOME="완료"
            case "$KISA_STATUS" in
                "양호")     return "$KISA_EXIT_GOOD" ;;
                "취약")     return "$KISA_EXIT_VULN" ;;
                "점검필요") return "$KISA_EXIT_MANUAL" ;;
                *)          return "$KISA_EXIT_ERROR" ;;
            esac
            ;;
        "$KISA_EXIT_VULN")
            KISA_FIX_OUTCOME="미승인/보류"
            KISA_STATUS="취약"
            return "$KISA_EXIT_VULN"
            ;;
        "$KISA_EXIT_MANUAL")
            KISA_FIX_OUTCOME="자동 조치 불가(수동 조치 필요)"
            KISA_STATUS="점검필요"
            return "$KISA_EXIT_MANUAL"
            ;;
        *)
            KISA_FIX_OUTCOME="조치 실패"
            KISA_STATUS="오류"
            return "$KISA_EXIT_ERROR"
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

ensure_mysqld_block() {
    local marker="$1" content="$2"
    local begin="# BEGIN KISA-DBMS-${marker} (managed by fix script)"
    local end="# END KISA-DBMS-${marker}"

    if [ ! -f "$MY_CNF_PATH" ]; then
        mkdir -p "$(dirname "$MY_CNF_PATH")"
        printf '[mysqld]\n%s\n%s\n%s\n' "$begin" "$content" "$end" > "$MY_CNF_PATH"
        log_info "${MY_CNF_PATH} 신규 생성 및 [${marker}] 블록 추가"
        return 0
    fi

    local backup="${MY_CNF_PATH}.bak_$(date '+%Y%m%d_%H%M%S')"
    cp -p "$MY_CNF_PATH" "$backup"

    local tmp; tmp="$(mktemp)"
    if grep -qF "$begin" "$MY_CNF_PATH"; then
        awk -v b="$begin" -v e="$end" -v content="$content" '
            $0==b {print; print content; skip=1; next}
            $0==e {print; skip=0; next}
            skip==1 {next}
            {print}
        ' "$MY_CNF_PATH" > "$tmp"
        log_info "${MY_CNF_PATH} 의 [${marker}] 블록 갱신 (백업: ${backup})"
    elif grep -qE '^\[mysqld\]' "$MY_CNF_PATH"; then
        awk -v b="$begin" -v e="$end" -v content="$content" '
            {print}
            /^\[mysqld\]/ && !done {print b; print content; print e; done=1}
        ' "$MY_CNF_PATH" > "$tmp"
        log_info "${MY_CNF_PATH} [mysqld] 섹션에 [${marker}] 블록 추가 (백업: ${backup})"
    else
        cat "$MY_CNF_PATH" > "$tmp"
        {
            echo ""
            echo "[mysqld]"
            echo "$begin"
            echo "$content"
            echo "$end"
        } >> "$tmp"
        log_info "${MY_CNF_PATH} 에 [mysqld] 섹션 및 [${marker}] 블록 추가 (백업: ${backup})"
    fi
    mv "$tmp" "$MY_CNF_PATH"
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
    os_type="$(get_mysql_os_type)"
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
        "양호")     exit "$KISA_EXIT_GOOD" ;;
        "취약")     exit "$KISA_EXIT_VULN" ;;
        "점검필요") exit "$KISA_EXIT_MANUAL" ;;
        *)          exit "$KISA_EXIT_ERROR" ;;
    esac
}
