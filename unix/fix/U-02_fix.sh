#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-02"
readonly ITEM_TITLE="비밀번호 관리정책 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="설정 파일(login.defs, pwquality.conf) 값만 변경되며 서비스 재시작이 불필요함. 기존 로그인 세션에는 영향이 없고, 신규 비밀번호 변경 시점부터 정책이 적용됨"
readonly SEVERITY="상"

readonly LOGIN_DEFS="/etc/login.defs"
readonly PWQUALITY_CONF="/etc/security/pwquality.conf"
readonly PWHISTORY_CONF="/etc/security/pwhistory.conf"
readonly MAX_DAYS_LIMIT=90
readonly MIN_DAYS_LIMIT=1
readonly MIN_LEN_LIMIT=8
readonly MIN_CLASS_LIMIT=3
readonly HISTORY_LIMIT=4

CHECK_DETAIL=""
FIX_DETAIL=""

_conf_value() {
    local file="$1" key="$2"
    [ -r "$file" ] || return 1
    awk -F= -v key="$key" '
        $0 !~ /^[[:space:]]*#/ {
            lhs=$1; gsub(/[[:space:]]/,"",lhs)
            if (lhs==key) { v=$2; gsub(/[[:space:]]/,"",v); print v; exit }
        }' "$file"
}

_password_history_value() {
    local f line value=""
    for f in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password; do
        [ -r "$f" ] || continue
        line="$(grep -E '^[[:space:]]*password[[:space:]].*(pam_pwhistory|pam_unix)\\.so' "$f" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"
        [ -n "$line" ] || continue
        value="$(printf '%s' "$line" | grep -oE 'remember[[:space:]]*=[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -n1)"
        if printf '%s' "$line" | grep -q 'pam_pwhistory\\.so' && [ -z "$value" ]; then
            value="$(_conf_value "$PWHISTORY_CONF" remember)"
        fi
        [ -n "$value" ] && { printf '%s' "$value"; return 0; }
    done
    return 1
}

do_check() {
    [ -r "$LOGIN_DEFS" ] || { CHECK_DETAIL="${LOGIN_DEFS}를 읽을 수 없어 판정이 불가능함."; return "$KISA_EXIT_FAIL"; }
    local max_days min_days min_len min_class history
    max_days="$(awk '/^[[:space:]]*PASS_MAX_DAYS[[:space:]]/{print $2; exit}' "$LOGIN_DEFS")"
    min_days="$(awk '/^[[:space:]]*PASS_MIN_DAYS[[:space:]]/{print $2; exit}' "$LOGIN_DEFS")"
    min_len="$(_conf_value "$PWQUALITY_CONF" minlen)"
    [ -n "$min_len" ] || min_len="$(awk '/^[[:space:]]*PASS_MIN_LEN[[:space:]]/{print $2; exit}' "$LOGIN_DEFS")"
    min_class="$(_conf_value "$PWQUALITY_CONF" minclass)"
    history="$(_password_history_value)"
    local reasons=()
    [[ "$max_days" =~ ^[0-9]+$ ]] && [ "$max_days" -le "$MAX_DAYS_LIMIT" ] || reasons+=("최대 사용기간=${max_days:-미설정}(90일 이하 필요)")
    [[ "$min_days" =~ ^[0-9]+$ ]] && [ "$min_days" -ge "$MIN_DAYS_LIMIT" ] || reasons+=("최소 사용기간=${min_days:-미설정}(1일 이상 필요)")
    [[ "$min_len" =~ ^[0-9]+$ ]] && [ "$min_len" -ge "$MIN_LEN_LIMIT" ] || reasons+=("최소 길이=${min_len:-미설정}(8자 이상 필요)")
    [[ "$min_class" =~ ^[0-9]+$ ]] && [ "$min_class" -ge "$MIN_CLASS_LIMIT" ] || reasons+=("문자 클래스=${min_class:-미설정}(3종 이상 필요)")
    [[ "$history" =~ ^[0-9]+$ ]] && [ "$history" -ge "$HISTORY_LIMIT" ] || reasons+=("최근 비밀번호 기억=${history:-미적용}(4회 이상 및 PAM 연동 필요)")
    if [ "${#reasons[@]}" -eq 0 ]; then
        CHECK_DETAIL="PASS_MIN_DAYS=$min_days, PASS_MAX_DAYS=$max_days, minlen=$min_len, minclass=$min_class, remember=$history로 기준 충족."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="비밀번호 관리정책 미흡: $(IFS='; '; echo "${reasons[*]}")"
    return "$KISA_EXIT_VULN"
}

_set_login_defs_value() {
    local key="$1" value="$2"
    if grep -qE "^[[:space:]]*${key}[[:space:]]" "$LOGIN_DEFS"; then
        sed -i -E "s/^[[:space:]]*${key}[[:space:]]+.*/${key}   ${value}/" "$LOGIN_DEFS"
    else
        printf '%s\t%s\n' "$key" "$value" >> "$LOGIN_DEFS"
    fi
}

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."
        return 0
    fi
    if [ "$current" -eq "$KISA_EXIT_FAIL" ]; then
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."
        return 2
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local backup="${LOGIN_DEFS}.bak.$(date +%Y%m%d%H%M%S)"
    if ! cp -p "$LOGIN_DEFS" "$backup" 2>/dev/null; then
        FIX_DETAIL="설정 파일 백업 실패로 조치를 중단함."
        return 2
    fi
    log_info "login.defs 백업 완료: ${backup}"

    _set_login_defs_value "PASS_MAX_DAYS" "$MAX_DAYS_LIMIT"
    _set_login_defs_value "PASS_MIN_DAYS" "$MIN_DAYS_LIMIT"
    _set_login_defs_value "PASS_MIN_LEN" "$MIN_LEN_LIMIT"

    local pwq_note="pwquality.conf 미존재(login.defs PASS_MIN_LEN 만 적용)"
    if [ -w "$PWQUALITY_CONF" ] || { [ ! -e "$PWQUALITY_CONF" ] && [ -w "$(dirname "$PWQUALITY_CONF")" ]; }; then
        [ -e "$PWQUALITY_CONF" ] && cp -p "$PWQUALITY_CONF" "${PWQUALITY_CONF}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null
        touch "$PWQUALITY_CONF" 2>/dev/null
        if grep -qE '^[[:space:]]*minlen[[:space:]]*=' "$PWQUALITY_CONF" 2>/dev/null; then
            sed -i -E "s/^[[:space:]]*minlen[[:space:]]*=.*/minlen = ${MIN_LEN_LIMIT}/" "$PWQUALITY_CONF"
        else
            printf 'minlen = %s\n' "$MIN_LEN_LIMIT" >> "$PWQUALITY_CONF"
        fi
        pwq_note="pwquality.conf minlen=${MIN_LEN_LIMIT} 적용"
        if grep -qE '^[[:space:]]*minclass[[:space:]]*=' "$PWQUALITY_CONF"; then
            sed -i -E "s/^[[:space:]]*minclass[[:space:]]*=.*/minclass = ${MIN_CLASS_LIMIT}/" "$PWQUALITY_CONF"
        else
            printf 'minclass = %s\n' "$MIN_CLASS_LIMIT" >> "$PWQUALITY_CONF"
        fi
    fi

    local history_note="PAM 비밀번호 이력 모듈 미연동"
    if [ -d "$(dirname "$PWHISTORY_CONF")" ]; then
        touch "$PWHISTORY_CONF" 2>/dev/null || { FIX_DETAIL="${PWHISTORY_CONF} 생성 실패."; return 2; }
        if grep -qE '^[[:space:]]*remember[[:space:]]*=' "$PWHISTORY_CONF"; then
            sed -i -E "s/^[[:space:]]*remember[[:space:]]*=.*/remember = ${HISTORY_LIMIT}/" "$PWHISTORY_CONF"
        else
            printf 'remember = %s\n' "$HISTORY_LIMIT" >> "$PWHISTORY_CONF"
        fi
        if grep -RqsE '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so|^[[:space:]]*password[[:space:]].*pam_unix\.so.*remember[[:space:]]*=' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null; then
            history_note="최근 비밀번호 ${HISTORY_LIMIT}회 기억 정책 적용 및 PAM 연동 확인"
        fi
    fi

    FIX_DETAIL="PASS_MIN_DAYS=${MIN_DAYS_LIMIT}, PASS_MAX_DAYS=${MAX_DAYS_LIMIT}, PASS_MIN_LEN=${MIN_LEN_LIMIT}, minclass=${MIN_CLASS_LIMIT}로 설정하고 ${pwq_note}; ${history_note}. 백업: ${backup}"
    [ "$history_note" != "PAM 비밀번호 이력 모듈 미연동" ] || return 1
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-02 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
