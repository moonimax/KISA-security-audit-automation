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
CHECK_EVIDENCE=""

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
    CHECK_EVIDENCE="$(evidence_json \
        "설정 파일" "$LOGIN_DEFS, $PWQUALITY_CONF" \
        "최대 사용 기간" "${max_days:-미설정}" \
        "최소 사용 기간" "${min_days:-미설정}" \
        "최소 길이" "${min_len:-미설정}" \
        "문자 클래스" "${min_class:-미설정}" \
        "최근 비밀번호 기억" "${history:-미적용}")"
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

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY" "$CHECK_EVIDENCE"
