#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-62"
readonly ITEM_TITLE="로그인 시 경고 메시지 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="로그인 및 사용 중 서비스 배너 변경·재시작이 필요할 수 있어 관리자 승인이 필요함"
readonly SEVERITY="하"

CHECK_DETAIL=""

_has_warning_text() {
    [ -r "$1" ] && grep -Eqi '(unauthori[sz]ed|authorized users only|prohibited|monitored|경고|무단|접근[[:space:]]*금지|모니터링)' "$1"
}
_service_banner_gaps() {
    local gaps=() conf
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active vsftpd >/dev/null 2>&1; then
        conf=/etc/vsftpd.conf; [ -r "$conf" ] || conf=/etc/vsftpd/vsftpd.conf
        grep -Eqi '^[[:space:]]*ftpd_banner[[:space:]]*=.*(warning|unauthor|경고|무단)' "$conf" 2>/dev/null || gaps+=("vsftpd")
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active proftpd >/dev/null 2>&1; then
        grep -Eqi '^[[:space:]]*(DisplayLogin|ServerIdent)' /etc/proftpd/proftpd.conf 2>/dev/null || gaps+=("proftpd")
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active postfix >/dev/null 2>&1; then
        grep -Eqi '^[[:space:]]*smtpd_banner[[:space:]]*=.*(warning|unauthor|경고|무단)' /etc/postfix/main.cf 2>/dev/null || gaps+=("SMTP")
    fi
    if command -v systemctl >/dev/null 2>&1 && { systemctl is-active named >/dev/null 2>&1 || systemctl is-active bind9 >/dev/null 2>&1; }; then
        grep -RhEqi '^[[:space:]]*version[[:space:]]+"(not disclosed|unknown|restricted)"' /etc/named.conf /etc/bind 2>/dev/null || gaps+=("DNS")
    fi
    printf '%s' "$(IFS=','; echo "${gaps[*]}")"
}
do_check() {
    local missing=() f
    for f in /etc/motd /etc/issue /etc/issue.net; do _has_warning_text "$f" || missing+=("$f"); done
    local gaps="$(_service_banner_gaps)"; [ -z "$gaps" ] || missing+=("서비스 배너:$gaps")
    if [ "${#missing[@]}" -gt 0 ]; then CHECK_DETAIL="실제 경고 문구 또는 사용 중 서비스 배너 누락: $(IFS=','; echo "${missing[*]}")"; return "$KISA_EXIT_VULN"; fi
    CHECK_DETAIL="콘솔/원격 로그인 경고문과 사용 중인 FTP·SMTP·DNS 서비스 배너 기준 충족."; return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
