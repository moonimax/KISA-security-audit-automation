#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-35"
readonly ITEM_TITLE="공유 서비스에 대한 익명 접근 제한 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="FTP/Samba 설정 변경 후 서비스 재시작이 필요하며, 실제로 익명/guest 접속을 이용해 파일을 배포 중인 운영 환경이라면 서비스 중단으로 이어질 수 있어 관리자 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local checked="false" offenders=()

    local vsftpd_conf="/etc/vsftpd.conf"
    [ -r "$vsftpd_conf" ] || vsftpd_conf="/etc/vsftpd/vsftpd.conf"
    if [ -r "$vsftpd_conf" ]; then
        checked="true"
        local val
        val="$(grep -E '^[[:space:]]*anonymous_enable[[:space:]]*=' "$vsftpd_conf" 2>/dev/null | tail -n1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
        if [ "$val" = "yes" ]; then
            offenders+=("${vsftpd_conf}(anonymous_enable=YES)")
        fi
    fi

    if [ -r /etc/proftpd/proftpd.conf ]; then
        checked="true"
        if grep -Eq '^[[:space:]]*<Anonymous([[:space:]]|>)' /etc/proftpd/proftpd.conf 2>/dev/null; then
            offenders+=("/etc/proftpd/proftpd.conf(<Anonymous> 블록 존재)")
        fi
    fi

    local smb_conf="/etc/samba/smb.conf"
    if [ -r "$smb_conf" ]; then
        checked="true"
        if grep -Eiq '^[[:space:]]*(map[[:space:]]+to[[:space:]]+guest)[[:space:]]*=[[:space:]]*(bad[[:space:]]user|bad[[:space:]]password)' "$smb_conf" 2>/dev/null \
            || grep -Eiq '^[[:space:]]*guest[[:space:]]+ok[[:space:]]*=[[:space:]]*yes' "$smb_conf" 2>/dev/null; then
            offenders+=("${smb_conf}(guest 접근 허용 설정)")
        fi
    fi

    if [ "$checked" = "false" ]; then
        CHECK_DETAIL="FTP(vsftpd/proftpd), Samba 어느 것도 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="익명/guest 접근이 허용된 공유 서비스 설정 발견: $(IFS='; '; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="설치된 공유 서비스에서 익명/guest 접근이 허용되어 있지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
