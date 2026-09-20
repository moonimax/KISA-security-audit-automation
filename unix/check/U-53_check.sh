#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-53"
readonly ITEM_TITLE="FTP 서비스 정보 노출 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="배너 문구 변경 후 FTP 서비스 reload 가 필요해 관리자 승인이 필요함"
readonly SEVERITY="하"

CHECK_DETAIL=""

do_check() {
    local checked="false" offenders=()

    local vsftpd_conf="/etc/vsftpd.conf"
    [ -r "$vsftpd_conf" ] || vsftpd_conf="/etc/vsftpd/vsftpd.conf"
    if [ -r "$vsftpd_conf" ]; then
        checked="true"
        local banner_line banner_value
        banner_line="$(grep -E '^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*=' "$vsftpd_conf" 2>/dev/null | tail -n1)"
        if [ -z "$banner_line" ]; then
            offenders+=("${vsftpd_conf}(ftpd_banner 미설정, 기본 배너 사용)")
        else
            banner_value="${banner_line#*=}"
            if printf '%s' "$banner_value" | grep -Eqi '(vsftpd|proftpd|pure-?ftpd|[0-9]+\.[0-9]+([.][0-9]+)?)'; then
                offenders+=("${vsftpd_conf}(제품명 또는 버전 문자열 노출)")
            fi
        fi
    fi

    if [ -r /etc/proftpd/proftpd.conf ]; then
        checked="true"
        local val
        val="$(grep -Ei '^[[:space:]]*ServerIdent[[:space:]]' /etc/proftpd/proftpd.conf 2>/dev/null | tail -n1 | awk '{print tolower($2)}')"
        [ "$val" = "off" ] || offenders+=("/etc/proftpd/proftpd.conf(ServerIdent off 미설정)")
    fi

    if [ "$checked" = "false" ]; then
        CHECK_DETAIL="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="배너에 버전 정보가 노출될 수 있는 설정 발견: $(IFS='; '; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="설치된 FTP 서비스의 배너에 버전 정보 노출 설정이 없음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
