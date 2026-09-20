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
FIX_DETAIL=""

do_check() {
    local checked="false" offenders=()
    local vsftpd_conf="/etc/vsftpd.conf"
    [ -r "$vsftpd_conf" ] || vsftpd_conf="/etc/vsftpd/vsftpd.conf"
    if [ -r "$vsftpd_conf" ]; then
        checked="true"
        local banner_line banner_value
        banner_line="$(grep -E '^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*=' "$vsftpd_conf" 2>/dev/null | tail -n1)"
        if [ -z "$banner_line" ]; then
            offenders+=("${vsftpd_conf}(배너 미설정)")
        else
            banner_value="${banner_line#*=}"
            printf '%s' "$banner_value" | grep -Eqi '(vsftpd|proftpd|pure-?ftpd|[0-9]+\.[0-9]+([.][0-9]+)?)' \
                && offenders+=("${vsftpd_conf}(제품명/버전 노출)")
        fi
    fi
    if [ -r /etc/proftpd/proftpd.conf ]; then
        checked="true"
        local val
        val="$(grep -Ei '^[[:space:]]*ServerIdent[[:space:]]' /etc/proftpd/proftpd.conf 2>/dev/null | tail -n1 | awk '{print tolower($2)}')"
        [ "$val" = "off" ] || offenders+=("/etc/proftpd/proftpd.conf")
    fi
    if [ "$checked" = "false" ]; then
        CHECK_DETAIL="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="배너에 버전 정보가 노출될 수 있는 설정 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="설치된 FTP 서비스의 배너에 버전 정보 노출 설정이 없음."
    return "$KISA_EXIT_GOOD"
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
    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 서비스 reload 가 필요한 항목이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=()
    local vsftpd_conf="/etc/vsftpd.conf"
    [ -r "$vsftpd_conf" ] || vsftpd_conf="/etc/vsftpd/vsftpd.conf"
    if [ -w "$vsftpd_conf" ]; then
        local banner_line banner_value needs_banner_fix=false
        banner_line="$(grep -E '^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*=' "$vsftpd_conf" 2>/dev/null | tail -n1)"
        [ -z "$banner_line" ] && needs_banner_fix=true
        banner_value="${banner_line#*=}"
        printf '%s' "$banner_value" | grep -Eqi '(vsftpd|proftpd|pure-?ftpd|[0-9]+\.[0-9]+([.][0-9]+)?)' \
            && needs_banner_fix=true
        if [ "$needs_banner_fix" = true ]; then
        local backup="${vsftpd_conf}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$vsftpd_conf" "$backup" 2>/dev/null
        sed -i -E '/^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*=/d' "$vsftpd_conf"
        printf '\nftpd_banner=Authorized users only. Unauthorized access is prohibited.\n' >> "$vsftpd_conf"
        applied+=("${vsftpd_conf} ftpd_banner 커스텀 문구 설정 (백업: ${backup})")
        restart_active_services vsftpd || { FIX_DETAIL="vsftpd 재시작 실패."; return 2; }
        fi
    fi

    if [ -w /etc/proftpd/proftpd.conf ]; then
        local val
        val="$(grep -Ei '^[[:space:]]*ServerIdent[[:space:]]' /etc/proftpd/proftpd.conf 2>/dev/null | tail -n1 | awk '{print tolower($2)}')"
        if [ "$val" != "off" ]; then
            local backup="/etc/proftpd/proftpd.conf.bak.$(date +%Y%m%d%H%M%S)"
            cp -p /etc/proftpd/proftpd.conf "$backup" 2>/dev/null
            if grep -Eiq '^[[:space:]]*ServerIdent[[:space:]]' /etc/proftpd/proftpd.conf; then
                sed -i -E 's/^([[:space:]]*ServerIdent[[:space:]]+).*/\1off/I' /etc/proftpd/proftpd.conf
            else
                printf '\nServerIdent off\n' >> /etc/proftpd/proftpd.conf
            fi
            applied+=("/etc/proftpd/proftpd.conf ServerIdent off (백업: ${backup})")
            restart_active_services proftpd || { FIX_DETAIL="proftpd 재시작 실패."; return 2; }
        fi
    fi

    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상 설정 파일에 쓰기 권한이 없거나 대상을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 2
    fi
    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}")"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-53 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
