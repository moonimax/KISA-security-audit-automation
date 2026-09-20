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
FIX_DETAIL=""

do_check() {
    local checked="false" offenders=()
    local vsftpd_conf="/etc/vsftpd.conf"
    [ -r "$vsftpd_conf" ] || vsftpd_conf="/etc/vsftpd/vsftpd.conf"
    if [ -r "$vsftpd_conf" ]; then
        checked="true"
        local val
        val="$(grep -E '^[[:space:]]*anonymous_enable[[:space:]]*=' "$vsftpd_conf" 2>/dev/null | tail -n1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
        [ "$val" = "yes" ] && offenders+=("${vsftpd_conf}(anonymous_enable=YES)")
    fi
    if [ -r /etc/proftpd/proftpd.conf ]; then
        checked="true"
        grep -Eq '^[[:space:]]*<Anonymous([[:space:]]|>)' /etc/proftpd/proftpd.conf 2>/dev/null && offenders+=("/etc/proftpd/proftpd.conf(<Anonymous> 블록 존재)")
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 서비스 재시작이 필요한 항목이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
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
        local val
        val="$(grep -E '^[[:space:]]*anonymous_enable[[:space:]]*=' "$vsftpd_conf" 2>/dev/null | tail -n1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
        if [ "$val" = "yes" ]; then
            local backup="${vsftpd_conf}.bak.$(date +%Y%m%d%H%M%S)"
            cp -p "$vsftpd_conf" "$backup" 2>/dev/null
            sed -i -E 's/^[[:space:]]*anonymous_enable[[:space:]]*=.*/anonymous_enable=NO/' "$vsftpd_conf"
            applied+=("${vsftpd_conf} anonymous_enable=NO (백업: ${backup})")
            if command -v systemctl >/dev/null 2>&1 && systemctl is-active vsftpd >/dev/null 2>&1; then
                systemctl restart vsftpd >/dev/null 2>&1 || { cp -p "$backup" "$vsftpd_conf"; FIX_DETAIL="vsftpd 재시작 실패로 롤백함."; return 2; }
            fi
        fi
    fi

    local proftpd_conf="/etc/proftpd/proftpd.conf"
    if [ -w "$proftpd_conf" ] && grep -Eq '^[[:space:]]*<Anonymous([[:space:]]|>)' "$proftpd_conf" 2>/dev/null; then
        local backup="${proftpd_conf}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$proftpd_conf" "$backup" 2>/dev/null || { FIX_DETAIL="proftpd 설정 백업 실패."; return 2; }
        sed -i -E '/^[[:space:]]*<Anonymous([[:space:]]|>)/,/^[[:space:]]*<\/Anonymous>/ s/^/# KISA-U35 disabled: /' "$proftpd_conf"
        if command -v proftpd >/dev/null 2>&1 && ! proftpd -t -c "$proftpd_conf" >/dev/null 2>&1; then
            cp -p "$backup" "$proftpd_conf"
            FIX_DETAIL="proftpd 설정 문법 검증 실패로 롤백함."
            return 2
        fi
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active proftpd >/dev/null 2>&1; then
            systemctl restart proftpd >/dev/null 2>&1 || { cp -p "$backup" "$proftpd_conf"; FIX_DETAIL="proftpd 재시작 실패로 설정을 롤백함."; return 2; }
        fi
        applied+=("${proftpd_conf} Anonymous 블록 비활성화(백업: ${backup})")
    fi

    local smb_conf="/etc/samba/smb.conf"
    if [ -w "$smb_conf" ]; then
        local need_fix="false"
        grep -Eiq '^[[:space:]]*guest[[:space:]]+ok[[:space:]]*=[[:space:]]*yes' "$smb_conf" 2>/dev/null && need_fix="true"
        grep -Eiq '^[[:space:]]*(map[[:space:]]+to[[:space:]]+guest)[[:space:]]*=[[:space:]]*(bad[[:space:]]user|bad[[:space:]]password)' "$smb_conf" 2>/dev/null && need_fix="true"
        if [ "$need_fix" = "true" ]; then
            local backup="${smb_conf}.bak.$(date +%Y%m%d%H%M%S)"
            cp -p "$smb_conf" "$backup" 2>/dev/null
            sed -i -E 's/^([[:space:]]*guest[[:space:]]+ok[[:space:]]*=).*/\1 no/I' "$smb_conf"
            sed -i -E 's/^([[:space:]]*map[[:space:]]+to[[:space:]]+guest[[:space:]]*=).*/\1 Never/I' "$smb_conf"

            local syntax_ok="true"
            if command -v testparm >/dev/null 2>&1; then
                testparm -s "$smb_conf" >/dev/null 2>&1 || syntax_ok="false"
            fi
            if [ "$syntax_ok" = "false" ]; then
                cp -p "$backup" "$smb_conf"
                log_error "smb.conf 문법 검증 실패, 백업본으로 롤백함."
                applied+=("${smb_conf} 변경이 testparm 검증에 실패하여 롤백함(백업: ${backup})")
            else
                applied+=("${smb_conf} guest ok=no, map to guest=Never (백업: ${backup})")
                if command -v systemctl >/dev/null 2>&1; then
                    local svc
                    for svc in smb smbd; do
                        if systemctl is-active "$svc" >/dev/null 2>&1; then
                            systemctl restart "$svc" >/dev/null 2>&1 || { FIX_DETAIL="Samba 재시작 실패($svc)."; return 2; }
                        fi
                    done
                fi
            fi
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
log_info "U-35 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
