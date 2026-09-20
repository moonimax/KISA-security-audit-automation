#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-57"
readonly ITEM_TITLE="Ftpusers 파일 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="ftpusers 파일에 root 를 한 줄 추가하는 단순 변경으로, FTP 데몬은 매 연결마다 이 파일을 다시 읽으므로 서비스 재시작이 불필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

_find_ftpusers() {
    for f in /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/ftpusers; do
        [ -r "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

_ftp_installed() {
    { [ -r /etc/vsftpd.conf ] || [ -r /etc/vsftpd/vsftpd.conf ] || [ -r /etc/proftpd/proftpd.conf ]; }
}

do_check() {
    if ! _ftp_installed; then
        CHECK_DETAIL="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local f
    f="$(_find_ftpusers)" || {
        CHECK_DETAIL="FTP 서비스는 설치되어 있으나 ftpusers 파일을 찾을 수 없어 root 계정 차단 여부를 확인할 수 없음(취약으로 판단)."
        return "$KISA_EXIT_VULN"
    }
    if grep -Eq '^[[:space:]]*root[[:space:]]*$' "$f" 2>/dev/null; then
        CHECK_DETAIL="${f} 에 root 계정이 등재되어 있음."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="${f} 에 root 계정이 등재되어 있지 않음."
    return "$KISA_EXIT_VULN"
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

    local target_file
    target_file="$(_find_ftpusers)"
    if [ -z "$target_file" ]; then
        if [ -r /etc/vsftpd.conf ] || [ -r /etc/vsftpd/vsftpd.conf ]; then
            target_file="/etc/vsftpd.ftpusers"
            [ -d /etc/vsftpd ] && target_file="/etc/vsftpd/ftpusers"
        else
            target_file="/etc/ftpusers"
        fi
    fi

    if [ -e "$target_file" ]; then
        local backup="${target_file}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$target_file" "$backup" 2>/dev/null
    fi

    if ! grep -Eq '^[[:space:]]*root[[:space:]]*$' "$target_file" 2>/dev/null; then
        printf 'root\n' >> "$target_file"
    fi

    if grep -Eq '^[[:space:]]*root[[:space:]]*$' "$target_file" 2>/dev/null; then
        FIX_DETAIL="${target_file} 에 root 계정을 추가하여 FTP 직접 로그인을 차단함."
        return 0
    fi

    FIX_DETAIL="${target_file} 에 root 계정 추가를 시도했으나 반영되지 않음(쓰기 권한 확인 필요)."
    return 2
}

do_fix
KISA_FIX_RC=$?
log_info "U-57 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
