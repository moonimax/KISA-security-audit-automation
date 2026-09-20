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
        CHECK_DETAIL="${f} 에 root 계정이 등재되어 있어 FTP 직접 로그인이 차단됨."
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="${f} 에 root 계정이 등재되어 있지 않아 root 의 FTP 직접 로그인이 가능함."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
