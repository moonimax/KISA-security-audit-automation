#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-24"
readonly ITEM_TITLE="별도의 업로드 경로 사용 및 권한 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="애플리케이션이 실제 사용하는 업로드 경로 파악이 필요해 지정된 경로 외에는 자동 판단이 불가능함"
readonly SEVERITY="중"

CHECK_DETAIL=""

find_writable_upload_dirs() {
    local root="$1"
    [ -d "$root" ] || return 0
    local d
    for d in uploads upload files; do
        local p="${root%/}/$d"
        if [ -d "$p" ]; then
            local perm
            perm="$(stat -c '%a' "$p" 2>/dev/null)"
            if [ -n "$perm" ]; then
                local other="${perm: -1}"
                case "$other" in
                    2|3|6|7) printf '%s(perm=%s)\n' "$p" "$perm" ;;
                esac
            fi
        fi
    done
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local found=""
    if webdetect_apache_present; then
        found="${found}$(find_writable_upload_dirs "$(webdetect_apache_docroot)")"$'\n'
    fi
    if webdetect_nginx_present; then
        found="${found}$(find_writable_upload_dirs "$(webdetect_nginx_docroot)")"$'\n'
    fi
    found="$(printf '%s' "$found" | grep -v '^$' || true)"

    if [ -n "$found" ]; then
        CHECK_DETAIL="문서 루트 바로 아래에 world-writable 권한의 업로드 디렉터리 후보가 있음(참고용, 실제 사용 경로는 관리자 확인 필요): $(printf '%s' "$found" | tr '\n' ' ')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="흔히 쓰이는 업로드 디렉터리명(uploads/upload/files) 중 world-writable 권한인 것을 찾지 못함(애플리케이션 고유 업로드 경로는 이 점검 범위 밖일 수 있음)."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
