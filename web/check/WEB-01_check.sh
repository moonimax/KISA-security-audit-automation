#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-01"
readonly ITEM_TITLE="Default 관리자 계정명 변경"
readonly ACTION_TAG="승인요청"
readonly IMPACT="관리자 계정명 변경 시 기존에 알고 있던 로그인 정보가 무효화되어 재접속 정보 갱신이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local users_xml
    if ! users_xml="$(webdetect_tomcat_users_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat tomcat-users.xml 을 찾을 수 없어 관리자 콘솔 계정이 존재하지 않는 것으로 판단됨(해당 서비스 없음). 양호."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$users_xml" ]; then
        CHECK_DETAIL="${users_xml} 파일을 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local weak_found=""
    while IFS= read -r line; do
        case "$line" in
            *manager-gui*|*manager-script*|*manager-jmx*|*manager-status*)
                local uname
                uname="$(printf '%s' "$line" | sed -n 's/.*username="\([^"]*\)".*/\1/p')"
                case "$(printf '%s' "$uname" | tr '[:upper:]' '[:lower:]')" in
                    tomcat|admin|manager|root|administrator)
                        weak_found="${weak_found}${uname} "
                        ;;
                esac
                ;;
        esac
    done < <(grep -i '<user ' "$users_xml" 2>/dev/null)

    if [ -n "$weak_found" ]; then
        CHECK_DETAIL="tomcat-users.xml(${users_xml}) 내 manager 역할을 가진 계정명이 기본/추측 용이 계정명(${weak_found% })으로 설정되어 있음."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="tomcat-users.xml(${users_xml}) 에 manager 역할을 가진 계정이 없거나, 계정명이 기본 계정명이 아님."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아(점검 사이 설정이 변경됨) 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
