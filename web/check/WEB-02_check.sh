#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-02"
readonly ITEM_TITLE="취약한 비밀번호 사용 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="비밀번호 변경 시 기존 관리자 세션 및 자동화 스크립트가 사용하던 인증 정보가 무효화됨"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local users_xml
    if ! users_xml="$(webdetect_tomcat_users_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat tomcat-users.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$users_xml" ]; then
        CHECK_DETAIL="${users_xml} 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local weak_found="" manager_found="false"
    while IFS= read -r line; do
        case "$line" in
            *manager-gui*|*manager-script*|*manager-jmx*|*manager-status*)
                manager_found="true"
                local uname pass
                uname="$(printf '%s' "$line" | sed -n 's/.*username="\([^"]*\)".*/\1/p')"
                pass="$(printf '%s' "$line" | sed -n 's/.*password="\([^"]*\)".*/\1/p')"
                local pass_lc
                pass_lc="$(printf '%s' "$pass" | tr '[:upper:]' '[:lower:]')"
                if [ -z "$pass" ] || [ "$pass" = "$uname" ]; then
                    weak_found="${weak_found}${uname}(공백/계정명과동일) "
                else
                    case "$pass_lc" in
                        tomcat|admin|password|123456|changeit|manager|admin123|tomcat123|s3cret)
                            weak_found="${weak_found}${uname}(알려진취약값) "
                            ;;
                        *)
                            if [ "${#pass}" -lt 8 ]; then
                                weak_found="${weak_found}${uname}(8자미만) "
                            fi
                            ;;
                    esac
                fi
                ;;
        esac
    done < <(grep -i '<user ' "$users_xml" 2>/dev/null)

    if [ -n "$weak_found" ]; then
        CHECK_DETAIL="tomcat-users.xml(${users_xml}) 의 manager 역할 계정 중 취약한 비밀번호 사용: ${weak_found% }"
        return "$KISA_EXIT_VULN"
    fi
    if [ "$manager_found" = "false" ]; then
        CHECK_DETAIL="tomcat-users.xml(${users_xml}) 에 manager 역할을 가진 계정이 없음. 양호."
    else
        CHECK_DETAIL="tomcat-users.xml(${users_xml}) 의 manager 역할 계정 비밀번호가 복잡도 기준을 만족함."
    fi
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
