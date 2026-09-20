#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-23"
readonly ITEM_TITLE="LDAP 알고리즘 적절하게 구성"
readonly ACTION_TAG="승인요청"
readonly IMPACT="다이제스트 알고리즘 변경 시 기존에 저장된 해시값과 불일치가 발생해 인증이 실패할 수 있음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local server_xml
    if ! server_xml="$(webdetect_tomcat_server_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat server.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$server_xml" ]; then
        CHECK_DETAIL="${server_xml} 를 읽을 수 없음."
        return "$KISA_EXIT_FAIL"
    fi
    if ! grep -qi 'LDAPRealm' "$server_xml" 2>/dev/null; then
        CHECK_DETAIL="LDAPRealm 설정 없음(해당 없음)."
        return "$KISA_EXIT_GOOD"
    fi
    local digest digest_lc
    digest="$(grep -i 'LDAPRealm' "$server_xml" 2>/dev/null | sed -n 's/.*digest="\([^"]*\)".*/\1/p' | head -n1)"
    digest_lc="$(printf '%s' "$digest" | tr '[:upper:]' '[:lower:]')"
    case "$digest_lc" in
        sha-256|sha256|sha-384|sha-512)
            CHECK_DETAIL="digest='${digest}' 안전함."
            return "$KISA_EXIT_GOOD"
            ;;
        *)
            CHECK_DETAIL="digest='${digest:-미설정}' 취약함."
            return "$KISA_EXIT_VULN"
            ;;
    esac
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

    local server_xml
    server_xml="$(webdetect_tomcat_server_xml 2>/dev/null)"

    if ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): digest 알고리즘 변경은 LDAP 디렉터리에 저장된 기존 해시값과 형식이 달라져 인증 실패를 유발할 수 있음. 승인 후 KISA_APPROVAL=true 로 재실행해도 자동 변경은 수행되지 않음."
        return 1
    fi

    FIX_DETAIL="digest 알고리즘 자동 변경은 기존 계정 인증 실패 위험이 있어 수행하지 않음. ${server_xml:-server.xml} 의 LDAPRealm digest 속성을 SHA-256 이상으로 변경하되, LDAP 디렉터리 서버 측 해시 저장 방식과의 호환 여부를 먼저 확인한 뒤 관리자가 직접 적용해야 함. 시스템 변경 없이 안내만 반환함."
    return 1
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-23 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
