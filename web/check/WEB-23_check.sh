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

do_check() {
    local server_xml
    if ! server_xml="$(webdetect_tomcat_server_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat server.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$server_xml" ]; then
        CHECK_DETAIL="${server_xml} 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    if ! grep -qi 'LDAPRealm' "$server_xml" 2>/dev/null; then
        CHECK_DETAIL="${server_xml} 에 LDAPRealm 설정이 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local digest digest_lc
    digest="$(grep -i 'LDAPRealm' "$server_xml" 2>/dev/null | sed -n 's/.*digest="\([^"]*\)".*/\1/p' | head -n1)"
    digest_lc="$(printf '%s' "$digest" | tr '[:upper:]' '[:lower:]')"

    case "$digest_lc" in
        sha-256|sha256|sha-384|sha-512)
            CHECK_DETAIL="${server_xml} 의 LDAPRealm digest='${digest}' 로 SHA-256 이상 사용 중."
            return "$KISA_EXIT_GOOD"
            ;;
        *)
            CHECK_DETAIL="${server_xml} 의 LDAPRealm digest='${digest:-미설정}' 로 안전한(SHA-256 이상) 알고리즘이 아님."
            return "$KISA_EXIT_VULN"
            ;;
    esac
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
