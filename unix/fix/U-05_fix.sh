#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-05"
readonly ITEM_TITLE="root 이외의 UID가 '0' 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="UID 0 계정을 삭제하거나 UID를 변경하는 작업이며, 해당 계정이 실제로 사용 중인 프로세스/파일 소유권과 얽혀 있을 경우 서비스 장애나 권한 문제를 유발할 수 있는 파괴적 변경임"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local extra_root_accounts
    extra_root_accounts="$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')"
    if [ -n "$extra_root_accounts" ]; then
        CHECK_DETAIL="root 외 UID 0 계정 발견: ${extra_root_accounts}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="UID 0 을 가진 계정은 root 뿐임."
    return "$KISA_EXIT_GOOD"
}

do_fix() {
    do_check
    local current=$?
    [ "$current" -eq "$KISA_EXIT_GOOD" ] && { FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."; return 0; }
    [ "$current" -eq "$KISA_EXIT_FAIL" ] && { FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."; return 2; }
    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요. 승인 후 KISA_U05_UID_MAP='계정:새UID,...'와 KISA_APPROVAL=true를 함께 지정해야 UID 0 자체를 제거함."
        return 1
    fi
    require_root || { FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."; return 2; }
    local mapping="${KISA_U05_UID_MAP:-}"
    if [ -z "$mapping" ]; then
        FIX_DETAIL="부분 조치/수동 조치 필요: UID 변경값을 추정하지 않음. KISA_U05_UID_MAP='계정:새UID,...'를 지정해야 함."
        return 1
    fi

    local accounts changed="" missing="" failed=""
    accounts="$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)"
    while IFS= read -r acct; do
        [ -n "$acct" ] || continue
        local new_uid=""
        IFS=',' read -r -a pairs <<< "$mapping"
        local pair
        for pair in "${pairs[@]}"; do
            [ "${pair%%:*}" = "$acct" ] && new_uid="${pair#*:}"
        done
        if ! [[ "$new_uid" =~ ^[1-9][0-9]*$ ]] || getent passwd "$new_uid" >/dev/null 2>&1; then
            missing="${missing}${missing:+,}$acct"
            continue
        fi
        if command -v usermod >/dev/null 2>&1 && usermod -u "$new_uid" "$acct" 2>/dev/null; then
            changed="${changed}${changed:+,}$acct:$new_uid"
        else
            failed="${failed}${failed:+,}$acct"
        fi
    done <<< "$accounts"

    if [ -n "$failed" ]; then
        FIX_DETAIL="UID 변경 실패 계정: $failed. 변경 완료: ${changed:-없음}."
        return 2
    fi
    if [ -n "$missing" ]; then
        FIX_DETAIL="부분 조치/수동 조치 필요: UID 매핑이 없거나 유효하지 않은 계정: $missing. 변경 완료: ${changed:-없음}."
        return 1
    fi
    FIX_DETAIL="root 외 UID 0 계정의 UID를 실제로 변경함: $changed. 파일 소유권은 usermod가 홈 외부까지 모두 바꾸지 않으므로 관리자가 잔여 UID 0 소유 파일을 별도 확인해야 함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-05 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
