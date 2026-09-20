#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-40"
readonly ITEM_TITLE="NFS 접근 통제"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 호스트를 허용할지는 실제 NFS 클라이언트 목록에 대한 관리자 판단이 반드시 필요하며, /etc/exports 변경 후 exportfs -ra 재적용이 필요해 기존 마운트 클라이언트의 접근이 일시적으로 영향을 받을 수 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/exports ]; then
        CHECK_DETAIL="/etc/exports 파일이 없어 NFS 공유 미사용으로 판단됨. 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local lines
    lines="$(grep -vE '^[[:space:]]*(#|$)' /etc/exports 2>/dev/null)"
    if [ -z "$lines" ]; then
        CHECK_DETAIL="/etc/exports 에 유효한 공유 설정이 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local offenders=()
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local path host_part
        path="$(awk '{print $1}' <<< "$line")"
        host_part="$(sed -E "s|^${path//|/\\|}[[:space:]]*||" <<< "$line")"
        if [ -z "$host_part" ] || printf '%s' "$host_part" | grep -qE '(^|[[:space:]])\*(\(|[[:space:]]|$)'; then
            offenders+=("${path}(전체 호스트 허용)")
        fi
        printf '%s' "$line" | grep -q 'no_root_squash' && offenders+=("${path}(no_root_squash)")
    done <<< "$lines"

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="접근 통제가 미흡한 NFS 공유 설정 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="/etc/exports 의 모든 공유가 특정 호스트로 제한되어 있고 no_root_squash 옵션을 사용하지 않음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 허용 호스트 지정 및 exportfs 재적용이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요(전체 호스트 개방 라인을 특정 호스트로 좁히려면 KISA_U40_ALLOWED_HOSTS 도 함께 지정)."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if [ ! -w /etc/exports ]; then
        FIX_DETAIL="/etc/exports 에 쓰기 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local backup="/etc/exports.bak.$(date +%Y%m%d%H%M%S)"
    cp -p /etc/exports "$backup" 2>/dev/null
    log_info "/etc/exports 백업 완료: ${backup}"

    local applied=()

    if grep -q 'no_root_squash' /etc/exports; then
        sed -i 's/no_root_squash/root_squash/g' /etc/exports
        applied+=("no_root_squash -> root_squash 로 전환")
    fi

    if [ -n "${KISA_U40_ALLOWED_HOSTS:-}" ] && grep -qE '(^|[[:space:]])\*(\(|[[:space:]]|$)' /etc/exports; then
        local hosts
        hosts="$(printf '%s' "$KISA_U40_ALLOWED_HOSTS" | tr ',' ' ')"
        sed -i -E "s/(^|[[:space:]])\*(\(|[[:space:]]|\$)/\1${hosts}\2/g" /etc/exports
        applied+=("전체 호스트 개방('*') 라인을 '${hosts}' 로 제한")
    elif grep -qE '(^|[[:space:]])\*(\(|[[:space:]]|$)' /etc/exports; then
        applied+=("전체 호스트 개방('*') 라인은 KISA_U40_ALLOWED_HOSTS 미지정으로 변경하지 않음(수동 조치 필요)")
    fi

    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상 라인을 다시 조회했으나 발견되지 않음(경합 상태 가능). 백업: ${backup}"
        return 0
    fi

    if command -v exportfs >/dev/null 2>&1; then
        if exportfs -ra 2>/dev/null; then
            applied+=("exportfs -ra 재적용 완료")
        else
            cp -p "$backup" /etc/exports
            exportfs -ra 2>/dev/null
            FIX_DETAIL="변경된 /etc/exports 가 exportfs -ra 적용에 실패하여 백업본(${backup})으로 롤백함."
            return 2
        fi
    fi

    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}") (백업: ${backup})"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-40 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
