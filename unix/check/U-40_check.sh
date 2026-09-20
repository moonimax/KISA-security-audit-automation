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
        if printf '%s' "$line" | grep -q 'no_root_squash'; then
            offenders+=("${path}(no_root_squash)")
        fi
    done <<< "$lines"

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="접근 통제가 미흡한 NFS 공유 설정 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="/etc/exports 의 모든 공유가 특정 호스트로 제한되어 있고 no_root_squash 옵션을 사용하지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
