#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-04"
readonly ITEM_TITLE="비밀번호 파일 보호"
readonly ACTION_TAG="승인요청"
readonly IMPACT="pwconv 실행은 시스템 전체 계정의 인증 정보를 passwd -> shadow 체계로 변환하는 작업으로, 변환 중 오류 발생 시 전 계정 로그인 장애로 이어질 수 있는 고위험 작업임"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    if [ ! -e /etc/shadow ]; then
        CHECK_DETAIL="/etc/shadow 파일이 존재하지 않음."
        return "$KISA_EXIT_VULN"
    fi
    local bad_count
    bad_count="$(awk -F: '$2!="x" && $2!="*" {c++} END{print c+0}' /etc/passwd)"
    if [ "$bad_count" -gt 0 ]; then
        CHECK_DETAIL="/etc/passwd 에 shadow('x') 미사용 계정이 ${bad_count}건 존재함."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="/etc/shadow 존재하며 모든 계정이 shadow 체계('x')를 사용 중임."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): pwconv 는 전체 계정 인증 정보를 변환하는 고위험 작업이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하거나, 사전에 /etc/passwd, /etc/shadow, /etc/group 을 백업한 뒤 수동으로 'pwconv' 실행을 검토하세요."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if ! command -v pwconv >/dev/null 2>&1; then
        FIX_DETAIL="pwconv 명령을 찾을 수 없어 조치를 수행할 수 없음(shadow-utils 패키지 필요)."
        return 2
    fi

    local ts backup_dir
    ts="$(date +%Y%m%d%H%M%S)"
    backup_dir="/var/backups/kisa_u04_${ts}"
    mkdir -p "$backup_dir" 2>/dev/null || { FIX_DETAIL="백업 디렉토리(${backup_dir}) 생성 실패로 조치를 중단함."; return 2; }

    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
        [ -e "$f" ] && cp -p "$f" "$backup_dir/" 2>/dev/null
    done
    log_info "passwd/shadow 관련 파일 백업 완료: ${backup_dir}"

    if pwconv 2>/dev/null; then
        FIX_DETAIL="pwconv 실행으로 shadow 패스워드 체계를 적용함. 백업: ${backup_dir}"
        return 0
    fi

    FIX_DETAIL="pwconv 실행이 실패함. 백업(${backup_dir})을 확인하여 수동 복구가 필요할 수 있음."
    return 2
}

do_fix
KISA_FIX_RC=$?
log_info "U-04 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
