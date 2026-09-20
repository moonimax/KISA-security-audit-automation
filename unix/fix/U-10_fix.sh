#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-10"
readonly ITEM_TITLE="동일한 UID 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="usermod -u 로 UID를 변경하면 해당 UID로 소유된 기존 파일들의 소유권이 자동으로 갱신되지 않아 파일 소유권 불일치가 발생할 수 있음. 어떤 계정의 UID를 남기고 어떤 계정을 변경할지도 관리자 판단이 필요한 파괴적 변경임"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local dup_uids
    dup_uids="$(awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d | tr '\n' ',' | sed 's/,$//')"
    if [ -n "$dup_uids" ]; then
        local dup_accounts
        dup_accounts="$(awk -F: -v duplist=",$dup_uids," 'index(duplist, ","$3",") {print $1"(uid="$3")"}' /etc/passwd | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="중복된 UID 발견(${dup_uids}): ${dup_accounts}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="모든 계정의 UID가 고유함."
    return "$KISA_EXIT_GOOD"
}

_find_free_uid() {
    local start used_list candidate
    start="$1"
    used_list="$2"
    candidate="$start"
    while printf ' %s ' "$used_list" | grep -q " ${candidate} "; do
        candidate=$((candidate + 1))
    done
    printf '%s' "$candidate"
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 어떤 계정의 UID를 유지/변경할지 판단이 필요하고 UID 변경은 파일 소유권 정합성에 영향을 주는 파괴적 변경이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if ! command -v usermod >/dev/null 2>&1; then
        FIX_DETAIL="usermod 명령을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    fi

    local dup_uids
    dup_uids="$(awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d)"
    if [ -z "$dup_uids" ]; then
        FIX_DETAIL="조치 대상 중복 UID를 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local used_uids
    used_uids="$(awk -F: '{print $3}' /etc/passwd | sort -n -u | tr '\n' ' ')"

    local backup="/etc/passwd.bak.$(date +%Y%m%d%H%M%S)"
    cp -p /etc/passwd "$backup" 2>/dev/null
    log_info "/etc/passwd 백업 완료: ${backup}"

    local changed_list="" failed_list="" manual_home_notes=""

    while IFS= read -r uid; do
        [ -z "$uid" ] && continue
        local accounts_with_uid first_kept=1
        accounts_with_uid="$(awk -F: -v u="$uid" '$3==u {print $1}' /etc/passwd)"

        while IFS= read -r acct; do
            [ -z "$acct" ] && continue
            if [ "$first_kept" -eq 1 ]; then
                first_kept=0
                continue
            fi

            local new_uid old_home usermod_err
            new_uid="$(_find_free_uid 1000 "$used_uids")"
            old_home="$(awk -F: -v a="$acct" '$1==a {print $6}' /etc/passwd)"
            usermod_err="$(usermod -u "$new_uid" "$acct" 2>&1)"

            if [ $? -eq 0 ]; then
                used_uids="${used_uids} ${new_uid}"
                log_info "중복 UID 계정 ${acct} 를 uid=${uid} -> uid=${new_uid} 로 재할당함."
                changed_list="${changed_list}${changed_list:+,}${acct}(${uid}->${new_uid})"

                if [ -n "$old_home" ] && [ -d "$old_home" ]; then
                    find "$old_home" -xdev -uid "$uid" -exec chown "$new_uid" {} + 2>/dev/null
                    manual_home_notes="${manual_home_notes}${manual_home_notes:+, }${acct}:${old_home}(홈 디렉토리 내부만 보정)"
                fi
            elif [ "$uid" = "0" ] && printf '%s' "$usermod_err" | grep -qi 'currently used by process'; then
                if sed -i -E "s/^(${acct}:[^:]*:)[0-9]+(:)/\\1${new_uid}\\2/" /etc/passwd; then
                    used_uids="${used_uids} ${new_uid}"
                    log_info "중복 UID 계정 ${acct} 를 uid=${uid} -> uid=${new_uid} 로 재할당함(root(UID 0)를 PID 1이 상시 점유해 usermod 불가 -> /etc/passwd 직접 수정으로 우회)."
                    changed_list="${changed_list}${changed_list:+,}${acct}(${uid}->${new_uid})"

                    if [ -n "$old_home" ] && [ -d "$old_home" ]; then
                        find "$old_home" -xdev -uid "$uid" -exec chown "$new_uid" {} + 2>/dev/null
                        manual_home_notes="${manual_home_notes}${manual_home_notes:+, }${acct}:${old_home}(홈 디렉토리 내부만 보정)"
                    fi
                else
                    log_error "중복 UID 계정 ${acct} 재할당 실패(/etc/passwd 직접 수정도 실패): ${usermod_err}"
                    failed_list="${failed_list}${failed_list:+,}${acct}"
                fi
            else
                log_error "중복 UID 계정 ${acct} 재할당 실패: ${usermod_err:-알 수 없는 오류}"
                failed_list="${failed_list}${failed_list:+,}${acct}"
            fi
        done <<< "$accounts_with_uid"
    done <<< "$dup_uids"

    if [ -n "$failed_list" ]; then
        FIX_DETAIL="UID 재할당 실패 계정: ${failed_list}. 성공: ${changed_list:-없음}. 백업: ${backup}"
        return 2
    fi

    FIX_DETAIL="중복 UID 계정 재할당 완료(${changed_list}). 홈 디렉토리 내부 파일 소유권만 자동 보정함(${manual_home_notes:-해당 없음}). 홈 디렉토리 밖의 파일 소유권은 영향 범위가 넓어 자동 처리하지 않았으므로 관리자가 'find / -xdev -uid <구UID>' 등으로 별도 확인 필요. 백업: ${backup}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-10 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
