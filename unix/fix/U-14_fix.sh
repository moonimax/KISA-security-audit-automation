#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-14"
readonly ITEM_TITLE="root 홈, 패스 디렉터리 권한 및 패스 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="root 계정의 PATH 문자열만 정리하며 서비스 재시작이 불필요함. 기존 root 세션의 환경변수는 즉시 바뀌지 않고 다음 로그인부터 적용됨"
readonly SEVERITY="상"
readonly ROOT_HOME="/root"

CHECK_DETAIL=""
FIX_DETAIL=""

_path_has_unsafe_current_dir() {
    local file="$1" line rhs
    while IFS= read -r line; do
        rhs="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?PATH=//; s/[[:space:]]+$//')"
        local parts=() i
        IFS=: read -r -a parts <<< "$rhs"
        [ "$rhs" = "${rhs#:}" ] || return 0
        [ "$rhs" = "${rhs%:}" ] || return 0
        for ((i=0; i<${#parts[@]}; i++)); do
            [ -n "${parts[$i]}" ] || return 0
            if [ "${parts[$i]}" = "." ] && [ "$i" -ne $((${#parts[@]} - 1)) ]; then
                return 0
            fi
        done
    done < <(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$file" 2>/dev/null | grep -v '^[[:space:]]*#')
    return 1
}

do_check() {
    local path_files=(/root/.bash_profile /root/.bashrc /root/.profile /root/.cshrc /etc/profile)
    local offenders=()
    for f in "${path_files[@]}"; do
        [ -r "$f" ] || continue
        _path_has_unsafe_current_dir "$f" && offenders+=("$f")
    done
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="PATH의 앞/중간에 현재 디렉토리('.') 또는 빈 항목이 있는 파일: $(IFS=','; echo "${offenders[*]}"). 명시적 '.'이 마지막인 경우만 허용됨."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="root PATH의 앞/중간에 '.' 또는 빈 항목이 없으며, 명시적 '.'은 마지막 위치에서만 허용됨."
    return "$KISA_EXIT_GOOD"
}

do_fix() {
    do_check
    local current=$?
    [ "$current" -eq "$KISA_EXIT_GOOD" ] && { FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."; return 0; }
    [ "$current" -eq "$KISA_EXIT_FAIL" ] && { FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."; return 2; }
    require_root || { FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."; return 2; }
    local path_files=(/root/.bash_profile /root/.bashrc /root/.profile /root/.cshrc /etc/profile)
    local applied=() failed=0
    for f in "${path_files[@]}"; do
        [ -w "$f" ] || continue
        _path_has_unsafe_current_dir "$f" || continue
        local backup="${f}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$f" "$backup" 2>/dev/null || { failed=$((failed + 1)); continue; }
        awk '
        /^[[:space:]]*(export[[:space:]]+)?PATH=/ && $0 !~ /^[[:space:]]*#/ {
            prefix=$0; sub(/PATH=.*/, "PATH=", prefix)
            value=$0; sub(/^[[:space:]]*(export[[:space:]]+)?PATH=/, "", value)
            n=split(value, a, ":"); out=""; dot=0
            for (i=1; i<=n; i++) {
                if (a[i]=="") continue
                if (a[i]==".") { dot=1; continue }
                out=out (out=="" ? "" : ":") a[i]
            }
            if (dot) out=out (out=="" ? "" : ":") "."
            print prefix out
            next
        } { print }' "$f" > "${f}.kisa.tmp" &&
            chmod --reference="$f" "${f}.kisa.tmp" 2>/dev/null &&
            chown --reference="$f" "${f}.kisa.tmp" 2>/dev/null &&
            mv "${f}.kisa.tmp" "$f" 2>/dev/null
        if [ $? -eq 0 ]; then
            applied+=("$f PATH 정리(백업: $backup)")
        else
            rm -f "${f}.kisa.tmp" 2>/dev/null
            cp -p "$backup" "$f" 2>/dev/null
            failed=$((failed + 1))
        fi
    done
    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="PATH 조치에 실패했거나 대상을 다시 조회했으나 발견되지 않음."
        return 2
    fi
    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}") (실패 $failed건). /root 권한은 가이드 판정 범위 밖이므로 변경하지 않음."
    [ "$failed" -eq 0 ] || return 2
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-14 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
