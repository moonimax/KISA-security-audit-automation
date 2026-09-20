#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-14"
readonly ITEM_TITLE="root 홈, 패스 디렉터리 권한 및 패스 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="root 계정의 PATH 문자열 정리 및 /root 디렉토리 권한 축소만 수행되며 서비스 재시작이 불필요함. 기존 root 세션의 환경변수는 즉시 바뀌지 않고 다음 로그인부터 적용됨"
readonly SEVERITY="상"
readonly ROOT_HOME="/root"

CHECK_DETAIL=""

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

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
