#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-23"
readonly ITEM_TITLE="SUID, SGID, Sticky bit 설정 파일 점검"
readonly ACTION_TAG="승인요청"
readonly IMPACT="chmod 로 SUID/SGID 비트만 제거하는 가역적 변경(파일 삭제 아님)이지만, 화이트리스트에 없는 SUID 바이너리가 실제로는 서버에 설치된 정상 소프트웨어(DB, 백업 에이전트 등)의 권한 상승 메커니즘일 수 있어 관리자의 도메인 판단이 필요함"
readonly SEVERITY="상"
readonly SCAN_TIMEOUT="${KISA_U23_SCAN_TIMEOUT:-30}"

readonly SUID_WHITELIST=(
    /usr/bin/passwd /bin/passwd
    /usr/bin/su /bin/su
    /usr/bin/newgrp /bin/newgrp
    /usr/bin/gpasswd /bin/gpasswd
    /usr/bin/chsh /bin/chsh
    /usr/bin/chfn /bin/chfn
    /usr/bin/chage /usr/bin/expiry /usr/bin/sg
    /usr/sbin/unix_chkpwd /sbin/unix_chkpwd
    /usr/sbin/pam_extrausers_chkpwd
    /usr/sbin/pam_timestamp_check
    /usr/bin/sudo /usr/bin/sudoedit /usr/bin/sudo.ws
    /usr/lib/cargo/bin/sudo /usr/lib/cargo/bin/su
    /usr/bin/mount /bin/mount
    /usr/bin/umount /bin/umount
    /usr/sbin/mount.nfs /usr/sbin/mount.nfs4 /sbin/mount.nfs
    /usr/sbin/mount.cifs /sbin/mount.cifs
    /usr/bin/fusermount /usr/bin/fusermount3
    /usr/bin/ntfs-3g
    /usr/bin/ping /bin/ping /usr/bin/ping6 /bin/ping6
    /usr/bin/traceroute6.iputils
    /usr/sbin/pppd
    /usr/bin/mtr-packet /usr/sbin/mtr-packet
    /usr/bin/crontab /usr/bin/at
    /usr/bin/write /usr/bin/bsd-write /usr/bin/wall
    /usr/lib/openssh/ssh-keysign /usr/libexec/openssh/ssh-keysign
    /usr/bin/ssh-agent
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/libexec/dbus-1/dbus-daemon-launch-helper
    /usr/libexec/camel-lock-helper-1.2
    /usr/lib/evolution-data-server/camel-lock-helper-1.2
    /usr/bin/pkexec
    /usr/lib/polkit-1/polkit-agent-helper-1
    /usr/libexec/polkit-agent-helper-1
    /usr/lib/xorg/Xorg.wrap /usr/libexec/Xorg.wrap
    /usr/bin/vmware-user-suid-wrapper
    /usr/lib/snapd/snap-confine /usr/libexec/snapd/snap-confine
    /usr/bin/bwrap
    /usr/bin/mlocate /usr/bin/locate /usr/bin/plocate
    /usr/bin/dotlockfile /usr/bin/lockfile
    /usr/lib/x86_64-linux-gnu/utempter/utempter
    /usr/libexec/utempter/utempter
)

readonly NEVER_SUID_BASENAMES=(
    bash sh dash ksh zsh csh tcsh busybox
    cat tac less more head tail coreutils
    find grep egrep fgrep awk gawk mawk sed
    cp mv dd tar cpio rsync
    vi vim vim.basic vim.tiny nano pico emacs ed
    env xargs man
    python python2 python3 perl ruby lua node
    nmap tcpdump socat ncat nc netcat
)

CHECK_DETAIL=""
FIX_DETAIL=""

_canon() {
    readlink -f -- "$1" 2>/dev/null || printf '%s' "$1"
}

_pkg_owns() {
    local f="$1"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -S "$f" >/dev/null 2>&1 && return 0
    fi
    if command -v rpm >/dev/null 2>&1; then
        rpm -qf "$f" >/dev/null 2>&1 && return 0
    fi
    return 1
}

_is_runtime_privilege_tool() {
    local f="$1" fr cmd p pr
    fr="$(_canon "$f")"

    for cmd in sudo sudoedit su; do
        p="$(command -v "$cmd" 2>/dev/null || true)"
        [ -n "$p" ] || continue
        pr="$(_canon "$p")"
        [ "$f" = "$p" ] || [ "$fr" = "$pr" ] || [ "$f" = "$pr" ] || [ "$fr" = "$p" ] || continue
        return 0
    done

    for p in /usr/bin/sudo /usr/bin/sudo.* /usr/bin/sudoedit \
             /etc/alternatives/sudo /etc/alternatives/sudo.* \
             /usr/lib/cargo/bin/sudo /usr/lib/cargo/bin/sudo.* \
             /usr/bin/su /bin/su /usr/lib/cargo/bin/su; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        pr="$(_canon "$p")"
        [ "$f" = "$p" ] || [ "$fr" = "$pr" ] || [ "$f" = "$pr" ] || [ "$fr" = "$p" ] || continue
        return 0
    done
    return 1
}

_check_active_sudo_integrity() {
    local sudo_path sudo_real uid mode mode_num
    sudo_path="$(command -v sudo 2>/dev/null || true)"
    [ -n "$sudo_path" ] || return 0
    sudo_real="$(_canon "$sudo_path")"
    [ -f "$sudo_real" ] || return 1
    uid="$(stat -L -c '%u' "$sudo_real" 2>/dev/null || true)"
    mode="$(stat -L -c '%a' "$sudo_real" 2>/dev/null || true)"
    [[ "$uid" = "0" && "$mode" =~ ^[0-7]+$ ]] || return 1
    mode_num=$((8#$mode))
    (( (mode_num & 04000) != 0 ))
}

_is_whitelisted() {
    local f="$1" w fr wr base nb
    _is_runtime_privilege_tool "$f" && return 0

    fr="$(_canon "$f")"

    for w in "${SUID_WHITELIST[@]}"; do
        [ "$f" = "$w" ] && return 0
        wr="$(_canon "$w")"
        { [ "$fr" = "$wr" ] || [ "$f" = "$wr" ] || [ "$fr" = "$w" ]; } && return 0
    done

    base="$(basename -- "$fr")"
    for nb in "${NEVER_SUID_BASENAMES[@]}"; do
        [ "$base" = "$nb" ] && return 1
    done

    { _pkg_owns "$fr" || _pkg_owns "$f"; } && return 0

    return 1
}

_scan_suid_files() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$SCAN_TIMEOUT" find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null
    else
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null
    fi
}

_collect_targets() {
    local f key
    local -A seen=()
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        _is_whitelisted "$f" && continue
        key="$(stat -c '%d:%i' "$f" 2>/dev/null || true)"
        if [ -n "$key" ]; then
            [ -n "${seen[$key]:-}" ] && continue
            seen[$key]=1
        fi
        printf '%s\t%s\n' "${key:-?}" "$f"
    done
}

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    if ! _check_active_sudo_integrity; then
        CHECK_DETAIL="활성 sudo 바이너리($(command -v sudo 2>/dev/null || printf '경로 확인 실패'))가 root 소유가 아니거나 SUID 비트가 없어 권한 상승이 불가능함. U-23은 추가 변경을 수행해서는 안 됨."
        return "$KISA_EXIT_VULN"
    fi

    local result rc
    result="$(_scan_suid_files)"
    rc=$?
    if [ "$rc" -eq 124 ]; then
        CHECK_DETAIL="SUID/SGID 전체 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않아 판정을 완료하지 못함."
        return "$KISA_EXIT_FAIL"
    fi

    local offenders=() count=0 line
    while IFS=$'\t' read -r _ line; do
        [ -z "$line" ] && continue
        count=$((count + 1))
        [ "${#offenders[@]}" -lt 20 ] && offenders+=("$line")
    done <<< "$(printf '%s\n' "$result" | _collect_targets)"

    if [ "$count" -gt 0 ]; then
        CHECK_DETAIL="화이트리스트 밖 SUID/SGID 파일 ${count}건(하드링크 중복 제외, 최대 20건 표시) 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="발견된 모든 SUID/SGID 파일이 표준 유틸리티 화이트리스트 내에 있음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 화이트리스트 밖 SUID/SGID 파일이 정상 소프트웨어의 일부인지 확인이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하면 chmod 로 SUID/SGID 비트만 제거함(파일 삭제 없음)."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    if ! _check_active_sudo_integrity; then
        FIX_DETAIL="활성 sudo 바이너리의 root 소유권/SUID 무결성 검증에 실패하여 모든 U-23 변경을 중단함. 콘솔 또는 기존 root 세션에서 sudo 패키지를 복구해야 함(예: chmod u+s \$(readlink -f \$(command -v sudo)))."
        return 2
    fi

    local files
    files="$(_scan_suid_files)"

    local fixed=0 failed=0 key f
    local fixed_list=()
    while IFS=$'\t' read -r key f; do
        [ -z "$f" ] && continue
        if chmod ug-s "$f" 2>/dev/null; then
            fixed=$((fixed + 1))
            [ "${#fixed_list[@]}" -lt 15 ] && fixed_list+=("$f")
        else
            failed=$((failed + 1))
        fi
    done <<< "$(printf '%s\n' "$files" | _collect_targets)"

    if ! _check_active_sudo_integrity; then
        FIX_DETAIL="조치 후 활성 sudo 바이너리의 root 소유권/SUID 무결성 검증에 실패함. 추가 조치를 중단하고 콘솔 또는 기존 root 세션에서 sudo 패키지를 복구해야 함."
        return 2
    fi

    log_info "SUID/SGID 비트 제거: 성공 ${fixed}건, 실패 ${failed}건"

    if [ "$fixed" -eq 0 ] && [ "$failed" -eq 0 ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    if [ "$failed" -gt 0 ] && [ "$fixed" -eq 0 ]; then
        FIX_DETAIL="SUID/SGID 비트 제거에 모두 실패함(${failed}건)."
        return 2
    fi

    local listmsg
    listmsg="$(IFS=','; echo "${fixed_list[*]}")"
    if [ "$fixed" -gt "${#fixed_list[@]}" ]; then
        listmsg="${listmsg} …외 $((fixed - ${#fixed_list[@]}))건"
    fi
    FIX_DETAIL="화이트리스트 밖 파일 ${fixed}건에서 SUID/SGID 비트를 제거함(실패 ${failed}건, chmod +s 로 복구 가능): ${listmsg}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-23 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
