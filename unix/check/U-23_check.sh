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

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    if ! _check_active_sudo_integrity; then
        CHECK_DETAIL="활성 sudo 바이너리($(command -v sudo 2>/dev/null || printf '경로 확인 실패'))가 root 소유가 아니거나 SUID 비트가 없어 권한 상승이 불가능함."
        return "$KISA_EXIT_VULN"
    fi

    local result rc
    if command -v timeout >/dev/null 2>&1; then
        result="$(timeout "$SCAN_TIMEOUT" find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)"
        rc=$?
    else
        result="$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)"
        rc=0
    fi

    if [ "$rc" -eq 124 ]; then
        CHECK_DETAIL="SUID/SGID 전체 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않아 판정을 완료하지 못함."
        return "$KISA_EXIT_FAIL"
    fi

    local offenders=() count=0 f key
    local -A seen=()
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        _is_whitelisted "$f" && continue
        key="$(stat -c '%d:%i' "$f" 2>/dev/null || true)"
        if [ -n "$key" ]; then
            [ -n "${seen[$key]:-}" ] && continue
            seen[$key]=1
        fi
        count=$((count + 1))
        [ "${#offenders[@]}" -lt 20 ] && offenders+=("$f")
    done <<< "$result"

    if [ "$count" -gt 0 ]; then
        CHECK_DETAIL="화이트리스트 밖 SUID/SGID 파일 ${count}건(하드링크 중복 제외, 최대 20건 표시) 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="발견된 모든 SUID/SGID 파일이 표준 유틸리티 화이트리스트 내에 있음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
