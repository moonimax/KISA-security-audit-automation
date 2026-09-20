"""
inventory_sync.py
DB에 등록된 대상 서버 목록을 각 진단영역의 Ansible inventory와 동기화한다.

대시보드(IP 등록 페이지)에서 서버를 등록/삭제하면 Ansible 플레이북이
곧바로 그 서버를 대상으로 실행될 수 있어야 하므로, DB 변경 직후 이
동기화를 호출해 inventory 파일을 다시 만든다.

ansible_user는 이 프로젝트의 기존 관례를 따라 hostname과 동일하게
설정한다(예: instructor_db ansible_host=... ansible_user=instructor_db).
"""
import os
import re
import tempfile
from dataclasses import replace
from pathlib import Path

from . import db
from .runtime import DomainRuntime, RUNTIMES, UNIFIED_INVENTORY

CONTROL_HOSTS = [
    {
        "hostname": "control-node",
        "ip": "100.121.58.87",
        "ansible_user": "control",
    }
]
TAILSCALE_NAMES = {
    "100.120.178.40": "instructor-db",
    "100.112.225.33": "lecture-db",
    "100.76.242.18": "student-db",
    "100.88.45.99": "was",
    "100.122.19.67": "webs",
}

def _atomic_write(path: Path, content: str) -> None:
    """독자가 비어 있거나 절반만 쓰인 inventory를 보지 않게 교체한다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_name = temp_file.name
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.chmod(temp_name, existing_mode)
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)

def _existing_users_by_ip(runtime: DomainRuntime) -> dict[str, str]:
    """재생성 전 inventory의 IP별 SSH 계정을 보존한다."""
    if not runtime.inventory.exists():
        return {}
    users: dict[str, str] = {}
    host_re = re.compile(r"\bansible_host=(\S+)")
    user_re = re.compile(r"\bansible_user=(\S+)")
    for line in runtime.inventory.read_text(encoding="utf-8").splitlines():
        host_match = host_re.search(line)
        user_match = user_re.search(line)
        if host_match and user_match and not line.lstrip().startswith((";", "#")):
            users[host_match.group(1)] = user_match.group(1)
    return users

def _all_existing_users_by_ip() -> dict[str, str]:
    users: dict[str, str] = {}
    unified_runtime = replace(RUNTIMES["UNIX"], inventory=UNIFIED_INVENTORY)
    for runtime in [unified_runtime, *RUNTIMES.values()]:
        users.update(_existing_users_by_ip(runtime))
    return users

def _render_unified_inventory(hosts: list[dict], users_by_ip: dict[str, str]) -> str:
    lines = [
        "; SSAP 통합 인벤토리 - 콘솔 DB 변경 시 자동 생성됩니다.",
        "; vuln, managed, geonhome, localhost-0은 관리 범위에서 제외합니다.",
        "",
        "[control_nodes]",
    ]
    for host in CONTROL_HOSTS:
        lines.append(
            f"{host['hostname']} ansible_host={host['ip']} "
            f"ansible_user={host['ansible_user']} ansible_connection=local"
        )

    lines.extend(["", "[managed_assets]"])
    for host in hosts:
        tailscale_name = TAILSCALE_NAMES.get(host["ip"], host["hostname"])
        domains = ",".join(host.get("domains") or ["UNIX"])
        ansible_user = users_by_ip.get(host["ip"], host["hostname"])
        lines.append(f"; {tailscale_name} | domains={domains}")
        lines.append(
            f"{host['hostname']} ansible_host={host['ip']} ansible_user={ansible_user}"
        )

    group_names = {
        "UNIX": "unix_targets",
        "WEB": "web_targets",
        "DBMS": "dbms_targets",
    }
    for domain, group in group_names.items():
        lines.extend(["", f"[{group}]"])
        selected = [host for host in hosts if domain in (host.get("domains") or ["UNIX"])]
        lines.extend(host["hostname"] for host in selected)
        if not selected:
            lines.append("; (등록된 호스트 없음)")

    lines.extend(
        [
            "",
            "[assessment_targets:children]",
            "unix_targets",
            "web_targets",
            "dbms_targets",
        ]
    )
    return "\n".join(lines) + "\n"

def sync_inventory() -> None:
    hosts = db.list_hosts()
    users_by_ip = _all_existing_users_by_ip()
    _atomic_write(UNIFIED_INVENTORY, _render_unified_inventory(hosts, users_by_ip))
    for domain, runtime in RUNTIMES.items():
        selected = [host for host in hosts if domain in (host.get("domains") or ["UNIX"])]
        group = "mysql_servers" if domain == "DBMS" else "all"
        lines = [
            "; 이 파일의 호스트 목록은 대시보드 등록/삭제 시 자동 생성됩니다.",
            f"[{group}]",
        ]
        if not selected:
            lines.append("; (등록된 호스트 없음)")
        for host in selected:
            ansible_user = users_by_ip.get(host["ip"], host["hostname"])
            lines.append(
                f"{host['hostname']} ansible_host={host['ip']} ansible_user={ansible_user}"
            )
        if domain == "DBMS":
            lines.extend(["", "[mysql_servers:vars]", "ansible_become=true"])

        _atomic_write(runtime.inventory, "\n".join(lines) + "\n")
