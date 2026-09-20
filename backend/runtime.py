"""진단영역별 Ansible 실행 위치와 파일 이름을 한 곳에서 관리한다."""
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UNIFIED_INVENTORY = PROJECT_ROOT / "inventory" / "hosts.ini"

@dataclass(frozen=True)
class DomainRuntime:
    name: str
    root: Path
    inventory: Path
    deploy_playbook: str | None
    check_playbook: str
    audit_playbook: str
    remediate_playbook: str
    check_report_suffix: str
    audit_report_suffix: str

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

RUNTIMES = {
    "UNIX": DomainRuntime(
        "UNIX",
        PROJECT_ROOT / "unix",
        PROJECT_ROOT / "unix" / "inventory" / "hosts.ini",
        "playbooks/deploy.yml",
        "playbooks/check.yml",
        "playbooks/audit.yml",
        "playbooks/remediate_approved.yml",
        "_check.json",
        "_audit.json",
    ),
    "WEB": DomainRuntime(
        "WEB",
        PROJECT_ROOT / "web",
        PROJECT_ROOT / "web" / "inventory" / "hosts.ini",
        "playbooks/deploy.yml",
        "playbooks/check.yml",
        "playbooks/audit.yml",
        "playbooks/remediate_approved.yml",
        "_check.json",
        "_audit.json",
    ),
    "DBMS": DomainRuntime(
        "DBMS",
        PROJECT_ROOT / "db",
        PROJECT_ROOT / "db" / "inventory" / "hosts.ini",
        "playbooks/deploy.yml",
        "playbooks/check.yml",
        "playbooks/audit.yml",
        "playbooks/remediate_approved.yml",
        "_mysql_dbms_check.json",
        "_remediate.json",
    ),
}

def domain_for_code(code: str) -> str:
    normalized = code.strip().upper()
    if normalized.startswith("WEB-"):
        return "WEB"
    if normalized.startswith("D-"):
        return "DBMS"
    if normalized.startswith("U-"):
        return "UNIX"
    raise ValueError(f"지원하지 않는 점검 코드입니다: {code}")
