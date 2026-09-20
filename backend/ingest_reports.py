"""
ingest_reports.py
각 진단영역의 reports 디렉터리에 있는 점검 JSON을 읽어 DB에 채워 넣는다.

콘솔 작업은 jobs.py가 결과를 즉시 적재하며, 이 모듈은 기존 리포트를 다시
적재하는 수동 백필 도구다. --host 없이 실행하면 모든 영역을 순회한다.

사용법 (프로젝트 루트에서):
  python3 -m backend.ingest_reports
  python3 -m backend.ingest_reports --domain WEB --host web01
"""
import argparse
import json
import re

from . import db
from .runtime import DomainRuntime, RUNTIMES

def load_inventory_ips(runtime: DomainRuntime) -> dict[str, str]:
    """영역 inventory를 간단히 파싱해 {host: ip} 매핑을 만든다."""
    ip_by_host: dict[str, str] = {}
    if not runtime.inventory.exists():
        return ip_by_host
    line_re = re.compile(r"^(\S+)\s+ansible_host=(\S+)")
    for line in runtime.inventory.read_text(encoding="utf-8").splitlines():
        match = line_re.match(line.strip())
        if match:
            ip_by_host[match.group(1)] = match.group(2)
    return ip_by_host

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        help="이 호스트의 리포트만 적재한다. 생략 시 선택 영역 전체를 적재한다.",
    )
    parser.add_argument(
        "--domain", choices=RUNTIMES, help="UNIX/WEB/DBMS 중 한 영역만 적재한다."
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    db.init_db()
    domains = [args.domain] if args.domain else list(RUNTIMES)
    found = False
    for domain in domains:
        runtime = RUNTIMES[domain]
        ip_by_host = load_inventory_ips(runtime)
        if args.host:
            report_files = [runtime.reports_dir / f"{args.host}{runtime.check_report_suffix}"]
        else:
            report_files = sorted(runtime.reports_dir.glob(f"*{runtime.check_report_suffix}"))

        for path in report_files:
            if not path.exists():
                continue
            found = True
            host = path.name.removesuffix(runtime.check_report_suffix)
            ip = ip_by_host.get(host)
            results = json.loads(path.read_text(encoding="utf-8"))
            saved = db.save_results(host=host, results=results, ip=ip)
            print(f"[{domain}] {path.name}: host={host} ip={ip or '-'} → {saved}건 저장")

    if not found:
        target = f"host={args.host}" if args.host else "전체"
        raise SystemExit(f"선택한 영역에서 적재할 점검 리포트가 없습니다: {target}")

if __name__ == "__main__":
    main()
