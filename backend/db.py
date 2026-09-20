"""
db.py
SQLAlchemy ORM + PyMySQL을 사용하는 동기(sync) MySQL 데이터 계층.

check/fix 스크립트 + Ansible 플레이북(playbooks/check.yml)이 만들어내는
JSON 점검 결과(reports/<host>_check.json, 예: code/title/status/action/detail/
os_type/timestamp/action_tag/impact/severity/... 필드를 가진 객체의 배열)를
그대로 저장할 수 있도록 테이블을 설계했다.

- 각 점검 항목(레코드) 전체는 원본 그대로 `data` 컬럼(MySQL JSON 타입)에 저장한다
  (필드가 늘어나거나 바뀌어도 스키마 변경 없이 그대로 수용하기 위함).
- host/ip/code는 조회·필터링을 빠르게 하기 위해 별도 컬럼으로도 뽑아둔다.
- (host, code) 조합은 UNIQUE로 두어, 같은 서버에 대해 같은 항목을 다시
  점검하면(재점검) 기존 레코드를 최신 결과로 덮어쓴다(INSERT ... ON DUPLICATE KEY UPDATE).

DB 접속 정보는 하드코딩하지 않고 config.py(→ backend/.env)에서 읽어온다.
"""
import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from sqlalchemy import JSON, Column, DateTime, Integer, String, UniqueConstraint, create_engine, inspect, text
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

class CheckResult(Base):
    """점검 결과 1건(호스트 x 점검코드) = 테이블의 한 행."""

    __tablename__ = "check_results"
    __table_args__ = (UniqueConstraint("host", "code", name="uq_check_results_host_code"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String(255), nullable=False, index=True)
    ip = Column(String(64))
    code = Column(String(32), nullable=False, index=True)
    data = Column(JSON, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

class CheckRun(Base):
    """점검/조치 후 적재 1회를 보존하는 호스트 단위 실행 이력."""

    __tablename__ = "check_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String(255), nullable=False, index=True)
    ip = Column(String(64), index=True)
    domain = Column(String(32), nullable=False)
    run_kind = Column(String(64), nullable=False, default="점검")
    total_count = Column(Integer, nullable=False, default=0)
    good_count = Column(Integer, nullable=False, default=0)
    vuln_count = Column(Integer, nullable=False, default=0)
    auto_count = Column(Integer, nullable=False, default=0)
    approve_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

class ReportLog(Base):
    """대시보드에서 생성한 리포트의 조회 조건과 생성 정보를 보존한다."""

    __tablename__ = "report_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    data = Column(JSON, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

class RegisteredHost(Base):
    """대시보드(IP 등록 페이지)에서 등록한 점검 대상 서버 1건."""

    __tablename__ = "registered_hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), unique=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    domains = Column(String(64), nullable=False, default="UNIX")
    registered_at = Column(DateTime, nullable=False, default=datetime.utcnow)

class LoginUser(Base):
    """콘솔 로그인 사용자. 비밀번호는 PBKDF2 해시만 저장한다."""

    __tablename__ = "login_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    login_id = Column(String(100), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=False, default="")
    organization = Column(String(255), nullable=False, default="")
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

_PASSWORD_ALGORITHM = "pbkdf2_sha256"
_PASSWORD_ITERATIONS = 600_000

def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PASSWORD_ITERATIONS
    )
    return "$".join(
        (
            _PASSWORD_ALGORITHM,
            str(_PASSWORD_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )

def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != _PASSWORD_ALGORITHM:
            return False
        salt = base64.b64decode(salt_text, validate=True)
        expected = base64.b64decode(digest_text, validate=True)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations_text)
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False

def _seed_admin_user() -> None:
    """admin 계정이 없을 때만 초기 비밀번호로 생성한다."""
    with SessionLocal() as session:
        existing = session.query(LoginUser).filter(LoginUser.login_id == "admin").first()
        if existing is None:
            session.add(
                LoginUser(
                    username="admin",
                    login_id="admin",
                    email="admin@ssap.local",
                    organization="보안관제팀",
                    password_hash=_hash_password("P@ssw0rd"),
                )
            )
            session.commit()

def authenticate_user(login_id: str, password: str) -> Optional[dict[str, str]]:
    """아이디와 비밀번호가 일치하면 공개 가능한 사용자 정보만 반환한다."""
    with SessionLocal() as session:
        user = session.query(LoginUser).filter(LoginUser.login_id == login_id).first()
        if user is None or not _verify_password(password, user.password_hash):
            return None
        return {
            "username": user.username,
            "login_id": user.login_id,
            "email": user.email or "",
            "organization": user.organization or "",
        }

def change_password(login_id: str, current_password: str, new_password: str) -> bool:
    """현재 비밀번호가 맞을 때만 새 해시로 교체한다."""
    with SessionLocal() as session:
        user = session.query(LoginUser).filter(LoginUser.login_id == login_id).first()
        if user is None or not _verify_password(current_password, user.password_hash):
            return False
        user.password_hash = _hash_password(new_password)
        user.updated_at = datetime.utcnow()
        session.commit()
        return True

def init_db() -> None:
    """테이블을 생성하고 최초 관리자 계정을 준비한다(멱등)."""
    Base.metadata.create_all(bind=engine)
    action_columns_added = _ensure_check_run_action_columns()
    _ensure_login_user_profile_columns()
    _backfill_initial_check_runs()
    if action_columns_added:
        _backfill_existing_check_run_action_counts()
    _seed_admin_user()

def _ensure_check_run_action_columns() -> bool:
    """기존 check_runs 테이블에 조치방식별 개수 컬럼을 안전하게 추가한다."""
    column_names = {column["name"] for column in inspect(engine).get_columns("check_runs")}
    added = False
    with engine.begin() as connection:
        if "auto_count" not in column_names:
            connection.execute(text(
                "ALTER TABLE check_runs ADD COLUMN auto_count INT NOT NULL DEFAULT 0"
            ))
            added = True
        if "approve_count" not in column_names:
            connection.execute(text(
                "ALTER TABLE check_runs ADD COLUMN approve_count INT NOT NULL DEFAULT 0"
            ))
            added = True
    return added

def _backfill_initial_check_runs() -> None:
    """이력 테이블 도입 전에 있던 최신 결과를 기준 로그로 한 번만 옮긴다."""
    with SessionLocal() as session:
        if session.query(CheckRun.id).first() is not None:
            return
        registered = {row.ip: row.hostname for row in session.query(RegisteredHost).all()}
        if not registered:
            return
        newest: dict[tuple[str, str], CheckResult] = {}
        for row in session.query(CheckResult).filter(CheckResult.ip.in_(registered)).all():
            key = (row.ip or "", row.code)
            current = newest.get(key)
            if current is None or (row.created_at, row.id) > (current.created_at, current.id):
                newest[key] = row
        grouped: dict[tuple[str, str], list[CheckResult]] = {}
        for row in newest.values():
            domain = "WEB" if row.code.startswith("WEB-") else "DBMS" if row.code.startswith("D-") else "UNIX"
            grouped.setdefault((row.ip or "", domain), []).append(row)
        for (ip, domain), rows in grouped.items():
            statuses = [str(row.data.get("status") or "").strip() for row in rows]
            good_count = sum(status in {"양호", "O", "o"} for status in statuses)
            non_good_rows = [
                row for row, status in zip(rows, statuses)
                if status not in {"양호", "O", "o"}
            ]
            session.add(CheckRun(
                host=registered[ip],
                ip=ip,
                domain=domain,
                run_kind="기존 최신 결과",
                total_count=len(rows),
                good_count=good_count,
                vuln_count=len(rows) - good_count,
                auto_count=sum(row.data.get("action_tag") == "자동조치" for row in non_good_rows),
                approve_count=sum(row.data.get("action_tag") == "승인요청" for row in non_good_rows),
                created_at=max(row.created_at for row in rows),
            ))
        session.commit()

def _backfill_existing_check_run_action_counts() -> None:
    """컬럼 추가 시 기존 기준 로그의 조치방식별 개수를 최신 결과로 채운다."""
    with SessionLocal() as session:
        for run in session.query(CheckRun).filter(CheckRun.run_kind == "기존 최신 결과").all():
            candidates = session.query(CheckResult).filter(CheckResult.ip == run.ip).all()
            newest: dict[str, CheckResult] = {}
            for row in candidates:
                domain = "WEB" if row.code.startswith("WEB-") else "DBMS" if row.code.startswith("D-") else "UNIX"
                if domain != run.domain:
                    continue
                current = newest.get(row.code)
                if current is None or (row.created_at, row.id) > (current.created_at, current.id):
                    newest[row.code] = row
            non_good_rows = [
                row for row in newest.values()
                if str(row.data.get("status") or "").strip() not in {"양호", "O", "o"}
            ]
            run.auto_count = sum(row.data.get("action_tag") == "자동조치" for row in non_good_rows)
            run.approve_count = sum(row.data.get("action_tag") == "승인요청" for row in non_good_rows)
        session.commit()

def _ensure_login_user_profile_columns() -> None:
    """기존 login_users 테이블에도 프로필 컬럼을 안전하게 추가한다."""
    column_names = {column["name"] for column in inspect(engine).get_columns("login_users")}
    with engine.begin() as connection:
        if "email" not in column_names:
            connection.execute(text(
                "ALTER TABLE login_users ADD COLUMN email VARCHAR(255) NOT NULL DEFAULT ''"
            ))
        if "organization" not in column_names:
            connection.execute(text(
                "ALTER TABLE login_users ADD COLUMN organization VARCHAR(255) NOT NULL DEFAULT ''"
            ))
        connection.execute(text(
            "UPDATE login_users SET email = 'admin@ssap.local' "
            "WHERE login_id = 'admin' AND email = ''"
        ))
        connection.execute(text(
            "UPDATE login_users SET organization = '보안관제팀' "
            "WHERE login_id = 'admin' AND organization = ''"
        ))

def save_results(
    host: str,
    results: Iterable[Mapping[str, Any]],
    ip: Optional[str] = None,
    run_kind: str = "점검",
) -> int:
    """
    JSON 점검 결과값(딕셔너리 리스트, reports/<host>_check.json과 동일한 스키마)을
    받아 MySQL에 저장한다.

    :param host: 점검 대상 호스트명 (예: "instructor_db")
    :param results: [{"code": "U-01", "title": "...", "status": "취약", ...}, ...]
    :param ip: 대상 서버 IP (선택)
    :return: 저장(삽입/갱신)된 레코드 수
    """
    saved = 0
    result_rows = list(results)
    with SessionLocal() as session:
        for item in result_rows:
            code = item.get("code")
            if not code:
                continue

            stmt = mysql_insert(CheckResult).values(host=host, ip=ip, code=code, data=item)
            stmt = stmt.on_duplicate_key_update(
                ip=stmt.inserted.ip,
                data=stmt.inserted.data,
                created_at=datetime.utcnow(),
            )
            session.execute(stmt)
            saved += 1
        if saved:
            statuses = [str(item.get("status") or "").strip() for item in result_rows if item.get("code")]
            valid_rows = [item for item in result_rows if item.get("code")]
            first_code = next((str(item.get("code")) for item in result_rows if item.get("code")), "")
            domain = "WEB" if first_code.startswith("WEB-") else "DBMS" if first_code.startswith("D-") else "UNIX"
            good_count = sum(status in {"양호", "O", "o"} for status in statuses)
            non_good_rows = [
                item for item, status in zip(valid_rows, statuses)
                if status not in {"양호", "O", "o"}
            ]
            session.add(CheckRun(
                host=host,
                ip=ip,
                domain=domain,
                run_kind=run_kind,
                total_count=len(statuses),
                good_count=good_count,
                vuln_count=len(statuses) - good_count,
                auto_count=sum(item.get("action_tag") == "자동조치" for item in non_good_rows),
                approve_count=sum(item.get("action_tag") == "승인요청" for item in non_good_rows),
            ))
        session.commit()
    return saved

def _utc_iso(value: datetime) -> str:
    """DB의 naive UTC 시각을 브라우저가 오해하지 않도록 명시적 UTC로 직렬화한다."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def fetch_results(host: Optional[str] = None) -> list[dict]:
    """현재 등록 IP별 최신 점검 결과를 반환한다.

    호스트명 변경 전 결과는 DB에 보존하되 동일 IP/코드는 최신 1건만 선택한다.
    """
    with SessionLocal() as session:
        query = session.query(CheckResult)
        if host:
            query = query.filter(CheckResult.host == host)
            rows = query.order_by(CheckResult.host, CheckResult.code).all()
            canonical_hosts: dict[str, str] = {}
        else:
            canonical_hosts = {row.ip: row.hostname for row in session.query(RegisteredHost).all()}
            candidates = query.filter(CheckResult.ip.in_(canonical_hosts)).all() if canonical_hosts else []
            newest: dict[tuple[str, str], CheckResult] = {}
            for row in candidates:
                key = (row.ip or "", row.code)
                current = newest.get(key)
                if current is None or (row.created_at, row.id) > (current.created_at, current.id):
                    newest[key] = row
            rows = sorted(newest.values(), key=lambda row: (row.ip or "", row.code))

        records = []
        for row in rows:
            record = dict(row.data)
            record["host"] = canonical_hosts.get(row.ip, row.host)
            record["ip"] = row.ip
            record["saved_at"] = _utc_iso(row.created_at)
            records.append(record)
        return records

def fetch_check_runs(limit: int = 100) -> list[dict]:
    """최근 점검/조치 실행 이력을 최신순으로 반환한다."""
    with SessionLocal() as session:
        rows = session.query(CheckRun).order_by(CheckRun.created_at.desc(), CheckRun.id.desc()).limit(limit).all()
        return [{
            "id": row.id,
            "host": row.host,
            "ip": row.ip,
            "domain": row.domain,
            "run_kind": row.run_kind,
            "total_count": row.total_count,
            "good_count": row.good_count,
            "vuln_count": row.vuln_count,
            "auto_count": row.auto_count,
            "approve_count": row.approve_count,
            "created_at": _utc_iso(row.created_at),
        } for row in rows]

def _report_log_to_dict(row: "ReportLog") -> dict:
    record = dict(row.data)
    record["id"] = row.id
    record["created_at"] = _utc_iso(row.created_at)
    if not record.get("timestamp"):
        record["timestamp"] = record["created_at"]
    return record

def add_report_log(entry: Mapping[str, Any]) -> dict:
    """리포트 생성 기록 한 건을 DB에 저장한다."""
    with SessionLocal() as session:
        row = ReportLog(data=dict(entry))
        session.add(row)
        session.commit()
        session.refresh(row)
        return _report_log_to_dict(row)

def fetch_report_logs(limit: int = 500) -> list[dict]:
    """저장된 리포트 생성 기록을 최신순으로 반환한다."""
    with SessionLocal() as session:
        rows = (
            session.query(ReportLog)
            .order_by(ReportLog.created_at.desc(), ReportLog.id.desc())
            .limit(limit)
            .all()
        )
        return [_report_log_to_dict(row) for row in rows]

def _host_to_dict(row: "RegisteredHost") -> dict:
    return {
        "ip": row.ip,
        "hostname": row.hostname,
        "domains": row.domains.split(",") if row.domains else ["UNIX"],
        "registered_at": _utc_iso(row.registered_at),
    }

def list_hosts() -> list[dict]:
    """등록된 점검 대상 서버 전체를 등록일시 순으로 반환한다."""
    with SessionLocal() as session:
        rows = session.query(RegisteredHost).order_by(RegisteredHost.registered_at).all()
        return [_host_to_dict(r) for r in rows]

def add_host(ip: str, hostname: str, domains: list[str]) -> Optional[dict]:
    """새 점검 대상 서버를 등록한다. 이미 등록된 IP면 None을 반환한다."""
    with SessionLocal() as session:
        exists = session.query(RegisteredHost).filter(RegisteredHost.ip == ip).first()
        if exists:
            return None
        row = RegisteredHost(ip=ip, hostname=hostname, domains=",".join(domains))
        session.add(row)
        session.commit()
        session.refresh(row)
        return _host_to_dict(row)

def remove_host(ip: str) -> bool:
    """등록된 점검 대상 서버를 삭제한다. 존재하지 않았으면 False."""
    with SessionLocal() as session:
        row = session.query(RegisteredHost).filter(RegisteredHost.ip == ip).first()
        if not row:
            return False
        session.delete(row)
        session.commit()
        return True
