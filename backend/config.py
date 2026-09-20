"""
config.py
DB 접속 정보 등 환경설정을 코드에서 분리해서 관리한다.

우선순위: 실제 환경변수 > backend/.env 파일 > 기본값.
운영/개인 환경별로 다른 값을 쓰려면 코드를 고치지 말고
backend/.env (또는 실제 환경변수 KISA_MYSQL_* )만 바꾸면 된다.
"""
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

@dataclass(frozen=True)
class Settings:
    mysql_host: str = os.getenv("KISA_MYSQL_HOST", "127.0.0.1")
    mysql_port: int = int(os.getenv("KISA_MYSQL_PORT", "3306"))
    mysql_user: str = os.getenv("KISA_MYSQL_USER", "kisa")
    mysql_password: str = os.getenv("KISA_MYSQL_PASSWORD", "kisa_password")
    mysql_db: str = os.getenv("KISA_MYSQL_DB", "kisa_console")

    @property
    def database_url(self) -> str:
        """SQLAlchemy(PyMySQL 드라이버) 접속 문자열."""
        return (
            f"mysql+pymysql://{self.mysql_user}:{self.mysql_password}"
            f"@{self.mysql_host}:{self.mysql_port}/{self.mysql_db}?charset=utf8mb4"
        )

settings = Settings()
