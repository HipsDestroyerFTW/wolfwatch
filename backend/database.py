import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import StaticPool
from .config import settings

# Resolve relative SQLite paths against the project root (where this package lives)
_db_url = settings.DATABASE_URL
if _db_url.startswith("sqlite:///./") or _db_url.startswith("sqlite:///wolfwatch"):
    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _rel_path = _db_url.replace("sqlite:///", "", 1)
    _abs_path = os.path.join(_project_root, _rel_path)
    os.makedirs(os.path.dirname(_abs_path), exist_ok=True)
    _db_url = f"sqlite:///{_abs_path}"

engine = create_engine(
    _db_url,
    connect_args={"check_same_thread": False} if "sqlite" in _db_url else {},
    poolclass=StaticPool if "sqlite" in _db_url else None,
)

# Enable WAL mode for SQLite for better concurrent read performance
if "sqlite" in _db_url:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401 — ensures models are registered
    Base.metadata.create_all(bind=engine)
