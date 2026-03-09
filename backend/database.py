import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import StaticPool
from .config import settings

# Resolve SQLite paths to absolute, anchored to the project root.
# sqlite:///  = relative path, sqlite://// = already absolute
_db_url = settings.DATABASE_URL
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _db_url.startswith("sqlite:///") and not _db_url.startswith("sqlite:////"):
    _rel_path = _db_url[len("sqlite:///"):]
    _abs_path = os.path.join(_project_root, _rel_path)
    os.makedirs(os.path.dirname(_abs_path) or _project_root, exist_ok=True)
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
