import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

# Overridable for tests and production deploys (e.g. postgres in the cloud).
DATABASE_URL = os.environ.get("MALSCAN_DB_URL", "sqlite:///./malscan.db")
# Render (and Heroku-style hosts) hand out "postgres://" URLs, a scheme
# SQLAlchemy 2.0 no longer accepts — rewrite it to "postgresql://".
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    # create_all does not ALTER an existing table, so ensure the status index
    # exists on pre-existing scan_jobs tables too. Idempotent and harmless.
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_scan_jobs_status ON scan_jobs (status)"
            )
            # Same rationale for the result cache lookup (file_hash + status +
            # created_at). create_all won't add this to a pre-existing table.
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_scan_jobs_file_hash ON scan_jobs (file_hash)"
            )
            conn.commit()
    except Exception:
        pass