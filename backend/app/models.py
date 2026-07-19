from sqlalchemy import Column, String, DateTime, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    job_id = Column(String, primary_key=True)
    status = Column(String, default="Submitted", index=True) # Submitted, Processing, Completed
    # Indexed: the 24h result cache looks up prior completed jobs by file_hash
    # (see _find_cached_result in app/main.py) so a re-scan of the same bytes
    # returns the same verdict without re-running the whole pipeline.
    file_hash = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    results = Column(JSON, nullable=True) # Final results from Attribution Engine


class IndicatorIndex(Base):
    """Inverted index of indicators → job, for O(k·log n) cross-job clustering.

    One row per (indicator value, kind) per job. Populated when a job completes
    (see app/indicator_index.py). Avoids loading every prior job's full results
    on each scan.
    """
    __tablename__ = "indicator_index"
    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String, index=True, nullable=False)   # the IOC / ASN / registrar string
    kind = Column(String, nullable=False)                # 'ip' | 'domain' | 'asn' | 'registrar'
    job_id = Column(String, index=True, nullable=False)