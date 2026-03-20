from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    job_id = Column(String, primary_key=True)
    status = Column(String, default="Submitted") # Submitted, Processing, Completed
    file_hash = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    results = Column(JSON, nullable=True) # Final results from Attribution Engine