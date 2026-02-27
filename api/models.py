# api/models.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=True)
    domain = Column(String(512), nullable=True)
    reported_by = Column(String(256), nullable=True)
    source = Column(String(64), nullable=True)
    file_type = Column(String(64), nullable=True)
    file_name = Column(String(512), nullable=True)
    ocr_text = Column(Text, nullable=True)
    analysis_details = Column(JSON, nullable=True)
    confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(Integer, nullable=True)
    user_id = Column(String(128), nullable=True)
    username = Column(String(256), nullable=True)
    message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# DB setup
DATABASE_URL = "sqlite:///scam.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)