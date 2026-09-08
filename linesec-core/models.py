import uuid
from sqlalchemy import Column, String, Integer, Text
from database import Base

class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    tool_name = Column(String, index=True)
    vulnerability_name = Column(String, index=True)
    severity = Column(String)
    description = Column(Text)
    file_path = Column(String)
    line_number = Column(Integer)
    remediation_status = Column(String, default="OPEN")
    root_cause = Column(Text, nullable=True)
    remediation_plan = Column(Text, nullable=True)

