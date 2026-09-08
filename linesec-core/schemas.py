from pydantic import BaseModel
from typing import Optional

class FindingCreate(BaseModel):
    tool_name: str
    vulnerability_name: str
    severity: str
    description: str
    file_path: str
    line_number: int

class FindingResponse(FindingCreate):
    finding_id: str
    root_cause: Optional[str] = None
    remediation_plan: Optional[str] = None
    remediation_status: str

    class Config:
        orm_mode = True
        from_attributes = True
