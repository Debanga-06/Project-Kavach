from datetime import datetime

from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class EvidenceOut(BaseModel):
    signal: str
    description: str
    weight: int


class ScanOut(BaseModel):
    scan_id: str
    scan_type: str
    target: str
    risk_score: int
    severity: str
    classification: str
    confidence: float
    status: str
    evidence: list[EvidenceOut]
    recommendations: list[str]
    ai_summary: str | None = None
    ai_explanation: list[str] = []
    ai_model: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanSummaryOut(BaseModel):
    scan_id: str
    scan_type: str
    target: str
    risk_score: int
    severity: str
    classification: str
    created_at: datetime

    class Config:
        from_attributes = True
