"""
Report generation API routes.
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from ..reporting import ReportGenerator, ForensicReport
from ..reporting.generator import (
    TimelineEvent,
    EvidenceItem,
    AIAnalysisResult,
)

router = APIRouter(prefix="/report", tags=["Reporting"])


class ReportRequest(BaseModel):
    """Request to generate a forensic report."""

    title: str = Field(..., description="Report title")
    case_number: str | None = Field(None, description="Case number")
    incident_summary: str = Field("", description="Summary of the incident")
    incident_start: datetime | None = None
    incident_end: datetime | None = None
    conclusions: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    format: str = Field("html", description="Output format: html or pdf")


class TimelineEventRequest(BaseModel):
    """Timeline event for the report."""

    timestamp: datetime
    description: str
    severity: str = "INFO"
    source: str | None = None


# Shared generator
_generator: ReportGenerator | None = None


def get_generator() -> ReportGenerator:
    """Get or create report generator."""
    global _generator
    if _generator is None:
        from ..config import get_settings
        settings = get_settings()
        _generator = ReportGenerator(output_dir=settings.reports_dir)
    return _generator


@router.post("/generate")
async def generate_report(request: ReportRequest) -> dict[str, Any]:
    """
    Generate a forensic report.

    Creates an ISO 27037 compliant report in HTML or PDF format.
    """
    generator = get_generator()

    # Create report object
    report = ForensicReport(
        report_id=f"FR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        title=request.title,
        generated_at=datetime.utcnow(),
        generated_by="Forensic Framework v1.0",
        case_number=request.case_number,
        incident_start=request.incident_start,
        incident_end=request.incident_end,
        incident_summary=request.incident_summary,
        conclusions=request.conclusions,
        recommendations=request.recommendations,
    )

    # Generate report in requested format
    if request.format.lower() == "pdf":
        try:
            output_path = generator.generate_pdf(report)
            return {
                "success": True,
                "format": "pdf",
                "path": str(output_path),
                "report_id": report.report_id,
            }
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        output_path = generator.save_html(report)
        return {
            "success": True,
            "format": "html",
            "path": str(output_path),
            "report_id": report.report_id,
        }


@router.post("/preview", response_class=HTMLResponse)
async def preview_report(request: ReportRequest) -> HTMLResponse:
    """
    Preview a report without saving.

    Returns HTML content directly for browser preview.
    """
    generator = get_generator()

    report = ForensicReport(
        report_id=f"PREVIEW-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        title=request.title,
        generated_at=datetime.utcnow(),
        generated_by="Forensic Framework v1.0 (Preview)",
        case_number=request.case_number,
        incident_start=request.incident_start,
        incident_end=request.incident_end,
        incident_summary=request.incident_summary,
        conclusions=request.conclusions,
        recommendations=request.recommendations,
    )

    html_content = generator.generate_html(report)
    return HTMLResponse(content=html_content)


@router.get("/download/{report_id}")
async def download_report(report_id: str, format: str = "html") -> FileResponse:
    """
    Download a previously generated report.

    Returns the file for download.
    """
    generator = get_generator()
    extension = "pdf" if format.lower() == "pdf" else "html"
    filename = f"report_{report_id}.{extension}"
    file_path = generator.output_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/pdf" if extension == "pdf" else "text/html",
    )


@router.get("/list")
async def list_reports() -> dict[str, Any]:
    """List all generated reports."""
    generator = get_generator()

    reports = []
    for file in generator.output_dir.glob("report_*.html"):
        reports.append({
            "filename": file.name,
            "report_id": file.stem.replace("report_", ""),
            "format": "html",
            "size_bytes": file.stat().st_size,
            "created_at": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
        })

    for file in generator.output_dir.glob("report_*.pdf"):
        reports.append({
            "filename": file.name,
            "report_id": file.stem.replace("report_", ""),
            "format": "pdf",
            "size_bytes": file.stat().st_size,
            "created_at": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
        })

    return {
        "count": len(reports),
        "reports": sorted(reports, key=lambda r: r["created_at"], reverse=True),
    }
