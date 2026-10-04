from pathlib import Path
import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from backend.analyzer import analyze_directory, get_summary

from backend.database import (
    initialize_database,
    create_scan,
    save_findings,
    get_scan_history,
    get_scan,
    get_findings_for_scan,
)


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


app = FastAPI(
    title="ECDAT",
    description="Enterprise Cryptographic Discovery & Analysis Tool",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    directory: str


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/")
def root():
    return FileResponse(
        FRONTEND_DIR / "index.html"
    )


@app.get("/api/status")
def status():
    return {
        "name": "ECDAT",
        "version": "1.0.0",
        "status": "running",
    }


@app.post("/scan")
def scan(request: ScanRequest):

    findings = analyze_directory(
        request.directory
    )

    summary = get_summary(
        findings,
        request.directory
    )

    scan_id = create_scan(
        request.directory,
        summary
    )

    if findings:
        save_findings(
            findings,
            scan_id
        )

    return {
        "message": "Scan completed",
        "scan_id": scan_id,
        "summary": summary,
        "findings": findings,
    }


@app.get("/history")
def history():
    return {
        "scans": get_scan_history()
    }


@app.get("/history/{scan_id}")
def history_detail(scan_id: int):

    scan = get_scan(scan_id)

    if scan is None:
        return {
            "error": "Scan not found"
        }

    findings = get_findings_for_scan(
        scan_id
    )

    return {
        "scan": scan,
        "findings": findings,
    }


@app.get("/report/{scan_id}")
def report(scan_id: int):

    scan = get_scan(scan_id)

    if scan is None:
        return {
            "error": "Scan not found"
        }

    findings = get_findings_for_scan(
        scan_id
    )

    report_data = {
        "tool": "ECDAT",
        "version": "1.0.0",
        "scan": scan,
        "findings": findings,
    }

    report_json = json.dumps(
        report_data,
        indent=2
    )

    return Response(
        content=report_json,
        media_type="application/json",
        headers={
            "Content-Disposition":
                f'attachment; filename="ecdat_scan_{scan_id}.json"'
        },
    )


@app.get("/style.css")
def style():
    return FileResponse(
        FRONTEND_DIR / "style.css",
        media_type="text/css",
    )


@app.get("/app.js")
def javascript():
    return FileResponse(
        FRONTEND_DIR / "app.js",
        media_type="application/javascript",
    )
