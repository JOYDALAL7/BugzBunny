import os
import sys
import subprocess
import json
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from datetime import datetime

app = FastAPI(
    title="BugzBunny API",
    description="Hop. Hunt. Hack. - REST API",
    version="2.0.0"
)

scans = {}

class ScanRequest(BaseModel):
    target: str
    output: str = "reports"

class ScanStatus(BaseModel):
    scan_id: str
    target: str
    status: str
    started_at: str
    finished_at: Optional[str] = None
    report_path: Optional[str] = None

def run_scan_task(scan_id: str, target: str, output: str):
    """Background scan task"""
    scans[scan_id]["status"] = "running"
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_py  = os.path.join(base_dir, "main.py")

        result = subprocess.run(
            [sys.executable, main_py, "scan", "--target", target, "--output", output],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=base_dir
        )
        scans[scan_id]["status"]      = "complete"
        scans[scan_id]["finished_at"] = str(datetime.now())
        scans[scan_id]["report_path"] = f"{output}/{target}/{target}_report.html"
    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"]  = str(e)

@app.get("/")
def root():
    return {"tool": "BugzBunny", "version": "2.0.0", "status": "running"}

@app.post("/scan", response_model=ScanStatus)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan"""
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{request.target}"
    scans[scan_id] = {
        "scan_id":     scan_id,
        "target":      request.target,
        "status":      "queued",
        "started_at":  str(datetime.now()),
        "finished_at": None,
        "report_path": None
    }
    background_tasks.add_task(run_scan_task, scan_id, request.target, request.output)
    return scans[scan_id]

@app.get("/scans")
def list_scans():
    """List all scans"""
    return {"scans": list(scans.values())}

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """Get scan status"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

@app.get("/scan/{scan_id}/report")
def get_report(scan_id: str):
    """Get scan report"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    if scan["status"] != "complete":
        raise HTTPException(status_code=400, detail=f"Scan is {scan['status']}")
    report = scan.get("report_path")
    if not report or not os.path.exists(report):
        raise HTTPException(status_code=404, detail="Report not found")
    with open(report) as f:
        return {"report": f.read()}

@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: str):
    """Delete a scan"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans[scan_id]
    return {"message": "Scan deleted"}
