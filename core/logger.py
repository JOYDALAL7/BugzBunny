import json
import os
import uuid
from datetime import datetime

class ScanLogger:
    """Structured JSON logger for BugzBunny scans"""

    def __init__(self, scan_id: str, target: str, log_dir: str):
        self.scan_id  = scan_id
        self.target   = target
        self.log_file = os.path.join(log_dir, f"{scan_id}.log")

        # Create log directory if needed
        os.makedirs(log_dir, exist_ok=True)

        # Write scan start entry
        self.info("scanner", "scan_started", {
            "target":  target,
            "scan_id": scan_id
        })

    def _write(self, level: str, module: str, event: str, data: dict):
        """Write a structured JSON log entry"""
        entry = {
            "ts":      datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            "scan_id": self.scan_id,
            "target":  self.target,
            "module":  module,
            "level":   level,
            "event":   event,
            "data":    data
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def info(self, module: str, event: str, data: dict = {}):
        """Log an info event"""
        self._write("INFO", module, event, data)

    def warning(self, module: str, event: str, data: dict = {}):
        """Log a warning event"""
        self._write("WARNING", module, event, data)

    def error(self, module: str, event: str, data: dict = {}):
        """Log an error event"""
        self._write("ERROR", module, event, data)

    def metric(self, module: str, duration_ms: float, findings_count: int):
        """Log performance metrics for a module"""
        self._write("METRIC", module, "module_complete", {
            "duration_ms":    round(duration_ms, 2),
            "findings_count": findings_count
        })


def create_logger(target: str, output_dir: str) -> ScanLogger:
    """Create a new logger for a scan"""
    scan_id  = str(uuid.uuid4())[:8]
    log_dir  = os.path.join(output_dir, "logs")
    return ScanLogger(scan_id, target, log_dir)
