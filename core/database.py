import json
import os
from datetime import datetime
from peewee import *

db = SqliteDatabase(None)  # initialized later

class BaseModel(Model):
    class Meta:
        database = db

class Scan(BaseModel):
    target      = CharField()
    started_at  = DateTimeField(default=datetime.now)
    finished_at = DateTimeField(null=True)
    status      = CharField(default="running")

class Finding(BaseModel):
    scan        = ForeignKeyField(Scan, backref="findings")
    module      = CharField()
    type        = CharField()
    title       = CharField()
    description = TextField(default="")
    data        = TextField(default="")

def init_db(output_dir: str):
    """Initialize SQLite database for target"""
    db_path = os.path.join(output_dir, "bugzbunny.db")
    db.init(db_path)
    db.connect()
    db.create_tables([Scan, Finding], safe=True)
    return db_path

def create_scan(target: str) -> Scan:
    """Create a new scan record"""
    return Scan.create(target=target)

def save_finding(scan: Scan, module: str, ftype: str, title: str,
                 description: str = "", data: dict = {}):
    """Save a finding to the database"""
    Finding.create(
        scan=scan,
        module=module,
        type=ftype,
        title=title,
        description=description,
        data=json.dumps(data)
    )

def complete_scan(scan: Scan):
    """Mark scan as complete"""
    scan.finished_at = datetime.now()
    scan.status = "complete"
    scan.save()

def get_scan_summary(scan: Scan) -> dict:
    """Get summary of findings for a scan"""
    findings = Finding.select().where(Finding.scan == scan)
    summary = {
        "target": scan.target,
        "started_at": str(scan.started_at),
        "finished_at": str(scan.finished_at),
        "total_findings": findings.count(),
        "by_type": {},
        "by_module": {}
    }
    for f in findings:
        summary["by_type"][f.type] = summary["by_type"].get(f.type, 0) + 1
        summary["by_module"][f.module] = summary["by_module"].get(f.module, 0) + 1
    return summary
