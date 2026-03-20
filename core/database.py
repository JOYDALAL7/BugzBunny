import json
import os
from datetime import datetime
from peewee import *

db = SqliteDatabase(None)

class BaseModel(Model):
    class Meta:
        database = db

# ── Core Scan ──────────────────────────────────────────
class Scan(BaseModel):
    target      = CharField()
    started_at  = DateTimeField(default=datetime.now)
    finished_at = DateTimeField(null=True)
    status      = CharField(default="running")

# ── Normalized Tables ──────────────────────────────────
class Target(BaseModel):
    """Root domain being scanned"""
    domain      = CharField(unique=True)
    first_seen  = DateTimeField(default=datetime.now)
    last_seen   = DateTimeField(default=datetime.now)

class Host(BaseModel):
    """Each live subdomain/host discovered"""
    scan        = ForeignKeyField(Scan, backref="hosts")
    target      = ForeignKeyField(Target, backref="hosts")
    url         = CharField()
    ip          = CharField(null=True)
    status_code = IntegerField(null=True)
    is_live     = BooleanField(default=True)
    discovered_at = DateTimeField(default=datetime.now)

class Port(BaseModel):
    """Each open port per host"""
    host        = ForeignKeyField(Host, backref="ports")
    scan        = ForeignKeyField(Scan, backref="ports")
    number      = IntegerField()
    protocol    = CharField(default="tcp")
    service     = CharField(null=True)
    banner      = TextField(null=True)

class Technology(BaseModel):
    """Each technology detected per host"""
    host        = ForeignKeyField(Host, backref="technologies")
    scan        = ForeignKeyField(Scan, backref="technologies")
    name        = CharField()
    version     = CharField(null=True)
    confidence  = FloatField(default=1.0)

class WAFResult(BaseModel):
    """WAF detection result per host"""
    host        = ForeignKeyField(Host, backref="waf")
    scan        = ForeignKeyField(Scan, backref="waf_results")
    detected    = BooleanField(default=False)
    waf_name    = CharField(null=True)
    provider    = CharField(null=True)

class Secret(BaseModel):
    """Each JS secret found per host"""
    host        = ForeignKeyField(Host, backref="secrets")
    scan        = ForeignKeyField(Scan, backref="secrets")
    secret_type = CharField()
    match       = TextField()
    source_url  = TextField()
    severity    = CharField(default="high")

class CORSResult(BaseModel):
    """Each CORS issue found per host"""
    host        = ForeignKeyField(Host, backref="cors")
    scan        = ForeignKeyField(Scan, backref="cors_results")
    origin      = CharField()
    acao        = CharField()
    credentials = BooleanField(default=False)
    severity    = CharField(default="high")
    issue       = TextField()

class RiskChain(BaseModel):
    """Correlated attack chain (filled by risk engine later)"""
    scan        = ForeignKeyField(Scan, backref="risk_chains")
    host        = ForeignKeyField(Host, backref="risk_chains")
    risk_score  = FloatField(default=0.0)
    title       = CharField()
    description = TextField(default="")
    findings    = TextField(default="")  # JSON list of finding IDs
    created_at  = DateTimeField(default=datetime.now)

# ── Legacy Finding (keep for backward compat) ──────────
class Finding(BaseModel):
    scan        = ForeignKeyField(Scan, backref="findings")
    module      = CharField()
    type        = CharField()
    title       = CharField()
    description = TextField(default="")
    data        = TextField(default="")

# ── All Tables ─────────────────────────────────────────
ALL_TABLES = [
    Scan, Target, Host, Port, Technology,
    WAFResult, Secret, CORSResult, RiskChain, Finding
]

# ── Init ───────────────────────────────────────────────
def init_db(output_dir: str):
    """Initialize SQLite database for target"""
    db_path = os.path.join(output_dir, "bugzbunny.db")
    db.init(db_path)
    db.connect()
    db.create_tables(ALL_TABLES, safe=True)
    return db_path

def create_scan(target: str) -> Scan:
    """Create a new scan record"""
    return Scan.create(target=target)

def save_finding(scan: Scan, module: str, ftype: str, title: str,
                 description: str = "", data: dict = {}):
    """Save a finding to the legacy findings table"""
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
        "target":         scan.target,
        "started_at":     str(scan.started_at),
        "finished_at":    str(scan.finished_at),
        "total_findings": findings.count(),
        "by_type":        {},
        "by_module":      {}
    }
    for f in findings:
        summary["by_type"][f.type]     = summary["by_type"].get(f.type, 0) + 1
        summary["by_module"][f.module] = summary["by_module"].get(f.module, 0) + 1
    return summary
