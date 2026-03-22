from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class NormalizedFinding:
    host:         str
    module:       str
    finding_type: str
    title:        str
    severity:     str
    confidence:   float
    evidence:     str
    ip:           Optional[str] = None
    port:         Optional[int] = None
    metadata:     dict          = field(default_factory=dict)
    timestamp:    datetime      = field(default_factory=datetime.now)


class Normalizer:

    def normalize_ports(self, port_results: dict) -> list:
        findings = []
        for host, ports in port_results.items():
            for p in ports:
                findings.append(NormalizedFinding(
                    host         = host,
                    module       = "portscan",
                    finding_type = "port",
                    title        = f"Open port {p['port']}/{p['service']}",
                    severity     = "info",
                    confidence   = 1.0,
                    evidence     = f"{host}:{p['port']} ({p['service']})",
                    port         = p["port"],
                    metadata     = {"service": p["service"]}
                ))
        return findings

    def normalize_vulns(self, vuln_results: dict) -> list:
        findings = []
        severity_confidence = {
            "critical": 0.95,
            "high":     0.85,
            "medium":   0.75,
            "low":      0.60
        }
        for sev, vulns in vuln_results.items():
            for v in vulns:
                findings.append(NormalizedFinding(
                    host         = v.get("host", ""),
                    module       = "nuclei",
                    finding_type = "vulnerability",
                    title        = v.get("name", "Unknown"),
                    severity     = sev,
                    confidence   = severity_confidence.get(sev, 0.7),
                    evidence     = v.get("matched", ""),
                    metadata     = {"tags": v.get("tags", [])}
                ))
        return findings

    def normalize_cves(self, cve_results: dict, live_hosts: list = []) -> list:
        """
        Normalize CVE lookup results.
        KEY FIX: CVEs are keyed by tech name (e.g. 'Apache') but
        must be assigned to real scanned hosts so risk engine can
        correlate port + CVE on the same host.
        """
        findings = []

        # Build a clean list of real hosts to assign CVEs to
        # Use first live host as fallback if no better match
        real_hosts = []
        for h in live_hosts:
            real_hosts.append(h.split()[0])

        for tech, cves in cve_results.items():
            for cve in cves:
                score = cve.get("score", 0)
                try:
                    score = float(score)
                except Exception:
                    score = 0.0

                if score >= 9.0:
                    severity = "critical"
                elif score >= 7.0:
                    severity = "high"
                elif score >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"

                # ── KEY FIX ──────────────────────────────────
                # Assign CVE to real hosts, not tech name
                # This allows risk engine to correlate:
                # port(scanme.nmap.org) + cve(scanme.nmap.org)
                hosts_to_assign = real_hosts if real_hosts else [tech]

                for host in hosts_to_assign:
                    findings.append(NormalizedFinding(
                        host         = host,
                        module       = "cve_lookup",
                        finding_type = "cve",
                        title        = cve.get("id", "Unknown CVE"),
                        severity     = severity,
                        confidence   = min(1.0, score / 10.0),
                        evidence     = cve.get("description", "")[:200],
                        metadata     = {
                            "score":    score,
                            "severity": cve.get("severity", "N/A"),
                            "tech":     tech
                        }
                    ))
        return findings

    def normalize_secrets(self, js_results: dict) -> list:
        findings = []
        for host, secrets in js_results.items():
            for s in secrets:
                findings.append(NormalizedFinding(
                    host         = host,
                    module       = "js_secrets",
                    finding_type = "secret",
                    title        = s.get("type", "Unknown Secret"),
                    severity     = "high",
                    confidence   = 0.80,
                    evidence     = s.get("match", "")[:100],
                    metadata     = {
                        "source_url":  s.get("url", ""),
                        "secret_type": s.get("type", "")
                    }
                ))
        return findings

    def normalize_cors(self, cors_results: dict) -> list:
        findings = []
        for host, issues in cors_results.items():
            for issue in issues:
                has_creds  = issue.get("credentials", "").lower() == "true"
                severity   = "critical" if has_creds else "high"
                confidence = 0.95 if has_creds else 0.85
                findings.append(NormalizedFinding(
                    host         = host,
                    module       = "cors",
                    finding_type = "cors",
                    title        = issue.get("issue", "CORS Misconfiguration"),
                    severity     = severity,
                    confidence   = confidence,
                    evidence     = f"Origin: {issue.get('origin')} → ACAO: {issue.get('acao')}",
                    metadata     = {
                        "origin":      issue.get("origin"),
                        "acao":        issue.get("acao"),
                        "credentials": has_creds
                    }
                ))
        return findings

    def normalize_waf(self, waf_results: dict) -> list:
        findings = []
        for host, waf in waf_results.items():
            no_waf = "no waf" in waf.lower() if isinstance(waf, str) else True
            findings.append(NormalizedFinding(
                host         = host,
                module       = "waf",
                finding_type = "waf",
                title        = "No WAF Detected" if no_waf else f"WAF: {waf}",
                severity     = "medium" if no_waf else "info",
                confidence   = 0.90,
                evidence     = waf if isinstance(waf, str) else "No WAF",
                metadata     = {
                    "waf_name":  waf,
                    "protected": not no_waf
                }
            ))
        return findings

    def normalize_all(self, port_results: dict = {}, vuln_results: dict = {},
                      cve_results: dict = {}, js_results: dict = {},
                      cors_results: dict = {}, waf_results: dict = {},
                      live_hosts: list = []) -> list:
        """Normalize all module outputs into a flat list of NormalizedFindings"""

        all_findings = []
        all_findings.extend(self.normalize_ports(port_results))
        all_findings.extend(self.normalize_vulns(vuln_results))
        all_findings.extend(self.normalize_cves(cve_results, live_hosts))
        all_findings.extend(self.normalize_secrets(js_results))
        all_findings.extend(self.normalize_cors(cors_results))
        all_findings.extend(self.normalize_waf(waf_results))

        return all_findings
