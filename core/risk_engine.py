from dataclasses import dataclass, field
from core.normalizer import NormalizedFinding
import uuid

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.0
}

MODIFIERS = {
    "no_waf":          +2.0,
    "has_secret":      +3.0,
    "cors_with_creds": +3.5,
    "known_cve":       +2.5,
    "open_port_80":    +1.0,
    "open_port_443":   +0.5,
    "waf_present":     -2.0,
    "low_confidence":  -1.0,
}

@dataclass
class AttackChain:
    host:              str
    risk_score:        float
    findings:          list
    modifiers_applied: list
    recommendation:    str

@dataclass
class AttackPath:
    chain_id:    str
    host:        str
    steps:       list
    severity:    str
    impact:      str
    risk_score:  float
    exploitable: bool

class RiskEngine:

    def __init__(self, findings: list):
        self.findings = findings

    def _group_by_host(self) -> dict:
        groups = {}
        for f in self.findings:
            host = f.host
            if host not in groups:
                groups[host] = []
            groups[host].append(f)
        return groups

    def _apply_modifiers(self, host_findings: list) -> tuple:
        applied   = []
        mod_score = 0.0

        types      = [f.finding_type for f in host_findings]
        ports      = [f.port for f in host_findings if f.port]
        has_waf    = any(f.finding_type == "waf" and f.metadata.get("protected", False) for f in host_findings)
        no_waf     = any(f.finding_type == "waf" and not f.metadata.get("protected", False) for f in host_findings)
        has_secret = "secret" in types
        has_cve    = "cve" in types
        has_cors   = any(f.finding_type == "cors" and f.metadata.get("credentials", False) for f in host_findings)
        low_conf   = any(f.confidence < 0.5 for f in host_findings)

        if no_waf:
            applied.append("no_waf")
            mod_score += MODIFIERS["no_waf"]
        if has_waf:
            applied.append("waf_present")
            mod_score += MODIFIERS["waf_present"]
        if has_secret:
            applied.append("has_secret")
            mod_score += MODIFIERS["has_secret"]
        if has_cve:
            applied.append("known_cve")
            mod_score += MODIFIERS["known_cve"]
        if has_cors:
            applied.append("cors_with_creds")
            mod_score += MODIFIERS["cors_with_creds"]
        if 80 in ports:
            applied.append("open_port_80")
            mod_score += MODIFIERS["open_port_80"]
        if 443 in ports:
            applied.append("open_port_443")
            mod_score += MODIFIERS["open_port_443"]
        if low_conf:
            applied.append("low_confidence")
            mod_score += MODIFIERS["low_confidence"]

        return applied, mod_score

    def _calculate_score(self, host_findings: list, modifier_score: float) -> float:
        if not host_findings:
            return 0.0
        scores     = [SEVERITY_WEIGHTS.get(f.severity, 0.0) * f.confidence for f in host_findings]
        base_score = sum(scores) / len(scores)
        final      = base_score + modifier_score
        return round(min(10.0, max(0.0, final)), 2)

    def _generate_recommendation(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL: Immediate action required. High probability of exploitation."
        elif score >= 7.0:
            return "HIGH: Address within 24 hours. Significant attack surface exposed."
        elif score >= 5.0:
            return "MEDIUM: Schedule remediation within 1 week."
        elif score >= 2.5:
            return "LOW: Monitor and address in next security cycle."
        else:
            return "INFO: No immediate action required."

    def build_attack_paths(self, host: str, host_findings: list, score: float) -> AttackPath:
        steps        = []
        impact_parts = []

        for f in host_findings:
            if f.finding_type == "port":
                port_num = f.port or "unknown"
                steps.append(f"open_port:{port_num}")
                impact_parts.append(f"open port {port_num}")
            elif f.finding_type == "vulnerability":
                steps.append(f"vuln:{f.title}")
                impact_parts.append(f"vulnerability: {f.title}")
            elif f.finding_type == "cve":
                steps.append(f"cve:{f.title}")
                impact_parts.append(f"known CVE: {f.title}")
            elif f.finding_type == "waf":
                protected = f.metadata.get("protected", False)
                if protected:
                    steps.append(f"waf:{f.metadata.get('waf_name', 'unknown')}")
                    impact_parts.append("WAF protected")
                else:
                    steps.append("no_waf")
                    impact_parts.append("no WAF protection")
            elif f.finding_type == "cors":
                has_creds = f.metadata.get("credentials", False)
                if has_creds:
                    steps.append("cors:credentials")
                    impact_parts.append("CORS misconfiguration with credentials")
                else:
                    steps.append("cors:wildcard")
                    impact_parts.append("CORS wildcard misconfiguration")
            elif f.finding_type == "secret":
                steps.append(f"secret:{f.title}")
                impact_parts.append(f"exposed secret: {f.title}")
            elif f.finding_type == "tech":
                tech_name = f.metadata.get("name", f.title)
                steps.append(f"tech:{tech_name}")

        if score >= 9.0:
            severity = "critical"
        elif score >= 7.0:
            severity = "high"
        elif score >= 5.0:
            severity = "medium"
        else:
            severity = "low"

        types       = [f.finding_type for f in host_findings]
        has_port    = "port" in types
        has_cve     = "cve" in types or "vulnerability" in types
        has_sec     = "secret" in types
        has_cors    = "cors" in types
        no_waf      = any(
            f.finding_type == "waf" and not f.metadata.get("protected", False)
            for f in host_findings
        )
        exploitable = has_port and (has_cve or has_sec or has_cors) and no_waf

        impact = f"Host {host} exposed with: {', '.join(impact_parts)}" if impact_parts \
                 else f"Host {host} has potential attack surface"

        return AttackPath(
            chain_id    = str(uuid.uuid4())[:8],
            host        = host,
            steps       = steps,
            severity    = severity,
            impact      = impact,
            risk_score  = score,
            exploitable = exploitable
        )

    def run(self) -> tuple:
        """Run risk engine — returns (chains, attack_paths)"""
        groups       = self._group_by_host()
        chains       = []
        attack_paths = []

        for host, host_findings in groups.items():
            modifiers, mod_score = self._apply_modifiers(host_findings)
            score                = self._calculate_score(host_findings, mod_score)
            recommendation       = self._generate_recommendation(score)

            # Build attack chain
            chains.append(AttackChain(
                host              = host,
                risk_score        = score,
                findings          = host_findings,
                modifiers_applied = modifiers,
                recommendation    = recommendation
            ))

            # Build attack path
            path = self.build_attack_paths(host, host_findings, score)
            attack_paths.append(path)

        # Sort chains by risk score
        chains.sort(key=lambda x: x.risk_score, reverse=True)

        # Sort paths: exploitable first, then by risk score
        attack_paths.sort(key=lambda x: (not x.exploitable, -x.risk_score))

        return chains, attack_paths
