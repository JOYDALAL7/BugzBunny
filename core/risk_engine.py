from dataclasses import dataclass, field
from core.normalizer import NormalizedFinding

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

class RiskEngine:

    def __init__(self, findings: list):
        self.findings = findings

    def _group_by_host(self) -> dict:
        """Group all findings by host"""
        groups = {}
        for f in self.findings:
            host = f.host
            if host not in groups:
                groups[host] = []
            groups[host].append(f)
        return groups

    def _apply_modifiers(self, host_findings: list) -> tuple:
        """Check findings and return applicable modifiers"""
        applied    = []
        mod_score  = 0.0

        types      = [f.finding_type for f in host_findings]
        ports      = [f.port for f in host_findings if f.port]
        has_waf    = any(
            f.finding_type == "waf" and
            f.metadata.get("protected", False)
            for f in host_findings
        )
        no_waf     = any(
            f.finding_type == "waf" and
            not f.metadata.get("protected", False)
            for f in host_findings
        )
        has_secret = "secret" in types
        has_cve    = "cve" in types
        has_cors   = any(
            f.finding_type == "cors" and
            f.metadata.get("credentials", False)
            for f in host_findings
        )
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
        """Calculate final risk score for a host"""
        if not host_findings:
            return 0.0

        # Average of (severity_weight * confidence) across all findings
        scores = [
            SEVERITY_WEIGHTS.get(f.severity, 0.0) * f.confidence
            for f in host_findings
        ]
        base_score = sum(scores) / len(scores)

        # Add modifiers
        final = base_score + modifier_score

        # Clamp between 0.0 and 10.0
        return round(min(10.0, max(0.0, final)), 2)

    def _generate_recommendation(self, score: float) -> str:
        """Generate recommendation based on risk score"""
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

    def run(self) -> list:
        """Run the risk engine and return prioritized attack chains"""
        groups = self._group_by_host()
        chains = []

        for host, host_findings in groups.items():
            modifiers, mod_score  = self._apply_modifiers(host_findings)
            score                 = self._calculate_score(host_findings, mod_score)
            recommendation        = self._generate_recommendation(score)

            chains.append(AttackChain(
                host              = host,
                risk_score        = score,
                findings          = host_findings,
                modifiers_applied = modifiers,
                recommendation    = recommendation
            ))

        # Sort by risk score descending
        chains.sort(key=lambda x: x.risk_score, reverse=True)
        return chains
