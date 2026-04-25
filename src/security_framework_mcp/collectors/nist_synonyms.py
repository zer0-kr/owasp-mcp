from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS synonyms (
    alias TEXT NOT NULL,
    canonical TEXT NOT NULL,
    PRIMARY KEY (alias, canonical)
);
"""

_SYNONYMS: list[tuple[str, str]] = [
    ("MFA", "multi-factor authentication"),
    ("2FA", "two-factor authentication"),
    ("SSO", "single sign-on"),
    ("ZTA", "zero trust architecture"),
    ("ZT", "zero trust"),
    ("RBAC", "role-based access control"),
    ("ABAC", "attribute-based access control"),
    ("IAM", "identity and access management"),
    ("PKI", "public key infrastructure"),
    ("TLS", "transport layer security"),
    ("SSL", "secure sockets layer"),
    ("HTTPS", "HTTP over TLS"),
    ("VPN", "virtual private network"),
    ("IDS", "intrusion detection system"),
    ("IPS", "intrusion prevention system"),
    ("SIEM", "security information and event management"),
    ("SOC", "security operations center"),
    ("DLP", "data loss prevention"),
    ("WAF", "web application firewall"),
    ("XSS", "cross-site scripting"),
    ("CSRF", "cross-site request forgery"),
    ("SQLi", "SQL injection"),
    ("SSRF", "server-side request forgery"),
    ("RCE", "remote code execution"),
    ("APT", "advanced persistent threat"),
    ("CVE", "common vulnerabilities and exposures"),
    ("CWE", "common weakness enumeration"),
    ("CVSS", "common vulnerability scoring system"),
    ("SBOM", "software bill of materials"),
    ("SCA", "software composition analysis"),
    ("SAST", "static application security testing"),
    ("DAST", "dynamic application security testing"),
    ("IAST", "interactive application security testing"),
    ("RASP", "runtime application self-protection"),
    ("CI/CD", "continuous integration continuous delivery"),
    ("DevSecOps", "development security operations"),
    ("OIDC", "OpenID Connect"),
    ("SAML", "Security Assertion Markup Language"),
    ("JWT", "JSON Web Token"),
    ("HSTS", "HTTP Strict Transport Security"),
    ("CSP", "Content Security Policy"),
    ("CORS", "Cross-Origin Resource Sharing"),
    ("PII", "personally identifiable information"),
    ("PHI", "protected health information"),
    ("GDPR", "General Data Protection Regulation"),
    ("HIPAA", "Health Insurance Portability and Accountability Act"),
    ("FedRAMP", "Federal Risk and Authorization Management Program"),
    ("FISMA", "Federal Information Security Modernization Act"),
    ("ATO", "authorization to operate"),
    ("POA&M", "plan of action and milestones"),
    ("SSP", "system security plan"),
    ("RMF", "risk management framework"),
    ("CSF", "cybersecurity framework"),
]


def scrape_synonyms(conn: sqlite3.Connection) -> int:
    conn.executemany(
        "INSERT OR REPLACE INTO synonyms (alias, canonical) VALUES (?, ?)",
        _SYNONYMS,
    )
    conn.commit()
    log.info("Loaded %d synonym pairs", len(_SYNONYMS))
    return len(_SYNONYMS)
