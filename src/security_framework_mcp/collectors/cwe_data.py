from __future__ import annotations

import io
import logging
import sqlite3
import defusedxml.ElementTree as ET
import zipfile

import httpx

log = logging.getLogger(__name__)

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cwes (
    cwe_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS cwes_fts USING fts5(
    cwe_id, name, description,
    content='cwes', content_rowid='rowid'
);
"""

# Top CWEs referenced across OWASP Top 10, API Top 10, LLM Top 10, and ASVS
CWE_DATABASE = [
    ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."),
    ("CWE-77", "Improper Neutralization of Special Elements used in a Command ('Command Injection')", "The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component."),
    ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command."),
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."),
    ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command."),
    ("CWE-94", "Improper Control of Generation of Code ('Code Injection')", "The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment."),
    ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor", "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information."),
    ("CWE-213", "Exposure of Sensitive Information Due to Incompatible Policies", "The product's intended functionality exposes information to certain actors in accordance with the developer's security policy, but the information is regarded as sensitive according to the intended security policies of other stakeholders."),
    ("CWE-259", "Use of Hard-coded Password", "The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components."),
    ("CWE-269", "Improper Privilege Management", "The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor."),
    ("CWE-276", "Incorrect Default Permissions", "During installation, installed file permissions are set to allow anyone to modify those files."),
    ("CWE-284", "Improper Access Control", "The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor."),
    ("CWE-285", "Improper Authorization", "The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action."),
    ("CWE-287", "Improper Authentication", "When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct."),
    ("CWE-307", "Improper Restriction of Excessive Authentication Attempts", "The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame."),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "The product uses a broken or risky cryptographic algorithm or protocol."),
    ("CWE-345", "Insufficient Verification of Data Authenticity", "The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data."),
    ("CWE-346", "Origin Validation Error", "The product does not properly verify that the source of data or communication is valid."),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)", "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request."),
    ("CWE-400", "Uncontrolled Resource Consumption", "The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources."),
    ("CWE-426", "Untrusted Search Path", "The product searches for critical resources using an externally-supplied search path that can point to resources that are not under the product's direct control."),
    ("CWE-434", "Unrestricted Upload of File with Dangerous Type", "The product allows the upload or transfer of dangerous file types that are automatically processed within the product's environment."),
    ("CWE-471", "Modification of Assumed-Immutable Data (MAID)", "The product does not properly protect an assumed-immutable element from being modified by an attacker."),
    ("CWE-502", "Deserialization of Untrusted Data", "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid."),
    ("CWE-506", "Embedded Malicious Code", "The product contains code that appears to be malicious in nature."),
    ("CWE-521", "Weak Password Requirements", "The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts."),
    ("CWE-522", "Insufficiently Protected Credentials", "The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval."),
    ("CWE-532", "Insertion of Sensitive Information into Log File", "Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information."),
    ("CWE-611", "Improper Restriction of XML External Entity Reference", "The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output."),
    ("CWE-639", "Authorization Bypass Through User-Controlled Key", "The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data."),
    ("CWE-770", "Allocation of Resources Without Limits or Throttling", "The product allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on the size or number of resources that can be allocated."),
    ("CWE-798", "Use of Hard-coded Credentials", "The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data."),
    ("CWE-862", "Missing Authorization", "The product does not perform an authorization check when an actor attempts to access a resource or perform an action."),
    ("CWE-863", "Incorrect Authorization", "The product performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check."),
    ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes", "The product receives input from an upstream component that specifies multiple attributes, properties, or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified."),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination."),
    ("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains", "The product uses a cross-domain policy file that includes domains that should not be trusted."),
    ("CWE-1035", "OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities", "Using components with known vulnerabilities."),
    ("CWE-1104", "Use of Unmaintained Third Party Components", "The product relies on third-party components that are not actively maintained or supported."),
]

_ALLOWED_ABSTRACTIONS = {"Base", "Variant"}


def _download_cwe_entries() -> list[tuple[str, str, str, str]]:
    resp = httpx.get(CWE_XML_URL, timeout=60, follow_redirects=True)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        with zf.open(xml_name) as f:
            tree = ET.parse(f)

    rows: list[tuple[str, str, str, str]] = []
    for weakness in tree.getroot().findall(".//cwe:Weakness", _CWE_NS):
        if weakness.get("Status") == "Deprecated":
            continue
        if weakness.get("Abstraction") not in _ALLOWED_ABSTRACTIONS:
            continue
        wid = weakness.get("ID", "")
        name = weakness.get("Name", "")
        desc_el = weakness.find("cwe:Description", _CWE_NS)
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
        cwe_id = f"CWE-{wid}"
        url = f"https://cwe.mitre.org/data/definitions/{wid}.html"
        rows.append((cwe_id, name, description, url))
    return rows


def scrape_cwes(conn: sqlite3.Connection) -> int:
    try:
        rows = _download_cwe_entries()
        log.info("Downloaded %d CWE entries from MITRE XML", len(rows))
    except Exception:
        log.warning("Failed to download CWE XML, using hardcoded fallback", exc_info=True)
        rows = [
            (cwe_id, name, desc, f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html")
            for cwe_id, name, desc in CWE_DATABASE
        ]
    conn.executemany(
        "INSERT OR REPLACE INTO cwes (cwe_id, name, description, url) VALUES (?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d CWE entries", len(rows))
    return len(rows)
