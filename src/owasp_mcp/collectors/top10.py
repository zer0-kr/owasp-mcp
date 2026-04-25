from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS top10 (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    cwes TEXT,
    url TEXT
);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS top10_fts USING fts5(
    id, name, description, cwes,
    content='top10', content_rowid='rowid'
);
"""

# OWASP Top 10 2021 — stable, well-known data with CWE mappings
TOP10_2021 = [
    {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": (
            "Access control enforces policy such that users cannot act outside of their intended "
            "permissions. Failures typically lead to unauthorized information disclosure, modification, "
            "or destruction of data, or performing a business function outside the user's limits."
        ),
        "cwes": "CWE-200, CWE-201, CWE-352, CWE-566, CWE-639, CWE-862, CWE-863, CWE-284, CWE-285, CWE-22, CWE-23, CWE-35, CWE-59, CWE-219, CWE-264, CWE-275, CWE-276, CWE-384, CWE-425, CWE-532, CWE-538, CWE-540, CWE-548, CWE-552, CWE-668, CWE-706, CWE-862, CWE-863, CWE-913, CWE-922, CWE-1275",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": (
            "Formerly known as Sensitive Data Exposure. Failures related to cryptography which often "
            "lead to sensitive data exposure. Includes use of hard-coded passwords, broken or risky "
            "crypto algorithms, and insufficient entropy."
        ),
        "cwes": "CWE-259, CWE-327, CWE-331, CWE-261, CWE-296, CWE-310, CWE-319, CWE-320, CWE-321, CWE-322, CWE-323, CWE-324, CWE-325, CWE-326, CWE-328, CWE-329, CWE-330, CWE-332, CWE-334, CWE-335, CWE-336, CWE-337, CWE-338, CWE-340, CWE-347, CWE-523, CWE-720, CWE-757, CWE-759, CWE-760, CWE-780, CWE-818, CWE-916",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    {
        "id": "A03:2021",
        "name": "Injection",
        "description": (
            "An application is vulnerable to injection when user-supplied data is not validated, "
            "filtered, or sanitized. Includes SQL injection, NoSQL injection, OS command injection, "
            "LDAP injection, and Cross-site Scripting (XSS)."
        ),
        "cwes": "CWE-79, CWE-89, CWE-73, CWE-74, CWE-75, CWE-77, CWE-78, CWE-80, CWE-83, CWE-87, CWE-88, CWE-90, CWE-91, CWE-93, CWE-94, CWE-95, CWE-96, CWE-97, CWE-98, CWE-99, CWE-100, CWE-113, CWE-116, CWE-138, CWE-184, CWE-470, CWE-471, CWE-564, CWE-610, CWE-643, CWE-644, CWE-652, CWE-917",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": (
            "A new category focusing on risks related to design and architectural flaws, calling for "
            "more use of threat modeling, secure design patterns, and reference architectures. "
            "Insecure design cannot be fixed by a perfect implementation."
        ),
        "cwes": "CWE-73, CWE-183, CWE-209, CWE-213, CWE-235, CWE-256, CWE-257, CWE-266, CWE-269, CWE-280, CWE-311, CWE-312, CWE-313, CWE-316, CWE-419, CWE-430, CWE-434, CWE-444, CWE-451, CWE-472, CWE-501, CWE-522, CWE-525, CWE-539, CWE-579, CWE-598, CWE-602, CWE-642, CWE-646, CWE-650, CWE-653, CWE-656, CWE-657, CWE-799, CWE-807, CWE-840, CWE-841, CWE-927, CWE-1021, CWE-1173",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "The application might be vulnerable if it is missing appropriate security hardening, "
            "has improperly configured permissions, uses unnecessary features, default accounts, "
            "or error handling reveals overly informative error messages."
        ),
        "cwes": "CWE-2, CWE-11, CWE-13, CWE-15, CWE-16, CWE-260, CWE-315, CWE-520, CWE-526, CWE-537, CWE-541, CWE-547, CWE-611, CWE-614, CWE-756, CWE-776, CWE-942, CWE-1004, CWE-1032, CWE-1174",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": (
            "You are likely vulnerable if you do not know the versions of all components you use, "
            "the software is unsupported or out of date, you do not scan for vulnerabilities "
            "regularly, or you do not fix or upgrade the underlying platform and frameworks."
        ),
        "cwes": "CWE-1035, CWE-1104",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": (
            "Confirmation of the user's identity, authentication, and session management is critical "
            "to protect against authentication-related attacks. Includes weak passwords, improper "
            "credential storage, and session fixation."
        ),
        "cwes": "CWE-255, CWE-287, CWE-288, CWE-290, CWE-294, CWE-295, CWE-297, CWE-300, CWE-302, CWE-304, CWE-306, CWE-307, CWE-346, CWE-384, CWE-521, CWE-613, CWE-620, CWE-640, CWE-798, CWE-940, CWE-1216",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": (
            "A new category focusing on making assumptions related to software updates, critical data, "
            "and CI/CD pipelines without verifying integrity. Includes insecure deserialization."
        ),
        "cwes": "CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-830, CWE-915",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": (
            "This category helps detect, escalate, and respond to active breaches. Without logging "
            "and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, "
            "and active response occurs any time."
        ),
        "cwes": "CWE-117, CWE-223, CWE-532, CWE-778",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": (
            "SSRF flaws occur when a web application fetches a remote resource without validating "
            "the user-supplied URL. It allows an attacker to coerce the application to send a "
            "crafted request to an unexpected destination."
        ),
        "cwes": "CWE-918",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
]


def scrape_top10(conn: sqlite3.Connection) -> int:
    rows = [
        (item["id"], item["name"], item["description"], item["cwes"], item["url"])
        for item in TOP10_2021
    ]

    conn.executemany(
        "INSERT OR REPLACE INTO top10 (id, name, description, cwes, url) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    log.info("Loaded %d Top 10 items", len(rows))
    return len(rows)
