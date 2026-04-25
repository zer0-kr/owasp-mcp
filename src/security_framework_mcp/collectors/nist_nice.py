from __future__ import annotations

import logging
import sqlite3

log = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nist_nice (
    id TEXT PRIMARY KEY,
    name TEXT,
    category TEXT,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_nice_category ON nist_nice(category);
CREATE VIRTUAL TABLE IF NOT EXISTS nist_nice_fts USING fts5(
    id, name, category, description,
    content='nist_nice', content_rowid='rowid'
);
"""

# NICE Framework v2.1 (SP 800-181r1) — 7 categories + 52 work roles
_ROLES: list[tuple[str, str, str, str]] = [
    ("SP-RSK-001", "Authorizing Official/Designating Representative", "Securely Provision", "Senior official who grants authorization for information system operation and accepts risk on behalf of the organization."),
    ("SP-DEV-001", "Software Developer", "Securely Provision", "Develops and writes/codes new or modifies existing computer applications, software, or specialized utility programs following software assurance best practices."),
    ("SP-DEV-002", "Secure Software Assessor", "Securely Provision", "Analyzes the security of new or existing computer applications, software, or specialized utility programs and provides actionable results."),
    ("SP-ARC-001", "Enterprise Architect", "Securely Provision", "Develops and maintains business, systems, and information processes to support enterprise mission needs with security architecture requirements."),
    ("SP-ARC-002", "Security Architect", "Securely Provision", "Ensures that the stakeholder security requirements necessary to protect the organization's mission are adequately addressed in all aspects of enterprise architecture."),
    ("SP-SRP-001", "Research & Development Specialist", "Securely Provision", "Conducts software and systems engineering and software systems research to develop new capabilities, ensuring cybersecurity is integrated."),
    ("SP-TRD-001", "Systems Requirements Planner", "Securely Provision", "Consults with customers to evaluate functional requirements and translate functional requirements into technical solutions."),
    ("SP-TST-001", "System Testing and Evaluation Specialist", "Securely Provision", "Plans, prepares, and executes tests of systems to evaluate results against specifications and requirements."),
    ("OM-NET-001", "Network Operations Specialist", "Operate and Maintain", "Plans, implements, and operates network services/systems, including hardware and virtual environments."),
    ("OM-STS-001", "System Administrator", "Operate and Maintain", "Responsible for setting up and maintaining a system or specific components of a system including hardware and software."),
    ("OM-DTA-001", "Data Analyst", "Operate and Maintain", "Examines data from multiple disparate sources with the goal of providing security and privacy insight to the organization."),
    ("OM-DTA-002", "Database Administrator", "Operate and Maintain", "Administers databases and data management systems that allow for the secure storage, query, and utilization of data."),
    ("OM-KMG-001", "Knowledge Manager", "Operate and Maintain", "Responsible for the management and administration of processes and tools for identifying, curating, and distributing organizational knowledge."),
    ("OM-ANA-001", "Technical Support Specialist", "Operate and Maintain", "Provides technical support to customers who need assistance using client-level hardware and software."),
    ("OV-LGA-001", "Cyber Legal Advisor", "Oversee and Govern", "Provides legal advice and recommendations on relevant topics related to cyber law."),
    ("OV-LGA-002", "Privacy Officer/Compliance Manager", "Oversee and Govern", "Develops and oversees privacy compliance program and ensures PII handling conformance with laws and regulations."),
    ("OV-PMA-001", "Cyber Workforce Developer and Manager", "Oversee and Govern", "Develops cyberspace workforce plans, strategies, and guidance to support workforce manpower requirements."),
    ("OV-PMA-002", "Cyber Policy and Strategy Planner", "Oversee and Govern", "Develops and maintains cybersecurity plans, strategy, and policy to support organizational cyber activities."),
    ("OV-PMA-003", "Cyber Instructional Curriculum Developer", "Oversee and Govern", "Develops, plans, coordinates, and evaluates cybersecurity training/education courses and methods."),
    ("OV-PMA-004", "Cyber Instructor", "Oversee and Govern", "Develops and conducts training or education of personnel within cyber domain."),
    ("OV-PMA-005", "Information Systems Security Manager", "Oversee and Govern", "Responsible for the cybersecurity of a program, organization, system, or enclave."),
    ("OV-MGT-001", "Communications Security Manager", "Oversee and Govern", "Develops, plans, and manages COMSEC resources and requirements."),
    ("OV-MGT-002", "Cybersecurity Manager", "Oversee and Govern", "Manages and directs cybersecurity operations and personnel to protect IT infrastructure."),
    ("OV-EXL-001", "Executive Cyber Leadership", "Oversee and Govern", "Executes decision-making authorities and establishes vision and direction for the organization's cyber operations."),
    ("OV-TEA-001", "Program Manager", "Oversee and Govern", "Leads, coordinates, communicates, integrates, and ensures accountability for overall program for cybersecurity."),
    ("OV-TEA-002", "IT Project Manager", "Oversee and Govern", "Directly manages information technology projects to provide a unique service or product."),
    ("PR-CDA-001", "Cyber Defense Analyst", "Protect and Defend", "Uses data collected from a variety of cyber defense tools to analyze events within the environment for threats."),
    ("PR-CIR-001", "Cyber Defense Incident Responder", "Protect and Defend", "Investigates, analyzes, and responds to cyber incidents within the network or systems."),
    ("PR-INF-001", "Cyber Defense Infrastructure Support Specialist", "Protect and Defend", "Tests, implements, deploys, maintains, reviews, and administers infrastructure hardware and software for cybersecurity."),
    ("PR-VAM-001", "Vulnerability Assessment Analyst", "Protect and Defend", "Performs assessments of systems and networks and identifies where they deviate from acceptable configurations or policy."),
    ("AN-TGT-001", "Target Developer", "Analyze", "Performs target system analysis, builds and maintains electronic target folders, and provides target intelligence."),
    ("AN-TGT-002", "Target Network Analyst", "Analyze", "Conducts advanced analysis of collection and open-source data to ensure target continuity and profile targets."),
    ("AN-ASA-001", "All-Source Analyst", "Analyze", "Analyzes data from one or multiple sources to develop assessments that address cybersecurity threats and activities."),
    ("AN-ASA-002", "Mission Assessment Specialist", "Analyze", "Develops assessment plans and measures of performance/effectiveness for cyber operations."),
    ("AN-EXP-001", "Exploitation Analyst", "Analyze", "Collaborates to identify access and collection gaps that can be satisfied through cyber collection activities."),
    ("AN-LNG-001", "Multi-Disciplined Language Analyst", "Analyze", "Applies language, cultural knowledge, and technical expertise to process, analyze, and produce cyber intelligence."),
    ("CO-CLO-001", "All Source-Collection Manager", "Collect and Operate", "Identifies collection authorities and environment; evaluates and manages collection operations."),
    ("CO-CLO-002", "All Source-Collection Requirements Manager", "Collect and Operate", "Evaluates collection operations and develops strategies using available capabilities to improve collection."),
    ("CO-OPL-001", "Cyber Intel Planner", "Collect and Operate", "Develops detailed intelligence plans to satisfy cyber operations requirements."),
    ("CO-OPL-002", "Cyber Ops Planner", "Collect and Operate", "Develops detailed plans for conduct or support of cyber operations across the full spectrum of cyberspace operations."),
    ("CO-OPS-001", "Cyber Operator", "Collect and Operate", "Conducts collection, processing, and/or geolocation of systems to exploit, locate, and/or track targets of interest."),
    ("IN-FOR-001", "Cyber Crime Investigator", "Investigate", "Identifies, collects, examines, and preserves evidence using controlled and documented analytical and investigative techniques."),
    ("IN-FOR-002", "Digital Forensics Analyst", "Investigate", "Analyzes digital evidence and investigates computer security incidents to derive useful information for legal proceedings."),
]


def scrape_nist_nice(conn: sqlite3.Connection) -> int:
    conn.executemany(
        "INSERT OR REPLACE INTO nist_nice (id, name, category, description) VALUES (?, ?, ?, ?)",
        _ROLES,
    )
    conn.commit()
    log.info("Loaded %d NICE work roles", len(_ROLES))
    return len(_ROLES)
