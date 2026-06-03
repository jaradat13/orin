"""
orin.analysis – Threat Detection & Reporting Layer
===================================================
Consumes the raw telemetry stored in the Orin SQLite vault and produces
structured security findings, drift reports, and human-readable output.

Modules
-------
engine    – Core rules-based analysis cycle that emits ``security_events``.
diff      – Cross-file snapshot comparator (supports both SQLite and signed
            JSON export inputs).
reporter  – Markdown and HTML report compilers for audit briefings.
timeline  – Point-in-time delta calculator between two snapshot IDs.
"""
