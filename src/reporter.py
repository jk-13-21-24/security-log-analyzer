"""
Security Log Analyzer
---------------------
Incident report generator.

Author: JK
Purpose: Cybersecurity / SOC learning project
"""

from datetime import datetime
from pathlib import Path

from .detector import Detection


class IncidentReporter:
    """Generate SOC-style incident reports."""

    def __init__(self, output_directory: str = "reports"):
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    @staticmethod
    def generate_incident_id(index: int) -> str:
        """Generate a simple incident identifier."""

        date_part = datetime.now().strftime("%Y%m%d")

        return f"INC-{date_part}-{index:03d}"

    def generate_report(
        self,
        detection: Detection,
        incident_id: str,
    ) -> str:
        """Generate Markdown incident report."""

        report_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        report = f"""# Incident Report — {incident_id}

## Incident Summary

| Field | Value |
|---|---|
| Incident ID | {incident_id} |
| Detection | {detection.detection_name} |
| Severity | {detection.severity} |
| Source IP | `{detection.source_ip}` |
| Target Account(s) | {detection.username} |
| Failed Attempts | {detection.attempt_count} |
| MITRE ATT&CK | {detection.mitre_technique} |
| Report Generated | {report_time} |

---

## Description

{detection.description}

---

## Detection

The authentication log analyzer identified activity
matching the detection rule:

**{detection.detection_name}**

The activity originated from:

`{detection.source_ip}`

---

## MITRE ATT&CK Mapping

**{detection.mitre_technique}**

This detection is mapped to the MITRE ATT&CK
credential-access technique associated with the
observed authentication behavior.

---

## Recommended Investigation

1. Identify the source host associated with the IP address.
2. Review authentication events from the source.
3. Determine whether any authentication attempts succeeded.
4. Review activity involving the targeted account(s).
5. Check for additional suspicious network connections.
6. Review endpoint telemetry for related activity.
7. Determine whether credentials may have been exposed.
8. Preserve relevant logs and evidence.

---

## Analyst Notes

> This report is generated from simulated security
> telemetry for cybersecurity education and testing.

---

## Status

**Open — Requires Investigation**

"""

        return report

    def save_report(
        self,
        report: str,
        incident_id: str,
    ) -> Path:
        """Save incident report to disk."""

        filename = (
            self.output_directory
            / f"{incident_id}.md"
        )

        filename.write_text(
            report,
            encoding="utf-8",
        )

        return filename