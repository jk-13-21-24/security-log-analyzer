"""
Security Log Analyzer
---------------------
Main application entry point.

Author: JK
Purpose: Cybersecurity / SOC learning project
"""

from .parser import AuthLogParser
from .detector import AuthenticationDetector
from .reporter import IncidentReporter
from .json_reporter import JSONReporter


def main():
    """Run the security log analysis pipeline."""

    print("=" * 60)
    print("SECURITY LOG ANALYZER")
    print("=" * 60)

    # --------------------------------------------------
    # Step 1: Parse authentication logs
    # --------------------------------------------------

    parser = AuthLogParser()

    log_file = "sample_logs/auth.log"

    events = parser.parse_file(log_file)

    print(f"\nEvents Parsed: {len(events)}")

    # --------------------------------------------------
    # Step 2: Run detections
    # --------------------------------------------------

    detector = AuthenticationDetector(
        threshold=5,
        time_window_minutes=5,
    )

    detections = []

    detections.extend(
        detector.detect_brute_force(events)
    )

    detections.extend(
        detector.detect_password_spraying(events)
    )

    # --------------------------------------------------
    # Step 3: Display detections
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("SECURITY DETECTIONS")
    print("=" * 60)

    if not detections:

        print("\nNo suspicious activity detected.")

    else:

        print(
            f"\nDetections Found: "
            f"{len(detections)}\n"
        )

        for index, detection in enumerate(
            detections,
            start=1,
        ):

            print(
                f"[{index}] 🚨 "
                f"{detection.detection_name}"
            )

            print(
                f"    Severity        : "
                f"{detection.severity}"
            )

            print(
                f"    Source IP       : "
                f"{detection.source_ip}"
            )

            print(
                f"    Username(s)     : "
                f"{detection.username}"
            )

            print(
                f"    Failed Attempts : "
                f"{detection.attempt_count}"
            )

            print(
                f"    MITRE ATT&CK    : "
                f"{detection.mitre_technique}"
            )

            print("-" * 60)

    # --------------------------------------------------
    # Step 4: Generate incident reports
    # --------------------------------------------------

    reporter = IncidentReporter()

    print("\n" + "=" * 60)
    print("INCIDENT REPORTS")
    print("=" * 60)

    for index, detection in enumerate(
        detections,
        start=1,
    ):

        incident_id = (
            reporter.generate_incident_id(index)
        )

        report = reporter.generate_report(
            detection,
            incident_id,
        )

        report_path = reporter.save_report(
            report,
            incident_id,
        )

        print(
            f"\n[+] Generated: "
            f"{report_path}"
        )
    
    # Step 5: Export detections as JSON
    # --------------------------------------------------

    json_reporter = JSONReporter()

    json_path = json_reporter.export(
        detections,
    )

    print(
        f"\n[+] JSON Export: "
        f"{json_path}"
    )



if __name__ == "__main__":
    main()