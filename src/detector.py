"""
Security Log Analyzer
---------------------
Authentication detection engine.

Author: JK
Purpose: Cybersecurity / SOC learning project
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict

from .parser import SecurityEvent


@dataclass
class Detection:
    """Represents a security detection."""

    detection_name: str
    severity: str
    source_ip: str
    username: str
    attempt_count: int
    description: str
    mitre_technique: str


class AuthenticationDetector:
    """
    Detect suspicious authentication behavior.

    Current detections:

    - SSH Brute Force
    - Password Spraying
    """

    def __init__(
        self,
        threshold: int = 5,
        time_window_minutes: int = 5,
    ):
        """
        Initialize the detector.

        Args:
            threshold:
                Number of failed attempts required
                to trigger a detection.

            time_window_minutes:
                Time window used for correlation.
        """

        self.threshold = threshold
        self.time_window = timedelta(
            minutes=time_window_minutes
        )

    @staticmethod
    def parse_timestamp(timestamp: str) -> datetime:
        """
        Convert syslog timestamp into a datetime object.

        The year is not present in standard syslog timestamps,
        so the current year is used.
        """

        current_year = datetime.now().year

        return datetime.strptime(
            f"{current_year} {timestamp}",
            "%Y %b %d %H:%M:%S",
        )

    def detect_brute_force(
        self,
        events: list[SecurityEvent],
    ) -> list[Detection]:
        """
        Detect repeated authentication failures
        from the same IP within a defined time window.
        """

        failed_attempts = defaultdict(list)

        for event in events:

            if (
                event.event_type == "failed_login"
                and event.source_ip
            ):
                failed_attempts[
                    event.source_ip
                ].append(event)

        detections = []

        for source_ip, attempts in failed_attempts.items():

            attempts.sort(
                key=lambda event:
                self.parse_timestamp(event.timestamp)
            )

            for index in range(len(attempts)):

                window_start = self.parse_timestamp(
                    attempts[index].timestamp
                )

                window_events = []

                for event in attempts[index:]:

                    event_time = self.parse_timestamp(
                        event.timestamp
                    )

                    if (
                        event_time - window_start
                        <= self.time_window
                    ):
                        window_events.append(event)
                    else:
                        break

                if len(window_events) >= self.threshold:

                    usernames = sorted(
                        {
                            event.username
                            for event in window_events
                            if event.username
                        }
                    )

                    detections.append(
                        Detection(
                            detection_name="SSH Brute Force",
                            severity="HIGH",
                            source_ip=source_ip,
                            username=", ".join(usernames),
                            attempt_count=len(window_events),
                            description=(
                                f"{len(window_events)} failed "
                                f"authentication attempts detected "
                                f"from {source_ip} within "
                                f"{self.time_window.total_seconds() / 60:.0f} "
                                f"minutes."
                            ),
                            mitre_technique=(
                                "T1110 - Brute Force"
                            ),
                        )
                    )

                    # Only report one detection per IP
                    break

        return detections

    def detect_password_spraying(
        self,
        events: list[SecurityEvent],
    ) -> list[Detection]:
        """
        Detect potential password spraying.

        Password spraying attempts to authenticate against
        multiple accounts using repeated credentials.
        """

        failed_attempts = defaultdict(list)

        for event in events:

            if (
                event.event_type == "failed_login"
                and event.source_ip
            ):
                failed_attempts[
                    event.source_ip
                ].append(event)

        detections = []

        for source_ip, attempts in failed_attempts.items():

            usernames = {
                event.username
                for event in attempts
                if event.username
            }

            if len(usernames) >= 3:

                detections.append(
                    Detection(
                        detection_name="Password Spraying",
                        severity="HIGH",
                        source_ip=source_ip,
                        username=", ".join(
                            sorted(usernames)
                        ),
                        attempt_count=len(attempts),
                        description=(
                            f"Authentication failures were "
                            f"observed against {len(usernames)} "
                            f"different accounts from "
                            f"{source_ip}."
                        ),
                        mitre_technique=(
                            "T1110.003 - Password Spraying"
                        ),
                    )
                )

        return detections


def print_detections(
    detections: list[Detection],
) -> None:
    """Display detections in a SOC-style format."""

    print("\n" + "=" * 60)
    print("SECURITY DETECTIONS")
    print("=" * 60)

    if not detections:

        print("\nNo suspicious activity detected.")

        return

    print(
        f"\nDetections Found: {len(detections)}\n"
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
            f"    Description     : "
            f"{detection.description}"
        )

        print(
            f"    MITRE ATT&CK    : "
            f"{detection.mitre_technique}"
        )

        print("-" * 60)


if __name__ == "__main__":

    from .parser import AuthLogParser
    from .reporter import IncidentReporter

    parser = AuthLogParser()

    log_file = "sample_logs/auth.log"

    events = parser.parse_file(log_file)

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

    print_detections(detections)

    # Generate incident reports
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
            f"\n[+] Generated: {report_path}"
        )