"""
Security Log Analyzer
---------------------
Authentication log parser for Linux SSH logs.

Author: JK
Purpose: Cybersecurity / SOC learning project
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class SecurityEvent:
    """Represents a normalized security event."""

    timestamp: str
    hostname: str
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    raw_log: str = ""


class AuthLogParser:
    """Parser for Linux SSH authentication logs."""

    FAILED_LOGIN = re.compile(
        r"Failed password for (?:invalid user )?"
        r"(?P<username>\S+) "
        r"from (?P<ip>\S+) "
        r"port (?P<port>\d+)"
    )

    SUCCESSFUL_LOGIN = re.compile(
        r"Accepted password for "
        r"(?P<username>\S+) "
        r"from (?P<ip>\S+) "
        r"port (?P<port>\d+)"
    )

    INVALID_USER = re.compile(
        r"Invalid user (?P<username>\S+) "
        r"from (?P<ip>\S+) "
        r"port (?P<port>\d+)"
    )

    LOG_PATTERN = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
        r"(?P<hostname>\S+) "
        r"(?P<message>.*)$"
    )

    def parse_line(self, line: str) -> Optional[SecurityEvent]:
        """
        Parse one authentication log line.

        Returns:
            SecurityEvent if the line contains a recognized event.
            None otherwise.
        """

        line = line.strip()

        if not line:
            return None

        log_match = self.LOG_PATTERN.match(line)

        if not log_match:
            return None

        timestamp = log_match.group("timestamp")
        hostname = log_match.group("hostname")
        message = log_match.group("message")

        # Failed authentication
        match = self.FAILED_LOGIN.search(message)

        if match:
            return SecurityEvent(
                timestamp=timestamp,
                hostname=hostname,
                event_type="failed_login",
                username=match.group("username"),
                source_ip=match.group("ip"),
                source_port=int(match.group("port")),
                raw_log=line,
            )

        # Successful authentication
        match = self.SUCCESSFUL_LOGIN.search(message)

        if match:
            return SecurityEvent(
                timestamp=timestamp,
                hostname=hostname,
                event_type="successful_login",
                username=match.group("username"),
                source_ip=match.group("ip"),
                source_port=int(match.group("port")),
                raw_log=line,
            )

        # Invalid username
        match = self.INVALID_USER.search(message)

        if match:
            return SecurityEvent(
                timestamp=timestamp,
                hostname=hostname,
                event_type="invalid_user",
                username=match.group("username"),
                source_ip=match.group("ip"),
                source_port=int(match.group("port")),
                raw_log=line,
            )

        return None

    def parse_file(self, filepath: str) -> list[SecurityEvent]:
        """
        Parse an authentication log file.

        Args:
            filepath: Path to authentication log.

        Returns:
            List of normalized security events.
        """

        events = []

        with open(filepath, "r", encoding="utf-8") as log_file:
            for line in log_file:
                event = self.parse_line(line)

                if event:
                    events.append(event)

        return events


def print_events(events: list[SecurityEvent]) -> None:
    """Print parsed events in a readable format."""

    print("\n" + "=" * 60)
    print("SECURITY LOG ANALYZER")
    print("=" * 60)

    print(f"\nEvents Parsed: {len(events)}\n")

    for index, event in enumerate(events, start=1):
        print(f"[{index}] {event.event_type.upper()}")

        print(f"    Timestamp : {event.timestamp}")
        print(f"    Host      : {event.hostname}")
        print(f"    Username  : {event.username}")
        print(f"    Source IP : {event.source_ip}")
        print(f"    Port      : {event.source_port}")

        print("-" * 60)


if __name__ == "__main__":
    parser = AuthLogParser()

    log_file = "sample_logs/auth.log"

    events = parser.parse_file(log_file)

    print_events(events)