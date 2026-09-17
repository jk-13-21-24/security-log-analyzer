"""
Tests for the Security Log Analyzer detection engine.

Author: JK
"""

from src.detector import AuthenticationDetector
from src.parser import AuthLogParser


def load_test_events():
    """Load the project's sample authentication logs."""

    parser = AuthLogParser()

    return parser.parse_file(
        "sample_logs/auth.log"
    )


def test_brute_force_detection():
    """Verify SSH brute-force detection."""

    events = load_test_events()

    detector = AuthenticationDetector(
        threshold=5,
        time_window_minutes=5,
    )

    detections = detector.detect_brute_force(
        events
    )

    assert len(detections) == 1

    detection = detections[0]

    assert detection.detection_name == "SSH Brute Force"
    assert detection.severity == "HIGH"
    assert detection.source_ip == "192.168.1.50"
    assert detection.attempt_count == 6
    assert detection.mitre_technique == (
        "T1110 - Brute Force"
    )


def test_password_spraying_detection():
    """Verify password-spraying detection."""

    events = load_test_events()

    detector = AuthenticationDetector()

    detections = detector.detect_password_spraying(
        events
    )

    assert len(detections) == 1

    detection = detections[0]

    assert detection.detection_name == (
        "Password Spraying"
    )

    assert detection.severity == "HIGH"

    assert detection.source_ip == (
        "172.16.50.10"
    )

    assert detection.attempt_count == 4

    assert detection.mitre_technique == (
        "T1110.003 - Password Spraying"
    )


def test_brute_force_threshold():
    """Verify that the detection threshold works."""

    events = load_test_events()

    detector = AuthenticationDetector(
        threshold=10,
        time_window_minutes=5,
    )

    detections = detector.detect_brute_force(
        events
    )

    assert len(detections) == 0


def test_password_spraying_requires_multiple_users():
    """
    Verify that a single targeted account doesn't
    trigger the password-spraying detection.
    """

    parser = AuthLogParser()

    events = [
        parser.parse_line(
            "Sep 18 01:00:00 server01 "
            "sshd[1000]: Failed password for admin "
            "from 192.168.100.10 port 40000 ssh2"
        ),
        parser.parse_line(
            "Sep 18 01:00:05 server01 "
            "sshd[1001]: Failed password for admin "
            "from 192.168.100.10 port 40001 ssh2"
        ),
        parser.parse_line(
            "Sep 18 01:00:10 server01 "
            "sshd[1002]: Failed password for admin "
            "from 192.168.100.10 port 40002 ssh2"
        ),
    ]

    events = [
        event
        for event in events
        if event is not None
    ]

    detector = AuthenticationDetector()

    detections = detector.detect_password_spraying(
        events
    )

    assert len(detections) == 0