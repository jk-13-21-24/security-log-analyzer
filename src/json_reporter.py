import json
from dataclasses import asdict
from pathlib import Path

from .detector import Detection


class JSONReporter:
    """Export security detections as structured JSON."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, detections: list[Detection], filename: str = "detections.json") -> Path:
        """Export detections to a JSON file."""
        output_path = self.output_dir / filename

        data = {
            "tool": "Security Log Analyzer",
            "detection_count": len(detections),
            "detections": [asdict(detection) for detection in detections],
        }

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        return output_path