"""Bounded owner-device HID input observation; no output/feature operations.

Optional live dependency: hidapi==0.14.0.post4. Paths and serials are never
included in the artifact. This observes Windows HID input, not USB packets.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import time


def summarize(reports):
    counts = Counter(bytes(r) for r in reports)
    return {
        "report_count": sum(counts.values()),
        "distinct_reports": [{"hex": r.hex(), "count": n}
                             for r, n in sorted(counts.items())],
        "all_match_id3_length11": bool(counts) and all(
            len(r) == 11 and r[0] == 3 for r in counts),
    }


def capture(seconds=10):
    if not 0 < seconds <= 30:
        raise ValueError("Capture duration must be >0 and <=30 seconds")
    import hid
    candidates = [d for d in hid.enumerate(0x18D1, 0x9400)
                  if d.get("usage_page") == 1 and d.get("usage") == 5]
    if len(candidates) != 1:
        raise ValueError("Exactly one Stadia gamepad collection required")
    reports = []
    device = hid.device()
    started = datetime.now(timezone.utc).isoformat()
    try:
        device.open_path(candidates[0]["path"])
        begin = time.monotonic()
        end = begin + seconds
        while time.monotonic() < end:
            report = device.read(64, max(1, min(100, int((end-time.monotonic())*1000))))
            if report:
                reports.append(bytes(report))
        elapsed = time.monotonic() - begin
    finally:
        device.close()
    return {"phase": 79, "captured_at_utc": started,
            "method": "Windows HID input reads via hidapi 0.14.0.post4",
            "vid": "18d1", "pid": "9400", "usage_page": 1, "usage": 5,
            "requested_seconds": seconds, "elapsed_seconds": round(elapsed, 3),
            **summarize(reports),
            "limits": {"USB_packet_capture": False,
                       "output_or_feature_reports_sent": False,
                       "button_actions_requested_or_labeled": False,
                       "vendor_bulk_endpoints_observed": False,
                       "workqueue_or_callback_link_demonstrated": False}}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--seconds", type=float, default=10)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    result = capture(args.seconds)
    args.out.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
