"""Decode a normal-mode Stadia USB report offline; never accesses hardware.

Names identify HID usages, not unverified physical button labels. The contract
comes from evidence/stadia-hid-report-contract.json (report 3, 80 payload bits).
"""
import argparse
import json

BUTTON_USAGES = (18, 17, 20, 19, 13, 12, 11, 15, 14, 8, 7, 5, 4, 2, 1)
CONSUMER_USAGES = (233, 234, 205)


def decode_report(report):
    if len(report) != 11 or report[0] != 3:
        raise ValueError("Expected exactly 11 USB bytes including report ID 3")
    hat = report[1] & 15
    buttons = int.from_bytes(report[2:4], "little")
    axes = dict(zip(("x", "y", "z", "rz"), report[4:8]))
    return {
        "report_id": 3,
        "hat_raw": hat,
        "hat": hat if hat <= 7 else None,
        "pressed_button_usages": [u for bit, u in enumerate(BUTTON_USAGES)
                                  if buttons & (1 << bit)],
        "axes_raw": axes,
        "axes_outside_descriptor_range": [k for k, v in axes.items() if v == 0],
        "simulation_controls_raw": {"0xc5": report[8], "0xc4": report[9]},
        "pressed_consumer_usages": [u for bit, u in enumerate(CONSUMER_USAGES)
                                    if report[10] & (1 << bit)],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_hex", help="11 bytes, including the report ID")
    args = parser.parse_args()
    try:
        result = decode_report(bytes.fromhex(args.report_hex))
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
