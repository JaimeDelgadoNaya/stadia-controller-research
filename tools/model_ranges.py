"""Offline arithmetic model of build 169429 at 0x60801FE6. Not an exploit."""
MASK = 0xFFFFFFFF


def observed_range_check(lower, upper, start, size):
    if not lower <= start <= upper:
        return False
    end = (start + size - 1) & MASK
    return lower <= end <= upper


def nonwrapping_range_check(lower, upper, start, size):
    return size > 0 and lower <= start <= upper and size - 1 <= upper - start


if __name__ == "__main__":
    import json
    witness = (0x60000000, 0x60FFFFFF, 0x60000010, 0xFFFFFFF8)
    print(json.dumps({"range": [hex(v) for v in witness],
                      "observed_model_accepts": observed_range_check(*witness),
                      "nonwrapping_model_accepts": nonwrapping_range_check(*witness),
                      "status": "Arithmetic observation only. Reachable impact and authentication bypass are unproven."}, indent=2))
