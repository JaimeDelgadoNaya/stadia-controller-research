import unittest

from tools import audit_app_message_role as audit


class MessageRoleTests(unittest.TestCase):
    def test_exact_semantic_anchors(self):
        audit.validate_semantics(dict(audit.ANCHORS))

    def test_incomplete_old_entry_is_rejected(self):
        decoded = dict(audit.ANCHORS)
        del decoded[0x60058B64]
        with self.assertRaises(ValueError):
            audit.validate_semantics(decoded)

    def test_length_guard_mutation_is_rejected(self):
        decoded = dict(audit.ANCHORS)
        decoded[0x60058AA8] = ("cmp", "r1, #2")
        with self.assertRaises(ValueError):
            audit.validate_semantics(decoded)

    def test_unsigned_or_wrong_sample_is_rejected(self):
        with self.assertRaises(ValueError):
            audit.inspect(b"not firmware")
        with self.assertRaises(ValueError):
            audit.inspect(bytes(audit.IMAGE_SIZE))


if __name__ == "__main__":
    unittest.main()
