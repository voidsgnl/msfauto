import unittest

from msfauto.execution import (
    MAX_ADAPTER_OUTPUT_BYTES,
    AdapterOutputError,
    sanitize_adapter_output,
)


class AdapterOutputTests(unittest.TestCase):
    def test_redacts_common_secret_formats(self) -> None:
        output = sanitize_adapter_output(
            '{"password": "secret value", "api_token": "token-value"} '
            "Authorization: Bearer bearer-value"
        )
        for secret in ("secret value", "token-value", "bearer-value"):
            self.assertNotIn(secret, output)
        self.assertIn("[REDACTED]", output)

    def test_rejects_output_over_limit(self) -> None:
        with self.assertRaises(AdapterOutputError):
            sanitize_adapter_output("x" * (MAX_ADAPTER_OUTPUT_BYTES + 1))

    def test_rejects_non_text_output(self) -> None:
        with self.assertRaises(AdapterOutputError):
            sanitize_adapter_output(b"not text")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
