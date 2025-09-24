"""
Fake KMS provider for the purpose of testing SDK.
"""


class FakeKMSProvider:
    """Test double that simulates KMS decrypt and validates encryption context."""

    def __init__(self, dek: bytes):
        self._dek = dek
