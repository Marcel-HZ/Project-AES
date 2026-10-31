"""Shared context dataclass."""
from dataclasses import dataclass, field


@dataclass
class Context:
    plaintext: str
    key_bytes: bytes
    plaintext_bytes: bytes = b""
    padded: bytes = b""
    padding_len: int = 0
    blocks: list = field(default_factory=list)
    round_keys: list = field(default_factory=list)
    key_expansion_trace: dict = field(default_factory=dict)
    ciphertext: bytes = b""
    encrypt_trace: dict = field(default_factory=dict)
    round_snapshots: list = field(default_factory=list)
    decrypted_padded: bytes = b""
    decrypted: bytes = b""
    decrypt_trace: dict = field(default_factory=dict)
    modes: dict = field(default_factory=dict)
    tamper: dict = field(default_factory=dict)
    samples: dict = field(default_factory=dict)
    steps_done: list = field(default_factory=list)

    def reset_derived(self):
        self.plaintext_bytes = b""
        self.padded = b""
        self.padding_len = 0
        self.blocks = []
        self.round_keys = []
        self.key_expansion_trace = {}
        self.ciphertext = b""
        self.encrypt_trace = {}
        self.round_snapshots = []
        self.decrypted_padded = b""
        self.decrypted = b""
        self.decrypt_trace = {}
        self.modes = {}
        self.tamper = {}
        self.samples = {}
        self.steps_done = []
