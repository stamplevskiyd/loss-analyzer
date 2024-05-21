from enum import StrEnum


class PacketType(StrEnum):
    """Types of packets based on received/sent origin"""

    sent = "sent"
    received = "received"


class StringAlgorithmType(StrEnum):
    """Supported types of functions-preprocessor for group file create"""

    standard = "standard"
    tokenized = "tokenized"
    combined = "combined"
