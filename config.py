# File with sent packets
from custom_types import StringAlgorithmType

SENT_FILE: str = "sent.pcap"

# File with received packets
RECEIVED_FILE: str = "received.pcap"

# folder where to save packet groups for sent packets
SENT_GROUPS_SOLDER: str = "sent_groups"

# folder where to save packet groups for received packets
RECEIVED_GROUPS_SOLDER: str = "received_groups"

# Multiprocessing settings
USE_MULTIPROCESSING: bool = False
PROC_COUNT = 6

# Mode: standard or tokenized
STRING_ALGORITHM: StringAlgorithmType = StringAlgorithmType.tokenized
