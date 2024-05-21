# File with sent packets
from custom_types import StringAlgorithmType

sent_file: str = "sent.pcap"

# File with received packets
received_file: str = "received.pcap"

# folder where to save packet groups for sent packets
sent_groups_folder: str = "sent_groups"

# folder where to save packet groups for received packets
received_groups_folder: str = "received_groups"

# Multiprocessing settings
use_multiprocessing: bool = True
proc_count = 6

# Mode: standard or tokenized
string_algorithm: StringAlgorithmType = StringAlgorithmType.combined
