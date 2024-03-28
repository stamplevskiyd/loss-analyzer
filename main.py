from scapy.all import rdpcap
from scapy.plist import PacketList
from hash import transport_hash

filename: str = "200722_tcp_anon.pcapng"
# filename = "200722_win_scale_examples_anon.pcapng"

packets: PacketList = rdpcap(filename)

for packet in packets:
    print(transport_hash(packet))