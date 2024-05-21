import os.path
import random

from scapy.all import rdpcap, wrpcap
from scapy.compat import raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

sent_packet_count = 10000
loss_range = 0.4

sent_packets = rdpcap("200722_tcp_anon.pcapng")

sent_filename = "sent.pcap"
received_filename = "received.pcap"


def random_mac():
    return ":".join(["{:02x}".format(random.randint(0, 255)) for _ in range(6)])


def random_ip():
    return ".".join([str(random.randint(0, 255)) for _ in range(4)])


def random_port():
    return random.randint(1, 65535)


def generate_random_packet():
    ether = Ether(src=random_mac(), dst=random_mac())
    ip = IP(src=random_ip(), dst=random_ip())
    if random.choice([True, False]):
        tcp = TCP(sport=random_port(), dport=random_port())
        packet = ether / ip / tcp
    else:
        udp = UDP(sport=random_port(), dport=random_port())
        packet = ether / ip / udp

    packet = packet / Raw(
        load="".join([chr(random.randint(0, 255)) for _ in range(1000)])
    )

    return packet


received_packets_count = 0

if os.path.exists(sent_filename):
    os.remove(sent_filename)

if os.path.exists(received_filename):
    os.remove(received_filename)

sent_packets = set()
received_packets = set()

sent_cnt = 0
received_cnt = 0

for _ in range(sent_packet_count):
    random_packet = generate_random_packet()
    if raw(random_packet) not in sent_packets:
        sent_packets.add(raw(random_packet))
        wrpcap(filename=sent_filename, pkt=random_packet, append=True)
        sent_cnt += 1

        if random.random() > loss_range:
            wrpcap(filename=received_filename, pkt=random_packet, append=True)
            received_cnt += 1

print(f"Wrote to sent {sent_cnt} packets")
print(f"Wrote to received {received_cnt} packets")
