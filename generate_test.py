import random

from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

sent_packet_count = 10000
loss_range = 0.6

sent_packets = rdpcap("200722_tcp_anon.pcapng")

sent_filename = "sent.pcap"
received_filename = "received.pcap"


def random_mac():
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])


def random_ip():
    return '.'.join([str(random.randint(0, 255)) for _ in range(4)])


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

    packet = packet / Raw(load=''.join([chr(random.randint(0, 255)) for _ in range(random.randint(10, 100))]))

    return packet

received_packets_count = 0

for _ in range(sent_packet_count):
    random_packet = generate_random_packet()
    wrpcap(filename=sent_filename, pkt=random_packet, append=True)
    if random.random() > loss_range:
        wrpcap(filename=received_filename, pkt=random_packet, append=True)
        received_packets_count += 1

print(f"Wrote to sent {sent_packet_count} packets")
print(f"Wrote to received {received_packets_count} packets")