import threading
from queue import Queue
from flow_generator import FlowGenerator
from basic_packet_info import BasicPacketInfo
from scapy.layers.inet import IP, TCP, UDP


class PacketController(threading.Thread):
    def __init__(self):
        super().__init__()
        self.flow_generator = None
        self.queue = Queue()
        self.is_running = False

    def add_flow_generator(self, flow_generator):
        self.flow_generator = flow_generator

    def run(self):
        print('start packet controller')
        self.is_running = True
        while self.is_running:
            if not self.queue.empty():
                pkt = self.queue.get()
                basic_packet_info = BasicPacketInfo()
                basic_packet_info.timestamp = pkt.time * 1000  # milis
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    proto = pkt[IP].proto
                    basic_packet_info.src = src
                    basic_packet_info.dst = dst
                    basic_packet_info.protocol = proto
                    if TCP in pkt:
                        basic_packet_info.tcp_window = pkt[TCP].window
                        basic_packet_info.src_port = pkt[TCP].sport
                        basic_packet_info.dst_port = pkt[TCP].dport
                        basic_packet_info.protocol = 6  # for sure, dont need this
                        basic_packet_info.set_flag(pkt[TCP].flags)
                        basic_packet_info.payload_bytes = len(pkt[TCP].payload)
                        basic_packet_info.header_bytes = len(pkt[TCP]) - len(pkt[TCP].payload)
                    if UDP in pkt:
                        basic_packet_info.protocol = 17  # for sure, dont need ths
                        basic_packet_info.src_port = pkt[UDP].sport
                        basic_packet_info.dst_port = pkt[UDP].dport
                        basic_packet_info.payload_bytes = len(pkt[UDP].payload)
                        basic_packet_info.header_bytes = len(pkt[UDP]) - len(pkt[UDP].payload)
                self.flow_generator.add_packet(basic_packet_info)
                del basic_packet_info

    def put(self, packet):
        self.queue.put(packet)

    def stop(self):
        self.is_running = False
