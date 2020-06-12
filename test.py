from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from basic_packet_info import BasicPacketInfo
from basic_flow import BasicFlow
from flow_generator import FlowGenerator
from packet_controller import PacketController
from ml_controller import MachineLearningController
from predictor.svm_predictor import SVMPredictor

import signal
import sys


controller = PacketController()
ml_controller = MachineLearningController()
ml_controller.add_predictor(SVMPredictor('./model/svm_model.pkl'))


def on_flow_generated(flow=BasicFlow()):
    # print(flow.flow_id)
    ml_controller.put((flow.flow_id, flow.dump_features()))
    del [flow]


def pkt_cb(pkt):
    global controller
    basic_packet_info = BasicPacketInfo()
    basic_packet_info.timestamp = pkt.time * 1000 # milis
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
        # print(basic_packet_info)
        del pkt
        controller.put(basic_packet_info)


def pkt_cb_2(pkt):
    global controller
    controller.put(pkt)
    del pkt


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(sys.argv[0], '<network interface>')
        exit(0)
    inet = sys.argv[1]
    controller.add_flow_generator(FlowGenerator(120 * 1000, 5 * 1000, on_flow_generated))
    controller.start()
    ml_controller.start()
    time.sleep(1)
    sniff(iface=inet, prn=pkt_cb_2)
    controller.join()
    ml_controller.join()
