from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from basic_packet_info import BasicPacketInfo
from basic_flow import BasicFlow
from flow_generator import FlowGenerator
from packet_controller import PacketController
from ml_controller import MachineLearningController
from notify_controller import NotifyController
from predictor.svm_predictor import SVMPredictor
import signal
import sys


pkt_controller = PacketController()
ml_controller = MachineLearningController()
notify_controller = NotifyController()


def on_flow_generated(flow=BasicFlow()):
    # print(flow.flow_id)
    ml_controller.put((flow.flow_id, flow.dump_features()))
    del [flow]


def on_notify(msg):
    notify_controller.send(msg)


def on_pkt(pkt):
    global pkt_controller
    pkt_controller.put(pkt)
    del pkt


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(sys.argv[0], '<network interface>')
        exit(0)
    inet = sys.argv[1]
    pkt_controller.add_flow_generator(FlowGenerator(120 * 1000, 5 * 1000, on_flow_generated))
    ml_controller.add_predictor(SVMPredictor('./model/svm_model.pkl'))
    ml_controller.add_on_notify(on_notify)
    res = notify_controller.init_socket('/tmp/ids-ddos')
    if not res:
        print('Unix socket server not found', '/tmp/ids-ddos')
        exit(-1)
    pkt_controller.start()
    ml_controller.start()
    time.sleep(1)
    sniff(iface=inet, prn=on_pkt)
    pkt_controller.join()
    ml_controller.join()
