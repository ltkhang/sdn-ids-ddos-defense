from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from basic_packet_info import BasicPacketInfo
from basic_flow import BasicFlow
from flow_generator import FlowGenerator
from packet_controller import PacketController
from ml_controller import MachineLearningController
from notify_controller import NotifyController
from predictor.predictor_factory import PredictorFactory
import signal
import sys


pkt_controller = PacketController()
ml_controller = MachineLearningController()
notify_controller = NotifyController()


def on_flow_generated(flow=BasicFlow()):
    ml_controller.put((flow.flow_id, flow.dump_features()))
    del [flow]


def on_notify(msg):
    notify_controller.send(msg)


def on_pkt(pkt):
    global pkt_controller
    pkt_controller.put(pkt)
    del pkt


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print(sys.argv[0], '<network interface> <unixsocket_path> <model_name> <model_path>')
        exit(0)
    inet = sys.argv[1]
    unixsock_path = sys.argv[2]
    model_name = sys.argv[3]
    model_path = sys.argv[4]

    pkt_controller.add_flow_generator(FlowGenerator(120 * 1000, 5 * 1000, on_flow_generated))
    predictor_factory = PredictorFactory(model_name, model_path)
    ml_controller.add_predictor(predictor_factory.get())
    ml_controller.add_on_notify(on_notify)
    res = notify_controller.init_socket(unixsock_path)
    if not res:
        print('Unix socket server not found', unixsock_path)
        exit(-1)
    pkt_controller.start()
    ml_controller.start()
    time.sleep(1)
    sniff(iface=inet, prn=on_pkt)
    pkt_controller.join()
    ml_controller.join()
