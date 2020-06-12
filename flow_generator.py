from basic_flow import BasicFlow
from basic_packet_info import BasicPacketInfo


class FlowGenerator:
    def __init__(self, flow_timeout, flow_activity_timeout, on_flow_generated):
        self.flow_timeout = flow_timeout
        self.flow_activity_timeout = flow_activity_timeout
        self.current_flows = {}
        self.finished_flows = {}
        self.finished_flow_count = 0
        self.on_flow_generated = on_flow_generated

    def add_packet(self, basic_packet_info=BasicPacketInfo()):
        if basic_packet_info is None:
            return
        flow = BasicFlow()
        current_timestamp = basic_packet_info.timestamp
        flow_id = ''
        if (basic_packet_info.fwd_flow_id() in self.current_flows) or (basic_packet_info.bwd_flow_id() in self.current_flows):
            if basic_packet_info.fwd_flow_id() in self.current_flows:
                flow_id = basic_packet_info.fwd_flow_id()
            else:
                flow_id = basic_packet_info.bwd_flow_id()

            flow = self.current_flows[flow_id]

            if current_timestamp - flow.flow_start_time > self.flow_timeout:
                if flow.packet_count() > 1:
                    self.on_flow_generated(flow)
                    # self.finished_flows[self.get_flow_count()] = flow
                del self.current_flows[flow_id]
                self.current_flows[flow_id] = BasicFlow()
                self.current_flows[flow_id].basic_flow_1(basic_packet_info, flow.src, flow.dst, flow.src_port, flow.dst_port)
            else:
                if basic_packet_info.flagFIN:
                    flow.add_packet(basic_packet_info)
                    self.on_flow_generated(flow)
                    # self.finished_flows[self.get_flow_count()] = flow
                    del self.current_flows[flow_id]
                else:
                    flow.update_active_idle_time(current_timestamp, self.flow_activity_timeout)
                    flow.add_packet(basic_packet_info)
                    self.current_flows[id] = flow
                    del flow
        else:
            flow = BasicFlow()
            flow.basic_flow_2(basic_packet_info)
            self.current_flows[basic_packet_info.fwd_flow_id()] = flow

    def get_flow_count(self):
        self.finished_flow_count += 1
        return self.finished_flow_count
