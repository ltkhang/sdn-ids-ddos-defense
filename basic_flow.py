import statistics as stat
from basic_packet_info import BasicPacketInfo

PACKET = 1


class BasicFlow:
    def __init__(self):
        self.fwd_pkt_stats = []
        self.bwd_pkt_stats = []
        self.forward = []
        self.backward = []
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.f_header_bytes = 0
        self.b_header_bytes = 0
        self.flag_counts = {}
        self.fPSH_cnt = 0
        self.bPSH_cnt = 0
        self.fURG_cnt = 0
        self.bURG_cnt = 0
        self.act_data_pkt_forward = 0
        self.min_seg_size_forward = 0
        self.init_win_bytes_forward = 0
        self.init_win_bytes_backward = 0
        self.src = ''
        self.dst = ''
        self.src_port = 0
        self.dst_port = 0
        self.protocol = 0
        self.flow_start_time = 0
        self.start_active_time = 0
        self.end_active_time = 0
        self.flow_id = ''
        self.flow_iat = []
        self.forward_iat = []
        self.backward_iat = []
        self.flow_length_stats = []
        self.flow_active = []
        self.flow_idle = []
        self.flow_last_seen = 0
        self.forward_last_seen = 0
        self.backward_last_seen = 0
        self.forward_len = 0
        self.backward_len = 0
        self.init_flags()

        self.sf_last_packet_ts = -1
        self.sf_count = 0
        self.sf_ac_helper = -1

    def basic_flow_1(self, basic_packet_info, src, dst, src_port, dst_port):
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.first_packet(basic_packet_info)

    def basic_flow_2(self, basic_packet_info):
        self.first_packet(basic_packet_info)

    def init_flags(self):
        self.flag_counts['FIN'] = 0
        self.flag_counts['SYN'] = 0
        self.flag_counts['RST'] = 0
        self.flag_counts['PSH'] = 0
        self.flag_counts['ACK'] = 0
        self.flag_counts['URG'] = 0
        self.flag_counts['CWR'] = 0
        self.flag_counts['ECE'] = 0

    def first_packet(self, basic_packet_info=BasicPacketInfo()):
        self.detect_update_sub_flows(basic_packet_info)
        self.check_flags(basic_packet_info)

        self.flow_start_time = basic_packet_info.timestamp
        self.flow_last_seen = basic_packet_info.timestamp
        self.start_active_time = basic_packet_info.timestamp
        self.end_active_time = basic_packet_info.timestamp
        self.flow_length_stats.append(basic_packet_info.payload_bytes)

        if self.src == '':
            self.src = basic_packet_info.src
            self.src_port = basic_packet_info.src_port

        if self.dst == '':
            self.dst = basic_packet_info.dst
            self.dst_port = basic_packet_info.dst_port

        self.protocol = basic_packet_info.protocol

        if self.src == basic_packet_info.src:
            self.min_seg_size_forward = basic_packet_info.header_bytes
            self.init_win_bytes_forward = basic_packet_info.tcp_window
            self.flow_length_stats.append(basic_packet_info.payload_bytes)
            self.fwd_pkt_stats.append(basic_packet_info.payload_bytes)
            self.f_header_bytes = basic_packet_info.header_bytes
            self.forward_last_seen = basic_packet_info.timestamp
            self.forward_bytes += basic_packet_info.payload_bytes
            # self.forward.append(PACKET)
            self.forward_len += 1
            if basic_packet_info.flagPSH:
                self.fPSH_cnt += 1
            if basic_packet_info.flagURG:
                self.fURG_cnt += 1
            self.flow_id = basic_packet_info.fwd_flow_id()
        else:
            self.init_win_bytes_backward = basic_packet_info.tcp_window
            self.flow_length_stats.append(basic_packet_info.payload_bytes)
            self.bwd_pkt_stats.append(basic_packet_info.payload_bytes)
            self.b_header_bytes = basic_packet_info.header_bytes
            self.backward_last_seen = basic_packet_info.timestamp
            self.backward_bytes += basic_packet_info.payload_bytes
            # self.backward.append(PACKET)
            self.backward_len += 1
            if basic_packet_info.flagPSH:
                self.bPSH_cnt += 1
            if basic_packet_info.flagURG:
                self.bURG_cnt += 1
            self.flow_id = basic_packet_info.bwd_flow_id()

    def add_packet(self, basic_packet_info=BasicPacketInfo()):
        self.detect_update_sub_flows(basic_packet_info)
        self.check_flags(basic_packet_info)

        self.flow_length_stats.append(basic_packet_info.payload_bytes)
        current_timestamp = basic_packet_info.timestamp
        if self.src == basic_packet_info.src:
            if basic_packet_info.payload_bytes >= 1:
                self.act_data_pkt_forward += 1
            self.fwd_pkt_stats.append(basic_packet_info.payload_bytes)
            self.f_header_bytes += basic_packet_info.header_bytes
            # self.forward.append(basic_packet_info)
            self.forward_len += 1
            self.forward_bytes += basic_packet_info.payload_bytes
            if self.forward_len > 1:
                self.forward_iat.append(current_timestamp - self.forward_last_seen)
            self.forward_last_seen = current_timestamp
            self.min_seg_size_forward = min(basic_packet_info.header_bytes, self.min_seg_size_forward)
        else:
            self.bwd_pkt_stats.append(basic_packet_info.payload_bytes)
            self.init_win_bytes_backward = basic_packet_info.tcp_window
            self.b_header_bytes += basic_packet_info.header_bytes
            # self.backward.append(basic_packet_info)
            self.backward_len += 1
            self.backward_bytes += basic_packet_info.payload_bytes
            if self.backward_len > 1:
                self.backward_iat.append(current_timestamp - self.backward_last_seen)
            self.backward_last_seen = current_timestamp
        self.flow_iat.append(current_timestamp - self.flow_last_seen)
        self.flow_last_seen = current_timestamp

    def detect_update_sub_flows(self, basic_packet_info=BasicPacketInfo()):
        if self.sf_last_packet_ts == -1:
            self.sf_last_packet_ts = basic_packet_info.timestamp
            self.sf_ac_helper = basic_packet_info.timestamp
        if (basic_packet_info.timestamp - self.sf_last_packet_ts / 1000) > 1.0:
            self.sf_count += 1
            self.update_active_idle_time(basic_packet_info.timestamp - self.sf_last_packet_ts, 5000)
            self.sf_ac_helper = basic_packet_info.timestamp
        self.sf_last_packet_ts = basic_packet_info.timestamp

    def update_active_idle_time(self, current_time, threshold):
        if current_time - self.end_active_time > threshold:
            if self.end_active_time - self.start_active_time > 0:
                self.flow_active.append(self.end_active_time - self.start_active_time)
            self.flow_idle.append(current_time - self.end_active_time)
            self.start_active_time = current_time
            self.end_active_time = current_time
        else:
            self.end_active_time = current_time

    def check_flags(self, basic_packet_info=BasicPacketInfo()):
        if basic_packet_info.flagFIN:
            self.flag_counts['FIN'] += 1
        if basic_packet_info.flagSYN:
            self.flag_counts['SYN'] += 1
        if basic_packet_info.flagRST:
            self.flag_counts['RST'] += 1
        if basic_packet_info.flagPSH:
            self.flag_counts['PSH'] += 1
        if basic_packet_info.flagACK:
            self.flag_counts['ACK'] += 1
        if basic_packet_info.flagURG:
            self.flag_counts['URG'] += 1
        if basic_packet_info.flagCWR:
            self.flag_counts['CWR'] += 1
        if basic_packet_info.flagECE:
            self.flag_counts['ECE'] += 1

    def packet_count(self):
        return self.forward_len + self.backward_len

    def get_fpkts_per_second(self):
        duration = self.flow_last_seen - self.flow_start_time
        if duration > 0:
            return self.forward_len / (duration / 1000)
        return 0

    def get_bpkts_per_second(self):
        duration = self.flow_last_seen - self.flow_start_time
        if duration > 0:
            return self.backward_len / (duration / 1000)
        return 0

    def get_down_up_ratio(self):
        if self.forward_len > 0:
            return self.backward_len / self.forward_len
        return 0

    def get_avg_packet_size(self):
        if self.packet_count() > 0:
            return sum(self.flow_length_stats) / self.packet_count()
        return 0

    def f_avg_segment_size(self):
        if self.forward_len > 0:
            return sum(self.fwd_pkt_stats) / self.forward_len
        return 0

    def b_avg_segment_size(self):
        if self.backward_len > 0:
            return sum(self.bwd_pkt_stats) / self.backward_len
        return 0

    def get_sflow_fbytes(self):
        if self.sf_count > 0:
            return self.forward_bytes / self.sf_count
        return 0

    def get_sflow_fpackets(self):
        if self.sf_count > 0:
            return self.forward_len / self.sf_count
        return 0

    def get_sflow_bbytes(self):
        if self.sf_count > 0:
            return self.backward_bytes / self.sf_count
        return 0

    def get_sflow_bpackets(self):
        if self.sf_count > 0:
            return self.backward_len / self.sf_count

    def get_flow_duration(self):
        return self.flow_last_seen - self.flow_start_time

    def dump_features(self):
        res = []
        flow_duration = self.get_flow_duration()
        # res.append(self.dst_port)
        res.append(self.protocol)
        res.append(flow_duration)
        res.append(len(self.fwd_pkt_stats))
        res.append(len(self.bwd_pkt_stats))
        res.append(sum(self.fwd_pkt_stats))
        res.append(sum(self.bwd_pkt_stats))
        if len(self.fwd_pkt_stats) > 1:
            res.append(max(self.fwd_pkt_stats))
            res.append(min(self.fwd_pkt_stats))
            res.append(stat.mean(self.fwd_pkt_stats))
            res.append(stat.stdev(self.fwd_pkt_stats))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
        if len(self.bwd_pkt_stats) > 1:
            res.append(max(self.bwd_pkt_stats))
            res.append(min(self.bwd_pkt_stats))
            res.append(stat.mean(self.bwd_pkt_stats))
            res.append(stat.stdev(self.bwd_pkt_stats))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
        if flow_duration > 0:
            res.append((self.forward_bytes + self.backward_bytes) / (flow_duration / 1000)) # second
            res.append(self.packet_count() / (flow_duration / 1000))
        else:
            res.append(0)
            res.append(0)
        if len(self.flow_iat) > 1:
            res.append(stat.mean(self.flow_iat))
            res.append(stat.stdev(self.flow_iat))
            res.append(max(self.flow_iat))
            res.append(min(self.flow_iat))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
        if self.forward_len > 2:
            res.append(sum(self.forward_iat))
            res.append(stat.mean(self.forward_iat))
            res.append(stat.stdev(self.forward_iat))
            res.append(max(self.forward_iat))
            res.append(min(self.forward_iat))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
        if self.backward_len > 2:
            res.append(sum(self.backward_iat))
            res.append(stat.mean(self.backward_iat))
            res.append(stat.stdev(self.backward_iat))
            res.append(max(self.backward_iat))
            res.append(min(self.backward_iat))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
        res.append(self.fPSH_cnt)
        res.append(self.f_header_bytes)
        res.append(self.b_header_bytes)
        res.append(self.get_fpkts_per_second())
        res.append(self.get_bpkts_per_second())
        if self.forward_len > 0 and self.backward_len > 0:
            res.append(min(self.flow_length_stats))
            res.append(max(self.flow_length_stats))
            res.append(stat.mean(self.flow_length_stats))
            res.append(stat.stdev(self.flow_length_stats))
            res.append(stat.variance(self.flow_length_stats))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
        res.append(self.flag_counts['FIN'])
        res.append(self.flag_counts['SYN'])
        res.append(self.flag_counts['RST'])
        res.append(self.flag_counts['PSH'])
        res.append(self.flag_counts['ACK'])
        res.append(self.flag_counts['URG'])
        res.append(self.flag_counts['ECE'])
        res.append(self.get_down_up_ratio())
        res.append(self.get_avg_packet_size())
        res.append(self.f_avg_segment_size())
        res.append(self.b_avg_segment_size())
        res.append(self.get_sflow_fpackets())
        res.append(self.get_sflow_fbytes())
        res.append(self.get_sflow_bpackets())
        res.append(self.get_sflow_bbytes())
        res.append(self.init_win_bytes_forward)
        res.append(self.init_win_bytes_backward)
        res.append(self.act_data_pkt_forward)
        res.append(self.min_seg_size_forward)
        if len(self.flow_active) > 1:
            res.append(stat.mean(self.flow_active))
            res.append(stat.stdev(self.flow_active))
            res.append(max(self.flow_active))
            res.append(min(self.flow_active))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)
        if len(self.flow_idle) > 1:
            res.append(stat.mean(self.flow_idle))
            res.append(stat.stdev(self.flow_idle))
            res.append(max(self.flow_idle))
            res.append(min(self.flow_idle))
        else:
            res.append(0)
            res.append(0)
            res.append(0)
            res.append(0)

        return res
