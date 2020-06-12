class BasicPacketInfo:
    def __init__(self):
        self.src = ""
        self.dst = ""
        self.src_port = 0
        self.dst_port = 0
        self.protocol = 0
        self.timestamp = 0.0
        self.payload_bytes = 0
        self.flow_id = ""
        self.flagFIN = False
        self.flagPSH = False
        self.flagURG = False
        self.flagECE = False
        self.flagSYN = False
        self.flagACK = False
        self.flagCWR = False
        self.flagRST = False
        self.tcp_window = 0
        self.header_bytes = 0
        self.payload_packet = 0

    def set_flag(self, F):
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80
        self.flagFIN = not not(F & FIN)
        self.flagSYN = not not(F & SYN)
        self.flagRST = not not(F & RST)
        self.flagPSH = not not(F & PSH)
        self.flagACK = not not(F & ACK)
        self.flagURG = not not(F & URG)
        self.flagECE = not not(F & ECE)
        self.flagCWR = not not(F & CWR)

    def fwd_flow_id(self):
        return self.src + '-' + self.dst + '-' + str(self.src_port) + '-' + str(self.dst_port) + '-' + \
               str(self.protocol)

    def bwd_flow_id(self):
        return self.dst + '-' + self.src + '-' + str(self.dst_port) + '-' + str(self.src_port) + '-' + \
               str(self.protocol)

    def __str__(self):
        print('Timestamp', self.timestamp)
        print('IP Src', self.src, self.src_port)
        print('IP Dst', self.dst, self.dst_port)
        print('Protocol', self.protocol)
        print('Payload bytes', self.payload_bytes)
        print('TCP Window', self.tcp_window)
        print('Header bytes', self.header_bytes)
        print('flagFIN', self.flagFIN)
        print('flagSYN', self.flagSYN)
        print('flagRST', self.flagRST)
        print('flagPSH', self.flagPSH)
        print('flagACK', self.flagACK)
        print('flagURG', self.flagURG)
        print('flagECE', self.flagECE)
        print('flagCWR', self.flagCWR)
        return ''