import socket
import os


class NotifyController:
    def __init__(self):
        self.client = None

    def init_socket(self, unixsock_path):
        if os.path.exists(unixsock_path):
            self.client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.client.connect(unixsock_path)
            return True
        else:
            return False

    def send(self, msg):
        self.client.send(msg.encode('utf-8'))