import threading
from queue import Queue


class MachineLearningController(threading.Thread):
    def __init__(self):
        super().__init__()
        self.queue = Queue()
        self.is_running = False
        self.predictor = None

    def add_predictor(self, predictor):
        self.predictor = predictor

    def run(self):
        print('start machine learning controller')
        self.is_running = True
        while self.is_running:
            if not self.queue.empty():
                flow_id, features = self.queue.get()
                res = self.predictor.predict((flow_id, features))
                print(flow_id, res)

    def put(self, flow):
        print('put')
        self.queue.put(flow)

    def stop(self):
        self.is_running = False
