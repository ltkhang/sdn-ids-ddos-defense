import threading
from queue import Queue


class MachineLearningController(threading.Thread):
    def __init__(self):
        super().__init__()
        self.queue = Queue()
        self.is_running = False
        self.predictor = None
        self.on_notify = None

    def add_predictor(self, predictor):
        self.predictor = predictor

    def add_on_notify(self, on_notify):
        self.on_notify = on_notify

    def run(self):
        print('start machine learning controller')
        self.is_running = True
        while self.is_running:
            if not self.queue.empty():
                flow_id, features = self.queue.get()
                res = self.predictor.predict(features)
                if res == 1:
                    f = flow_id.split('-')
                    if len(f) == 5:
                        self.on_notify(f[0] + '-' + f[1])
                print(flow_id, res)

    def put(self, flow):
        self.queue.put(flow)

    def stop(self):
        self.is_running = False
