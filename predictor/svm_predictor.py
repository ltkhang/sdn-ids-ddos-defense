from .utils import normalize
import pickle
import numpy as np


class SVMPredictor:
    def __init__(self, model_path):
        self.model = pickle.load(open(model_path, 'rb'))

    def predict(self, data):
        flow_id, features = data
        x = normalize(np.asarray(features))
        return flow_id, self.model.predict(x)[0]
