from .utils import normalize
import pickle
import numpy as np


class MLPredictor:
    def __init__(self, model_path):
        self.model = pickle.load(open(model_path, 'rb'))

    def predict(self, features):
        x = normalize(np.asarray(features))
        return self.model.predict(x)[0]
