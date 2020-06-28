from .utils import normalize
import numpy as np


class DNNPredictor:
    def __init__(self, model_path):
        model_json, model_weight = model_path.split(',')
        print(model_json, model_weight)
        self.model = None

    def predict(self, features):
        return 0
