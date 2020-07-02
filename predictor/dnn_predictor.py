from .utils import normalize
import numpy as np
from keras.models import model_from_json
import tensorflow as tf

class DNNPredictor:
    def __init__(self, model_path):
        model_json, model_weight = model_path.split(',')
        print(model_json, model_weight)
        with open(model_json, 'r') as json_file:
            json_savedModel = json_file.read()
        self.model = model_from_json(json_savedModel)
        self.model.load_weights(model_weight)
        self.graph = tf.get_default_graph()

    def predict(self, features):
        x = normalize(np.asarray([features]))
        with self.graph.as_default():
            res = np.argmax(self.model.predict(x), axis=1)[0]
        return res

