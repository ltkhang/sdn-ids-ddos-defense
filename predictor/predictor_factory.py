from .svm_predictor import SVMPredictor
from .dnn_predictor import DNNPredictor

SVM_NAME = 'svm'
DNN_NAME = 'dnn'


class PredictorFactory:
    def __init__(self, predictor_name, predictor_model_path):
        self.name = predictor_name
        self.path = predictor_model_path

    def get(self):
        if self.name == DNN_NAME:
            return DNNPredictor(self.path)
        else:
            return SVMPredictor(self.path)


