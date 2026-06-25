import pytest

from model_samples import make_model_dataset
from worker.gbm_predictor import GBMPredictor
from worker.gbm_trainer import GBMTrainer, build_binary_label_vector, build_numeric_feature_matrix


def test_feature_matrix_and_binary_label_vector():
    dataset = make_model_dataset(10)

    matrix = build_numeric_feature_matrix(dataset)
    labels = build_binary_label_vector(dataset)

    assert len(matrix) == 10
    assert len(matrix[0]) == 15
    assert labels == [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]


def test_gbm_trainer_trains_and_predicts_offline():
    dataset = make_model_dataset(520)

    result = GBMTrainer(random_state=1).train(dataset)
    predictions = GBMPredictor(result.model).predict(dataset[:5])
    probabilities = GBMPredictor(result.model).predict_probability(dataset[:5])

    assert result.training_samples == 520
    assert result.metadata["algorithm"] == "GradientBoostingClassifier"
    assert len(predictions) == 5
    assert len(probabilities) == 5


def test_gbm_trainer_enforces_readiness_gate():
    with pytest.raises(ValueError, match="Dataset not ready"):
        GBMTrainer().train(make_model_dataset(100))
