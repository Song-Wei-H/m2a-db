from model_samples import make_model_dataset
from worker.model_readiness import check_model_readiness


def test_model_readiness_rejects_small_dataset():
    result = check_model_readiness(make_model_dataset(100))

    assert result.ready is False
    assert any("dataset_size below 500" in reason for reason in result.reasons)


def test_model_readiness_accepts_balanced_complete_dataset():
    result = check_model_readiness(make_model_dataset(520))

    assert result.ready is True
    assert result.report["dataset_size"] == 520
