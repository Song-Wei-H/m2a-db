from model_samples import make_model_dataset
from worker.gbm_trainer import GBMTrainer
from worker.model_evaluator import evaluate_model
from worker.model_report import build_model_report


def test_model_evaluator_outputs_metrics_and_feature_importance():
    dataset = make_model_dataset(520)
    training_result = GBMTrainer(random_state=2).train(dataset)

    evaluation = evaluate_model(training_result.model, dataset[:100])

    assert 0 <= evaluation["accuracy"] <= 1
    assert 0 <= evaluation["precision"] <= 1
    assert 0 <= evaluation["recall"] <= 1
    assert 0 <= evaluation["f1"] <= 1
    assert "confusion_matrix" in evaluation
    assert evaluation["feature_importance"]


def test_model_report_summarizes_training_run():
    dataset = make_model_dataset(520)
    training_result = GBMTrainer(random_state=3).train(dataset)
    evaluation = evaluate_model(training_result.model, dataset[:100])

    report = build_model_report(
        dataset=dataset,
        train_size=364,
        validation_size=78,
        test_size=78,
        evaluation_result=evaluation,
        model_metadata={"model_version": "gbm-test", "training_time": "2026-06-25T00:00:00Z"},
    )

    assert report["dataset_size"] == 520
    assert report["train_test_split"]["train"] == 364
    assert report["model_version"] == "gbm-test"
    assert "accuracy" in report["evaluation_metrics"]
