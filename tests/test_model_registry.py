import shutil
from pathlib import Path

from model_samples import make_model_dataset
from worker.gbm_predictor import GBMPredictor
from worker.gbm_trainer import GBMTrainer
from worker.model_evaluator import evaluate_model
from worker.model_registry import LocalModelRegistry


def test_local_model_registry_saves_loads_model_and_metadata():
    root = Path("tests/.tmp_model_registry")
    shutil.rmtree(root, ignore_errors=True)
    try:
        dataset = make_model_dataset(520)
        training_result = GBMTrainer(random_state=4).train(dataset)
        evaluation = evaluate_model(training_result.model, dataset[:100])
        registry = LocalModelRegistry(root)

        registered = registry.save_model(
            training_result.model,
            model_version="gbm-v1",
            dataset_size=training_result.training_samples,
            evaluation_result=evaluation,
        )
        loaded_model = registry.load_model("gbm-v1")
        metadata = registry.load_metadata("gbm-v1")

        assert registered.model_path.exists()
        assert registered.metadata_path.exists()
        assert metadata["model_version"] == "gbm-v1"
        assert metadata["training_samples"] == 520
        assert GBMPredictor(loaded_model).predict(dataset[:1]) in ([0], [1])
    finally:
        shutil.rmtree(root, ignore_errors=True)
