import pytest

from worker.model_dataset_loader import (
    load_test_dataset,
    load_training_dataset,
    load_validation_dataset,
    split_dataset,
)


class FakeRepository:
    def __init__(self, rows):
        self.rows = rows

    async def load_dataset(self):
        return list(self.rows)


def make_rows(count=100):
    return [{"id": index, "round_value": index % 2} for index in range(count)]


def test_split_dataset_is_deterministic_and_sized():
    split_a = split_dataset(make_rows(100), seed=7)
    split_b = split_dataset(make_rows(100), seed=7)

    assert len(split_a.train) == 70
    assert len(split_a.validation) == 15
    assert len(split_a.test) == 15
    assert split_a.train == split_b.train


@pytest.mark.asyncio
async def test_dataset_loader_reads_from_repository_only():
    repo = FakeRepository(make_rows(20))

    assert len(await load_training_dataset(repo)) == 20
    assert len(await load_validation_dataset(repo)) == 3
    assert len(await load_test_dataset(repo)) == 3
