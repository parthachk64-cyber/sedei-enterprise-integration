from __future__ import annotations

import pytest

from sedei.config import DATA_DIR
from sedei.datagen import write_dataset
from sedei.system import SimClock, build_system

ORDER = {"sku": "SKU-1001", "quantity": 2}


@pytest.fixture
def clock():
    return SimClock()


@pytest.fixture
def sys_(clock):
    s = build_system(":memory:", clock, deterministic_ids=True)
    yield s
    s.store.close()


@pytest.fixture
def token(sys_, clock):
    return lambda tenant="tenant-a", subject="svc-07", **kw: sys_.issuer.issue(tenant, subject, clock(), **kw)


def order(tenant="tenant-a", **kw):
    return {"tenant": tenant, **ORDER, **kw}


@pytest.fixture(scope="session")
def small_data(tmp_path_factory):
    d = tmp_path_factory.mktemp("small")
    write_dataset(d, seed=7, scale=0.25)
    return d


@pytest.fixture(scope="session")
def shipped_data():
    return DATA_DIR


@pytest.fixture(scope="session")
def trained_model(tmp_path_factory, shipped_data):
    from sedei.experiment import train_model
    runs = tmp_path_factory.mktemp("runs")
    return runs, train_model(shipped_data, runs)
