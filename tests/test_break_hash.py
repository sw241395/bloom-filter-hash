import pytest
import tempfile
from bloom_filter_hash import break_hash


def test_break_hash(temp_dir):
    hash = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"

    pwd = break_hash(hash, hash_alg="sha256", path_to_filters=temp_dir)

    assert pwd == "ab"


def test_not_break_hash(temp_dir):
    hash = "Not a hash not a hash we have not trained on"

    pwd = break_hash(hash, hash_alg="sha256", path_to_filters=temp_dir)

    assert pwd is None


def test_no_filters():
    with pytest.raises(OSError):
        with tempfile.TemporaryDirectory() as tmpdirname:
            break_hash("test", hash_alg="sha256", path_to_filters=tmpdirname)
