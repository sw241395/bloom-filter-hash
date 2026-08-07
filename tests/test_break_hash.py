import pytest
import tempfile
from bloom_filter_hash import break_hash, get_charset


class TestBreakHash:
    def test_break_hash(self, temp_dir):
        hash = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
        pwd = break_hash(hash, hash_alg="sha256", path_to_filters=temp_dir)
        assert pwd == "ab"

    def test_not_break_hash(self, temp_dir):
        hash = "Not a hash not a hash we have not trained on"
        pwd = break_hash(hash, hash_alg="sha256", path_to_filters=temp_dir)
        assert pwd is None

    def test_break_hash_finding_no_md5_filters(self, temp_dir):
        hash = "Some md5 hash"
        pwd = break_hash(hash, hash_alg="md5", path_to_filters=temp_dir)
        assert pwd is None

    def test_break_hash_invalid_alg(self):
        with pytest.raises(ValueError):
            break_hash("test", hash_alg="Bad Hash Alg")

    def test_break_hash_no_filters(self):
        with pytest.raises(OSError):
            with tempfile.TemporaryDirectory() as tmpdirname:
                break_hash("test", hash_alg="sha256", path_to_filters=tmpdirname)


class TestGetCharSet:
    def test_get_charset(self, temp_dir):
        hash = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
        charset = get_charset(hash, hash_alg="sha256", path_to_filters=temp_dir)
        key = temp_dir + "/sha256/2"
        assert key in charset.keys()
        assert charset[key]["password_length"] == 2
        assert {"a", "b"}.issubset(charset[key]["charset_hit"])

    def test_get_charset_no_hits(self, temp_dir):
        hash = "Not a hash not a hash we have not trained on"
        charset = get_charset(hash, hash_alg="sha256", path_to_filters=temp_dir)
        key = temp_dir + "/sha256/2"
        assert key in charset.keys()
        assert charset[key]["password_length"] == 2
        assert charset[key]["charset_hit"] == set()

    def test_get_charset_no_md5_filters(self, temp_dir):
        hash = "Some md5 hash"
        charset = get_charset(hash, hash_alg="md5", path_to_filters=temp_dir)
        assert charset == dict()

    def test_get_charset_invalid_alg(self):
        with pytest.raises(ValueError):
            get_charset("test", hash_alg="Bad Hash Alg")

    def test_get_charset_filters(self):
        with pytest.raises(OSError):
            with tempfile.TemporaryDirectory() as tmpdirname:
                get_charset("test", hash_alg="sha256", path_to_filters=tmpdirname)
