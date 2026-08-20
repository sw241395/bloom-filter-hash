import pytest
import tempfile
from bloom_filter_hash import break_hash, get_charset, hashcat

PATHS = ["pretrained_filters", "pretrained_position_filters"]


class TestBreakHash:
    @pytest.mark.parametrize("path", PATHS)
    def test_break_hash(self, temp_dir, path):
        hash = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
        pwd = break_hash(hash, hash_alg="sha256", path_to_filters=f"{temp_dir}/{path}")
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
    @pytest.mark.parametrize("path", PATHS)
    def test_get_charset(self, temp_dir, path):
        hash = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
        charset = get_charset(
            hash, hash_alg="sha256", path_to_filters=f"{temp_dir}/{path}"
        )
        key = f"{temp_dir}/{path}/sha256/2"
        assert key in charset.keys()
        assert charset[key]["password_length"] == 2

        if path == "pretrained_filters":
            assert {"a", "b"}.issubset(charset[key]["charset_hit"])
        elif path == "pretrained_position_filters":
            assert {"a"}.issubset(charset[key]["charset_hit"][0])
            assert {"b"}.issubset(charset[key]["charset_hit"][1])
        else:
            raise ValueError(f'path "{path}" not valid')

    def test_get_charset_no_hits(self, temp_dir):
        hash = "Not a hash not a hash we have not trained on"
        charset = get_charset(hash, hash_alg="sha256", path_to_filters=temp_dir)
        for path in PATHS:
            key = f"{temp_dir}/{path}/sha256/2"
            assert key in charset.keys()
            assert charset[key]["password_length"] == 2
            assert charset[key]["charset_hit"] == set() or charset[key][
                "charset_hit"
            ] == {0: set(), 1: set()}

    def test_get_charset_no_md5_filters(self, temp_dir):
        hash = "Some md5 hash"
        charset = get_charset(hash, hash_alg="md5", path_to_filters=temp_dir)
        assert charset == dict()

    def test_get_charset_invalid_alg(self):
        with pytest.raises(ValueError):
            get_charset("test", hash_alg="Bad Hash Alg")

    def test_get_charset_no_filters(self):
        with pytest.raises(OSError):
            with tempfile.TemporaryDirectory() as tmpdirname:
                get_charset("test", hash_alg="sha256", path_to_filters=tmpdirname)


class TestHashCat:
    def test_hashcat(self, temp_dir):
        hash = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
        commands = hashcat(hash, hash_alg="sha256", path_to_filters=temp_dir)

        assert (
            f"hashcat -m 1400 -a 3 {hash} --custom-charset1 ba ?1?1" in commands
            or f"hashcat -m 1400 -a 3 {hash} --custom-charset1 ab ?1?1" in commands
        )
        assert (
            f"hashcat -m 1400 -a 3 {hash} --custom-charset1 a --custom-charset2 b ?1?2"
            in commands
            or f"hashcat -m 1400 -a 3 {hash} --custom-charset1 b --custom-charset2 a ?1?2"
            in commands
        )

    def test_hashcat_no_hits(self, temp_dir):
        hash = "Not a hash not a hash we have not trained on"
        commands = hashcat(hash, hash_alg="sha256", path_to_filters=temp_dir)
        assert commands == []

    def test_get_charset_no_md5_filters(self, temp_dir):
        hash = "Some md5 hash"
        commands = hashcat(hash, hash_alg="md5", path_to_filters=temp_dir)
        assert commands == []

    def test_hashcat_invalid_alg(self):
        with pytest.raises(ValueError):
            hashcat("test", hash_alg="Bad Hash Alg")

    def test_hashcat_no_filters(self):
        with pytest.raises(OSError):
            with tempfile.TemporaryDirectory() as tmpdirname:
                hashcat("test", hash_alg="sha256", path_to_filters=tmpdirname)
