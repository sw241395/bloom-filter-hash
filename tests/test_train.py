import os
import json
import pytest
import tempfile
import itertools
import hashlib
from bloom_filter_hash import train
from bloom_filter2 import BloomFilter
import string


@pytest.mark.parametrize("hash_alg", ["sha256", "md5"])
def test_train(hash_alg):
    test_charset = set(string.ascii_letters + "0123456789")

    with tempfile.TemporaryDirectory() as tmpdirname:
        # Create a small set of filters on only 2 chars
        train(
            charset=test_charset,
            password_length=2,
            hash_alg=hash_alg,
            output_path=tmpdirname,
        )

        # Assert metadata was created
        metadata_json_filepath = f"{tmpdirname}/{hash_alg}/2/metadata.json"
        assert os.path.exists(metadata_json_filepath)
        with open(metadata_json_filepath, "r") as f:
            metadata = json.load(f)
            assert metadata == {
                "hash_alg": hash_alg,
                "password_length": 2,
                "max_elements": 1953,
                "error_rate": 0.1,
            }

        # Assert filters have been created
        for i in test_charset:
            assert os.path.exists(f"{tmpdirname}/{hash_alg}/2/{i}.bin")

        # Assert filters contain correct values
        for chars in itertools.product(test_charset, repeat=2):
            h = hashlib.new(hash_alg)
            h.update("".join(chars).encode())
            hash = h.hexdigest()

            for char in set(chars):
                filter = BloomFilter(
                    max_elements=1953,
                    error_rate=0.1,
                    filename=f"{tmpdirname}/{hash_alg}/2/{char}.bin",
                )
                assert hash in filter


def test_train_bad_hash_alg(temp_dir):
    with pytest.raises(ValueError):
        train(
            charset=set(range(10)),
            password_length=3,
            hash_alg="Not a hashing algorithm",
            output_path=temp_dir,
        )


def test_train_bad_error_rate(temp_dir):
    with pytest.raises(ValueError):
        train(
            charset=set(range(10)),
            password_length=3,
            output_path=temp_dir,
            bloom_filter_error_rate=2,
        )
