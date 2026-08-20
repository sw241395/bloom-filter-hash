import os
import json
import pytest
import tempfile
import itertools
import hashlib
from bloom_filter_hash import train_positions
from bloom_filter2 import BloomFilter
import string


@pytest.mark.parametrize("hash_alg", ["sha256", "md5"])
@pytest.mark.parametrize("jobs", [1, 2])
def test_train(hash_alg, jobs):
    test_charset = sorted(
        list(set(string.ascii_letters + string.punctuation + "0123456789"))
    )

    with tempfile.TemporaryDirectory() as tmpdirname:
        # Create a small set of filters on only 2 chars
        train_positions(
            charset=test_charset,
            password_length=2,
            hash_alg=hash_alg,
            output_path=tmpdirname,
            n_jobs=jobs,
        )

        # Assert metadata was created
        metadata_json_filepath = f"{tmpdirname}/{hash_alg}/2/metadata.json"
        assert os.path.exists(metadata_json_filepath)
        with open(metadata_json_filepath, "r") as f:
            metadata = json.load(f)
            assert metadata == {
                "method": "position",
                "hash_alg": hash_alg,
                "password_length": 2,
                "max_elements": 94,
                "error_rate": 0.05,
                "char_map": {char: i for i, char in enumerate(test_charset)},
            }

        # Assert filters have been created
        for i in range(2):
            for j in range(len(test_charset)):
                assert os.path.exists(f"{tmpdirname}/{hash_alg}/2/{i}/{j}.bin")

        # Assert filters contain correct values
        for chars in itertools.product(test_charset, repeat=2):
            h = hashlib.new(hash_alg)
            h.update("".join(chars).encode())
            hash = h.hexdigest()

            for i, char in enumerate(chars):
                filter = BloomFilter(
                    max_elements=metadata["max_elements"],
                    error_rate=metadata["error_rate"],
                    filename=(
                        f"{tmpdirname}/{hash_alg}/2/{i}/{metadata['char_map'][char]}.bin",
                        -1,
                    ),
                )
                assert hash in filter


def test_train_positions_bad_hash_alg(temp_dir):
    with pytest.raises(ValueError):
        train_positions(
            charset=set(range(10)),
            password_length=3,
            hash_alg="Not a hashing algorithm",
            output_path=temp_dir,
        )


def test_train_positions_bad_error_rate(temp_dir):
    with pytest.raises(ValueError):
        train_positions(
            charset=set(range(10)),
            password_length=3,
            output_path=temp_dir,
            bloom_filter_error_rate=2,
        )


# def test_train_positions_negative_n_jobs(temp_dir):
#     with pytest.raises(ValueError):
#         train_positions(
#             charset=set(range(10)),
#             password_length=3,
#             output_path=temp_dir,
#             n_jobs=-1,
#         )
