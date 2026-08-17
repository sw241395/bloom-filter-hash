import hashlib
import itertools
import json
# import multiprocessing

from bloom_filter2 import BloomFilter
from pathlib import Path
from tqdm.auto import tqdm
from os import PathLike


def train_positions(
    charset: set[str],
    password_length: int,
    hash_alg: str = "sha256",
    output_path: str | PathLike[str] = "./pretrained_position_filters",
    bloom_filter_error_rate: float = 0.05,
    # n_jobs: int = 1,
):
    """
    Build a set of Bloom Filters to check for chars and positions in password hashes.

    Args:
        charset (set[str]):
            The characters that will be used to create
            the filters and to brute force

        password_length (int):
            The length of the passwords you want to generate using the provided chars

        hash_alg (str):
            The hashing algorithm used to create the filters
            Default is "sha256"

        output_path (str or PathLike[str]):
            The output dir where to store the pre-created
            bloom filters.
            Default is "./pretrained_filters"

        bloom_filter_error_rate (float):
            The error rate for the bloom filters.
            Must be between 0 and 1.
            Default is 0.01
    """
    # Sort the charset
    charset = sorted(list(charset))
    # Check hashing algorithm is valid
    if hash_alg not in hashlib.algorithms_available:
        raise ValueError(
            f'Hashing algorithm "{hash_alg}" not available, please choose one from `hashlib.algorithms_available`'
        )
    hash_alg = eval(f"hashlib.{hash_alg}")
    # Check the error rate is between 0-1
    if not 0 < bloom_filter_error_rate < 1:
        raise ValueError("`bloom_filter_error_rate` must be between 0 and 1")
    # # Check n_jobs
    # if n_jobs < 1:
    #     raise ValueError("`n_jobs` must be a positive integer")
    # elif n_jobs > len(charset):
    #     raise ValueError("`n_jobs` must not exceed the number of chars in the charset")

    # Build folder path
    p = Path(output_path) / hash_alg().name / str(password_length)
    p.mkdir(parents=True, exist_ok=True)
    for i in range(password_length):
        (p / str(i)).mkdir(parents=True, exist_ok=True)

    # Calculate how many elements each filter must contain
    max_elements_in_filter = len(charset) ** (password_length - 1)

    # Create metadata that will be used to recreate the filters when breaking
    filter_map = {char: i for i, char in enumerate(charset)}
    metadata = {
        "method": "position",
        "hash_alg": hash_alg().name,
        "password_length": password_length,
        "max_elements": max_elements_in_filter,
        "error_rate": bloom_filter_error_rate,
        "char_map": filter_map,
    }
    with open(p / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)

    # Create the bloom filters
    # E.G Structure:
    # {
    #   <password char index position>:{
    #     0:filter, ...
    #   },
    #   ...
    # }
    filters = dict()
    for i in range(password_length):
        filters[i] = dict()
        for char, file_name in filter_map.items():
            filters[i][char] = BloomFilter(
                max_elements=max_elements_in_filter,
                error_rate=bloom_filter_error_rate,
                filename=(str(p / str(i) / f"{file_name}.bin"), -1),  # Save as MMap
            )

    # Train filters
    for pwd in tqdm(
        itertools.product(charset, repeat=password_length),
        total=len(charset) ** password_length,
    ):
        hash = hash_alg("".join(pwd).encode()).hexdigest()
        for index, char in enumerate(pwd):
            filters[index][char].add(hash)
