import hashlib
import itertools
import json

from bloom_filter2 import BloomFilter
from pathlib import Path
from tqdm.auto import tqdm
from os import PathLike


def train(
    charset: set[str],
    password_length: int,
    hash_alg: str = "sha256",
    output_path: str | PathLike[str] = "./pretrained_filters",
    bloom_filter_error_rate: float = 0.05,
):
    """
    Build a set of Bloom Filters to check for password hashes.

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

    # Build folder path
    p = Path(output_path) / hash_alg().name / str(password_length)
    p.mkdir(parents=True, exist_ok=True)

    # Calculate how many elements each filter must contain
    max_elements_in_filter = (len(charset) ** password_length) - (
        (len(charset) - 1) ** password_length
    )

    # Create metadata that will be used to recreate the filters when breaking
    # Also create the bloom filters
    filter_map = dict()
    filters = dict()
    for i, char in enumerate(charset):
        filter_map[char] = f"{i}.bin"
        filters[char] = BloomFilter(
            max_elements=max_elements_in_filter,
            error_rate=bloom_filter_error_rate,
            filename=(str(p / f"{i}.bin"), -1),  # Save as MMap
        )

    metadata = {
        "hash_alg": hash_alg().name,
        "password_length": password_length,
        "max_elements": max_elements_in_filter,
        "error_rate": bloom_filter_error_rate,
        "filter_map": filter_map,
    }
    with open(p / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)

    # Train filters
    for pwd in tqdm(
        itertools.product(charset, repeat=password_length),
        total=len(charset) ** password_length,
    ):
        hash = hash_alg("".join(pwd).encode()).hexdigest()
        for char in set(pwd):
            filters[char].add(hash)
