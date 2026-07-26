import glob
import itertools
import json
import hashlib

from bloom_filter2 import BloomFilter
from pathlib import Path, PurePath
from tqdm.auto import tqdm


def break_hash(
    hash: str,
    hash_alg: str,
    path_to_filters: Path = Path("./pretrained_filters"),
    verbose: bool = True,
):
    # Checks
    if hash_alg not in hashlib.algorithms_available:
        raise ValueError(
            f'Hashing algorithm "{hash_alg}" not available, please choose one from `hashlib.algorithms_available`'
        )
    hash_alg = eval(f"hashlib.{hash_alg}")

    # Find all pretrained filters
    for pretrained_filter_metadata in glob.iglob(
        path_to_filters + "/**/metadata.json", recursive=True
    ):
        # Open metadata
        with open(pretrained_filter_metadata) as json_file:
            metadata = json.load(json_file)
        # Skip filters that have been trained on other hashing algorithms
        if metadata["hash_alg"] != hash_alg().name:
            continue

        # Rebuild filters
        filters = {
            Path(f).stem: BloomFilter(
                max_elements=metadata["max_elements"],
                error_rate=metadata["error_rate"],
                filename=f,
            )
            for f in glob.glob(
                str(PurePath(pretrained_filter_metadata).parent / "*.bin")
            )
        }

        if verbose:
            print(
                f"Running hash through filters for passwords of length {metadata['password_length']} over the charset: \n {list(filters.keys())}"
            )

        # See what chars are potentially present in the password
        hit_charset = set(k for k, v in filters.items() if hash in v)
        if verbose:
            print(f"Hit bloom filter hits charset: {hit_charset}")

        for pwd in tqdm(
            itertools.product(hit_charset, repeat=metadata["password_length"]),
            total=len(hit_charset) ** metadata["password_length"],
            disable=not verbose,
        ):
            if hash_alg("".join(pwd).encode()).hexdigest() == hash:
                if verbose:
                    print(f"Password Found: {''.join(pwd)}")
                return "".join(pwd)
