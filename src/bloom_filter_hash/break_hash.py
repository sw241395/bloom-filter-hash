import glob
import itertools
import json
import math
import hashlib

from os import PathLike
from bloom_filter2 import BloomFilter
from pathlib import Path, PurePath
from tqdm.auto import tqdm


HASHCAT_HASH_TYPES = {
    # 'blake2b':600,
    # 'blake2s':31000,
    "md5": 0,
    # 'md5-sha1':4400,
    "ripemd160": 6000,
    "sha1": 100,
    "sha224": 1300,
    "sha256": 1400,
    "sha384": 10800,
    "sha3_224": 17300,
    "sha3_256": 17400,
    "sha3_384": 17500,
    "sha3_512": 17600,
    "sha512": 1700,
    # 'sha512_224':,
    # 'sha512_256':,
    # 'shake_128':,
    # 'shake_256':,
    # 'sm3:':25000,
}
# The commented out methods either could not be an associated hash or did not work


def break_hash(
    hash: str,
    hash_alg: str,
    path_to_filters: str | PathLike[str] = "./pretrained_filters",
    verbose: bool = True,
):
    """
    Using a set of pre-created bloom filters, try to
    reduce the work needed to brute force a hash.

    Args:
        hash (str):
            The hash you want to break
        hash_alg (str):
            The hashing algorithm used to create the hash
        path_to_filters (str or PathLike[str], Optional):
            The file path to the pre-created filters.
            It will also recursively search for "metadata.json"
            Default is "./pretrained_filters"
        verbose (bool):
            Print out progress bars and progress updates.
            Default is True

    Returns:
        str or None
            The plain text password from the hash
    """
    # Checks
    if hash_alg not in hashlib.algorithms_available:
        raise ValueError(
            f'Hashing algorithm "{hash_alg}" not available, please choose one from `hashlib.algorithms_available`'
        )
    hash_alg = eval(f"hashlib.{hash_alg}")

    # Find all pretrained filters
    pretrained_filter_metadata_paths = list(
        glob.iglob(str(Path(path_to_filters) / "**/metadata.json"), recursive=True)
    )
    if len(pretrained_filter_metadata_paths) == 0:
        raise OSError(f"No `metadata.json` files can be found in {path_to_filters}")

    # Loop through pretrained filters
    for pretrained_filter_metadata in pretrained_filter_metadata_paths:
        # Open metadata
        with open(pretrained_filter_metadata) as json_file:
            metadata = json.load(json_file)
        # Skip filters that have been trained on other hashing algorithms
        if metadata["hash_alg"] != hash_alg().name:
            continue

        if metadata.get("method") == "position":
            # Rebuild filters
            filters = dict()
            for i in range(metadata["password_length"]):
                filters[i] = dict()
                for char, file_name in metadata["char_map"].items():
                    filters[i][char] = BloomFilter(
                        max_elements=metadata["max_elements"],
                        error_rate=metadata["error_rate"],
                        filename=(
                            str(
                                PurePath(pretrained_filter_metadata).parent
                                / str(i)
                                / f"{file_name}.bin"
                            ),
                            -1,
                        ),  # Use MMap
                    )
            if verbose:
                print(
                    f"Running hash through filters for passwords of length {metadata['password_length']} over the charset: \n {list(metadata['char_map'].keys())}"
                )

            # See what chars are potentially present in the password
            hit_charset = {i: set() for i in filters.keys()}
            for index, filter_dict in filters.items():
                for char, f in filter_dict.items():
                    if hash in f:
                        hit_charset[index].add(char)
            if verbose:
                print(f"Hit bloom filter hits charset: {hit_charset}")

            iterator = itertools.product(*(hit_charset[i] for i in hit_charset))
            total = math.prod([len(v) for v in hit_charset.values()])

        else:
            # Rebuild filters
            filters = {
                char: BloomFilter(
                    max_elements=metadata["max_elements"],
                    error_rate=metadata["error_rate"],
                    filename=(
                        str(PurePath(pretrained_filter_metadata).parent / file),
                        -1,
                    ),  # Use MMap
                )
                for char, file in metadata["filter_map"].items()
            }

            if verbose:
                print(
                    f"Running hash through filters for passwords of length {metadata['password_length']} over the charset: \n {list(filters.keys())}"
                )

            # See what chars are potentially present in the password
            hit_charset = set(k for k, v in filters.items() if hash in v)
            if verbose:
                print(f"Hit bloom filter hits charset: {hit_charset}")
            iterator = itertools.product(
                hit_charset, repeat=metadata["password_length"]
            )
            total = len(hit_charset) ** metadata["password_length"]

        for pwd in tqdm(
            iterator,
            total=total,
            disable=not verbose,
        ):
            if hash_alg("".join(pwd).encode()).hexdigest() == hash:
                if verbose:
                    print(f"Password Found: {''.join(pwd)}")
                return "".join(pwd)


# TODO: update to use positional filters
def get_charset(
    hash: str,
    hash_alg: str,
    path_to_filters: str | PathLike[str] = "./pretrained_filters",
):
    """
    Using a set of pre-created bloom filters, try to
    return the charset the hash hits on.

    Args:
        hash (str):
            The hash you want to break
        hash_alg (str):
            The hashing algorithm used to create the hash
        path_to_filters (str or PathLike[str], Optional):
            The file path to the pre-created filters.
            It will also recursively search for "metadata.json"
            Default is "./pretrained_filters"

    Returns:
        dict
            charset for each password length the hash hit on (dict)
    """
    # Checks
    if hash_alg not in hashlib.algorithms_available:
        raise ValueError(
            f'Hashing algorithm "{hash_alg}" not available, please choose one from `hashlib.algorithms_available`'
        )
    hash_alg = eval(f"hashlib.{hash_alg}")

    # Find all pretrained filters
    pretrained_filter_metadata_paths = list(
        glob.iglob(str(Path(path_to_filters) / "**/metadata.json"), recursive=True)
    )
    if len(pretrained_filter_metadata_paths) == 0:
        raise OSError(f"No `metadata.json` files can be found in {path_to_filters}")

    # Loop through pretrained filters
    charset = dict()
    for pretrained_filter_metadata in pretrained_filter_metadata_paths:
        # Open metadata
        with open(pretrained_filter_metadata) as json_file:
            metadata = json.load(json_file)
        # Skip filters that have been trained on other hashing algorithms
        if metadata["hash_alg"] != hash_alg().name:
            continue

        # Rebuild filters
        filters = {
            char: BloomFilter(
                max_elements=metadata["max_elements"],
                error_rate=metadata["error_rate"],
                filename=(
                    str(PurePath(pretrained_filter_metadata).parent / file),
                    -1,
                ),  # use MMAP
            )
            for char, file in metadata["filter_map"].items()
        }

        charset[str(PurePath(pretrained_filter_metadata).parent)] = {
            "password_length": metadata["password_length"],
            "charset_hit": set(k for k, v in filters.items() if hash in v),
        }
    return charset


# TODO: update to use positional filters
def hashcat(
    hash: str,
    hash_alg: str,
    path_to_filters: str | PathLike[str] = "./pretrained_filters",
    verbose: bool = True,
):
    """
    Using a set of pre-created bloom filters, create a
    HashCat command using a custom charset to utilize
    the performance of HashCat.

    Args:
        hash (str):
            The hash you want to break
        hash_alg (str):
            The hashing algorithm used to create the hash
        path_to_filters (str or PathLike[str], Optional):
            The file path to the pre-created filters.
            It will also recursively search for "metadata.json"
            Default is "./pretrained_filters"
        verbose (bool):
            Print out commands.
            Default is True

    Returns:
        list[str]
            HashCat command to break hash
    """
    if hash_alg not in HASHCAT_HASH_TYPES.keys():
        raise ValueError("This method is not supported in HashCat")

    charset = get_charset(hash=hash, hash_alg=hash_alg, path_to_filters=path_to_filters)
    commands = []
    for v in charset.values():
        if len(v["charset_hit"]) == 0:
            continue
        command = f"hashcat -m {HASHCAT_HASH_TYPES[hash_alg]} -a 3 {hash} --custom-charset1 {''.join(v['charset_hit'])} {'?1' * v['password_length']}"
        if verbose:
            print(command)
        commands.append(command)
    return commands
