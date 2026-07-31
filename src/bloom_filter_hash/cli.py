import argparse
from pathlib import Path
from .train import train
from .break_hash import break_hash


def train_command(args):
    train(
        charset=set(list(args.charset)),
        password_length=args.pwdlen,
        hash_alg=args.hash_alg,
        output_path=args.output,
        bloom_filter_error_rate=args.error_rate,
    )


def break_hash_command(args):
    password = break_hash(
        hash=args.hash,
        hash_alg=args.hash_alg,
        path_to_filters=args.filters_path,
        verbose=args.verbose,
    )
    print("-" * 50)
    if password:
        print("Password Found: ", password)
    else:
        print("Password not found")


def main():
    parser = argparse.ArgumentParser(
        description="Train or break hashes using Bloom filters"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # Create the parser for training filters
    train_parser = subparsers.add_parser("train", help="Train a set of bloom filters")
    train_parser.add_argument(
        "charset",
        type=str,
        help="All chars to use when creating the bloom filters",
    )
    train_parser.add_argument(
        "pwdlen",
        type=int,
        help="Length of the password you want to train",
    )
    train_parser.add_argument(
        "--hash-alg",
        "-ha",  # -h is reserved for help
        type=str,
        default="sha256",
        help='Hashing algorithm (Default is "sha256")',
    )
    train_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("./pretrained_filters"),
        help='Output dir to put the bloom filters (Default is "./pretrained_filters")',
    )
    train_parser.add_argument(
        "--error-rate",
        "-e",
        type=float,
        default=0.1,
        help='The error rate for the bloom filters, how likely they are to return a false positive (Default is "0.1")',
    )
    train_parser.set_defaults(func=train_command)

    # Create the parser for breaking hashes
    break_parser = subparsers.add_parser(
        "break", help="Break a hash using a set of pre-trained bloom filters"
    )
    break_parser.add_argument(
        "hash",
        type=str,
        help="The hash you want to break",
    )
    break_parser.add_argument(
        "--hash-alg",
        type=str,
        help="The hashing algorithm used to create the hash",
    )
    break_parser.add_argument(
        "--filters-path",
        "-f",
        type=Path,
        default=Path("./pretrained_filters"),
        help='Dir where all the pre-created bloom filters are stored (Default is "./pretrained_filters")',
    )
    break_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose",
    )
    break_parser.set_defaults(func=break_hash_command)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
