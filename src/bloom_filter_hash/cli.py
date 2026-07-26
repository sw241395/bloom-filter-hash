import argparse
from pathlib import Path
from .train import train


def train_command(args):
    train(
        charset=set(list(args.charset)),
        password_length=args.pwdlen,
        hash_alg=args.hash_alg,
        output_path=args.output,
        bloom_filter_error_rate=args.error_rate,
    )


def break_command(args):
    print(args)


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
    break_parser.set_defaults(func=break_command)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
