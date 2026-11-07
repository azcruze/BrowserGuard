import argparse

from app import create_app
from app.benchmark import seed_benchmark


def main():
    parser = argparse.ArgumentParser(description="Initialize or safely reset BrowserGuard's synthetic benchmark data.")
    parser.add_argument("--reset", action="store_true", help="replace benchmark records while preserving user uploads")
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        result = seed_benchmark(reset=args.reset)
        print(result)


if __name__ == "__main__":
    main()
