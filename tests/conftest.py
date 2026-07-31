import pytest
import tempfile
from bloom_filter_hash import train


# Temp dir to use in tests
@pytest.fixture(scope="session", autouse=True)
def temp_dir():
    temp_dir = tempfile.TemporaryDirectory()
    print(1, temp_dir.name)

    # Create a small set of filters to use in the break filters testing
    train(charset={"a", "b", "c"}, password_length=2, output_path=temp_dir.name)

    yield temp_dir.name
    print("-" * 100)
    temp_dir.cleanup()
