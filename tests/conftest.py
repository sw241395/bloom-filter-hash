import pytest
import tempfile
from bloom_filter_hash import train, train_positions


# Temp dir to use in tests
@pytest.fixture(scope="session", autouse=True)
def temp_dir():
    temp_dir = tempfile.TemporaryDirectory()
    print(1, temp_dir.name)

    # Create a small set of filters to use in the break filters testing
    train(
        charset={"a", "b", "c"},
        password_length=2,
        output_path=f"{temp_dir.name}/pretrained_filters",
    )

    # Create a small set of positional filters to use to break filters testing
    train_positions(
        charset={"a", "b", "c"},
        password_length=2,
        output_path=f"{temp_dir.name}/pretrained_position_filters",
    )

    yield temp_dir.name
    temp_dir.cleanup()
