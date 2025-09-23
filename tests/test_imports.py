import importlib
import pathlib
import typing

import pytest


SRC_DIR = pathlib.Path(__file__).parent.parent / "src"


def discover_modules(source_dir: pathlib.Path) -> typing.List:
    """
    Function returning a list of dotted import paths
    that should be attempted imported by calling function
    e.g. importlib.import_module[dotted.path]
    """
    module_paths = []
    for py_file in source_dir.rglob("*.py"):
        if "tests" in py_file.parts or py_file.name == "conftest.py":
            continue

        # Convert file path to module path (e.g., src/my_app/utils.py -> my_app.utils)
        relative_path = py_file.relative_to(source_dir)
        module_str = ".".join(relative_path.with_suffix("").parts)
        module_paths.append(module_str)

    return module_paths


# Use pytest.mark.parametrize to create a separate test for each discovered module.
# This gives clearer feedback than a single test with a loop.
@pytest.mark.parametrize("module_name", discover_modules(SRC_DIR))
def test_module_imports(module_name):
    """
    Tests that a given module can be imported without raising an exception.
    """
    try:
        importlib.import_module(module_name)
    except ImportError as e:
        pytest.fail(f"Failed to import module '{module_name}'. Error: {e}")
