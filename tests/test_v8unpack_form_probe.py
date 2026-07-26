import importlib.util
from pathlib import Path


_PATH = Path(__file__).parents[1] / "tools" / "v8unpack_form_probe" / "matrix.py"
_SPEC = importlib.util.spec_from_file_location("v8unpack_form_probe_matrix", _PATH)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
at_pointer = _MODULE.at_pointer
json_differences = _MODULE.json_differences
json_pointer = _MODULE.json_pointer
pointer_parts = _MODULE.pointer_parts


def test_probe_matrix_json_pointer_and_minimal_delta():
    pointer = "/data/Страница~1Поле/raw/2/1"
    value = {"data": {"Страница/Поле": {"raw": [0, 1, ["x", "before"]]}}}

    assert pointer_parts(pointer) == ["data", "Страница/Поле", "raw", 2, 1]
    assert at_pointer(value, pointer) == "before"

    changed = {"data": {"Страница/Поле": {"raw": [0, 1, ["x", "after"]]}}}
    differences = list(json_differences(value, changed))
    assert differences == [
        (("data", "Страница/Поле", "raw", 2, 1), "before", "after")
    ]
    assert json_pointer(differences[0][0]) == pointer
