# run as a separate module
# python3 -m scripts.fuzzerr.tests.crash_minimizer.test_crash_minimizer


from scripts.fuzzerr.crash_minimizer import (
    _get_effective_ids,
    is_set,
    is_unset,
    unset_bit,
    set_bit,
)

from scripts.fuzzerr.utils import get_current_fn_name


def test_set_bit():
    print(f"[*] running {get_current_fn_name()}")
    arr = bytearray([17, 18])
    # binary: 00010001, 00010010

    set_bit(1, arr)
    assert is_set(1, arr)


def test_unset_bit():
    print(f"[*] running {get_current_fn_name()}")
    arr = bytearray([17, 18])
    # binary: 00010001, 00010010

    unset_bit(0, arr)
    assert is_unset(0, arr)

    unset_bit(1, arr)
    assert is_unset(0, arr)

    unset_bit(9, arr)
    assert is_unset(9, arr)


def test_is_set():
    print(f"[*] running {get_current_fn_name()}")
    arr = bytearray([17, 18])
    # binary: 00010001, 00010010
    assert is_set(0, arr) == True
    assert is_set(1, arr) == False
    assert is_set(4, arr) == True
    assert is_set(5, arr) == False
    assert is_set(8, arr) == False
    assert is_set(9, arr) == True


def test_get_effective_ids():
    print(f"[*] running {get_current_fn_name()}")
    log = None
    with open("scripts/fuzzerr/tests/crash_minimizer/log_get_bit.txt") as f:
        log = f.readlines()
    log = "".join(log)
    # print(log)
    expected = [2, 3, 6, 7, 10, 11, 12, 17, 22, 23, 24, 27, 29]
    got = _get_effective_ids(log)

    print(f"expected:{expected}, got:{got}")
    assert expected == got


if __name__ == "__main__":
    test_get_effective_ids()
    test_is_set()
    test_unset_bit()
    test_set_bit()
