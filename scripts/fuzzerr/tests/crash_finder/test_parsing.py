# run as a separate module
# python3 -m scripts.fuzzerr.tests.crash_finder.test_parsing


from scripts.fuzzerr.crash_finder import (
    _get_src_line_for_crash,
    _get_src_line_for_last_get_bit,
    parse_asan_crash
)

from scripts.fuzzerr.utils import get_current_fn_name


def test_parse_asan_crash():
    print(f"[*] running {get_current_fn_name()}")
    log = None
    with open("scripts/fuzzerr/tests/crash_finder/log_asan2.txt") as f:
        log = f.readlines()
    log = "".join(log)

    crash_info = parse_asan_crash(log, "")
    assert crash_info is not None
    assert crash_info["crash_filename"] == "lib_tparm.c"
    assert crash_info["crash_filename_path"] == "/home/shank/code/research/detecterr_input/ncurses-6.3/ncurses-6.3/ncurses/tinfo/lib_tparm.c"
    assert crash_info["crash_line"] == 621
    assert crash_info["crash_func"] == "tparm_setup"
    print(f"passed")


def test_get_src_line_for_last_get_bit():
    print(f"[*] running {get_current_fn_name()}")
    log = None
    with open("scripts/fuzzerr/tests/crash_finder/log_get_bit2.txt") as f:
        log = f.readlines()
    log = "".join(log)
    # print(log)

    src_path = "/home/shank/code/research/tmp/libpng-1.6.35"
    expected = 2142
    got = _get_src_line_for_last_get_bit(src_path=src_path, logtxt=log)

    print(f"expected:{expected}, got:{got}")
    assert expected == got


def test_get_src_line_for_crash():
    print(f"[*] running {get_current_fn_name()}")
    log = None
    with open("scripts/fuzzerr/tests/crash_finder/log_asan.txt") as f:
        log = f.readlines()
    log = "".join(log)
    # print(log)

    src_path = "/home/r3x/griller/griller/tests"
    expected = 75
    got = _get_src_line_for_crash(src_path=src_path, logtxt=log)

    print(f"expected:{expected}, got:{got}")
    assert expected == got


def test_get_src_line_for_crash3():
    print(f"[*] running {get_current_fn_name()}")
    log = None
    with open("scripts/fuzzerr/tests/crash_finder/log_asan3.txt") as f:
        log = f.readlines()
    log = "".join(log)
    # print(log)

    src_path = "/home/shank/code/research/FuzzERR/experiments/libpng/imagemagick_src"
    expected = 150
    got = _get_src_line_for_crash(src_path=src_path, logtxt=log)

    print(f"expected:{expected}, got:{got}")
    assert expected == got


if __name__ == "__main__":
    test_get_src_line_for_crash()
    test_get_src_line_for_crash3()
    test_get_src_line_for_last_get_bit()
    test_parse_asan_crash()
