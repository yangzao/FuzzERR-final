#! /usr/bin/env python3

import os
import sys
from utils import (
    get_timestamp
)


def main():
    if len(sys.argv) < 2:
        print("[!] usage: convert_txt_to_mask.py <mask_txt_file>")
        exit(1)

    # - read the mask file
    # - for each line, construct a 32 bit integer from the bits
    #   (treating the 1s and 0s as a bit pattern)
    # - convert the integer to bytes as big endiand and write to file

    ts = get_timestamp()
    saved_error_mask_file = os.path.join(ts + "_converted")

    with open(saved_error_mask_file, "wb") as mask_file:
        with open(sys.argv[1], "r") as mask_txt_file:
            for line in mask_txt_file:
                line = line.strip().replace(",", "")
                i = int(line, base=2)
                mask_file.write(i.to_bytes(4, 'little'))

    print(f">> created mask file: {saved_error_mask_file}")


if __name__ == "__main__":
    main()
