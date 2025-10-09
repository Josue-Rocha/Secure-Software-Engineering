#!/usr/bin/env python3

import hashlib
import os
import sys

HASH_FILES = [
    "md5_30_passwords-pt1.txt",
    "md5_30_passwords-pt2.txt",
    "md5_30_passwords-pt3.txt",
]
OUTPUT_FILE = "cracked_passwords.txt"
MIN_LEN = 3
MAX_LEN = 6

CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "&@#"
)

def load_hashes(files):
    hashes = set()
    for fn in files:
        if not os.path.isfile(fn):
            print(f"Warning: '{fn}' not found — skipping.")
            continue
        with open(fn, "r", encoding="utf-8") as f:
            for line in f:
                h = line.strip().lower()
                if h:
                    hashes.add(h)
    return hashes

def md5_hex(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def append_cracked(plain):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        out.write(plain + "\n")

def brute_force(target_hashes):
    if not target_hashes:
        print("No target hashes to crack.")
        return {}

    cracked = {}
    remaining = set(target_hashes)

    # truncate output file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("")

    # length = 3
    if MIN_LEN <= 3 <= MAX_LEN:
        for a in CHARSET:
            for b in CHARSET:
                for c in CHARSET:
                    cand = a + b + c
                    h = md5_hex(cand)
                    if h in remaining:
                        cracked[h] = cand
                        remaining.remove(h)
                        append_cracked(cand)
                        print(f"Cracked: {cand}")
                        if not remaining:
                            return cracked

    # length = 4
    if MIN_LEN <= 4 <= MAX_LEN:
        for a in CHARSET:
            for b in CHARSET:
                for c in CHARSET:
                    for d in CHARSET:
                        cand = a + b + c + d
                        h = md5_hex(cand)
                        if h in remaining:
                            cracked[h] = cand
                            remaining.remove(h)
                            append_cracked(cand)
                            print(f"Cracked: {cand}")
                            if not remaining:
                                return cracked

    # length = 5
    if MIN_LEN <= 5 <= MAX_LEN:
        for a in CHARSET:
            for b in CHARSET:
                for c in CHARSET:
                    for d in CHARSET:
                        for e in CHARSET:
                            cand = a + b + c + d + e
                            h = md5_hex(cand)
                            if h in remaining:
                                cracked[h] = cand
                                remaining.remove(h)
                                append_cracked(cand)
                                print(f"Cracked: {cand}")
                                if not remaining:
                                    return cracked

    # length = 6
    if MIN_LEN <= 6 <= MAX_LEN:
        for a in CHARSET:
            for b in CHARSET:
                for c in CHARSET:
                    for d in CHARSET:
                        for e in CHARSET:
                            for f in CHARSET:
                                cand = a + b + c + d + e + f
                                h = md5_hex(cand)
                                if h in remaining:
                                    cracked[h] = cand
                                    remaining.remove(h)
                                    append_cracked(cand)
                                    print(f"Cracked: {cand}")
                                    if not remaining:
                                        return cracked

    if remaining:
        print(f"Finished; could not crack {len(remaining)} hashes.")
    else:
        print("All hashes cracked.")
    return cracked

def main():
    targets = load_hashes(HASH_FILES)
    if not targets:
        print("No hashes loaded; check files.")
        sys.exit(1)

    print(f"Loaded: {len(targets)} hashes; Alphabet Size: {len(CHARSET)}; Lengths: {MIN_LEN}...{MAX_LEN}")
    cracked = brute_force(targets)
    print(f"Done. Cracked {len(cracked)} password(s). Results -> {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
