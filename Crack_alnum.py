#!/usr/bin/env python3
"""
Step 4 - Cracking the alphanumeric group (Python).

Salt was CONFIRMED in Step 3:  www.exploringsecurity.com
Model:                         SHA1(salt + password)
Policy for this group:         alphanumeric, 5-7 chars

Two passes:
  1) Dictionary attack with simple mangling rules (fast, likely to hit
     human-chosen passwords).
  2) Brute force over the 5-char lowercase+digit space (fallback).

Usage:
    python crack_alnum.py                 # built-in mini wordlist + brute force
    python crack_alnum.py rockyou.txt     # use a real wordlist for pass 1
"""

import hashlib
import itertools
import string
import sys
import time

SALT = "www.exploringsecurity.com"          # confirmed in Step 3

# Remaining targets (the alphanumeric group). We remove entries as we crack them.
TARGETS = {
    "2834da08d58330d8dafbb2ac1c0f85f6b3b135ef": "Sparky",     # admin
    "92e54f10103a3c511853c7098c04141f114719c1": "Mark123",
    "437fbc6892b38db6ac5bdbe2eab3f7bc924527d9": "superman",
    "f44f3b09df53c1c11273def13cacd8922a86d48c": "JillC",
}

# Hash the salt ONCE, then clone this state per guess (big speed win).
BASE = hashlib.sha1(SALT.encode())

def salted_hash(guess: str) -> str:
    h = BASE.copy()                 # reuse the salt's hashed state
    h.update(guess.encode())        # only the guess still needs hashing
    return h.hexdigest()

def check(guess: str) -> bool:
    """Hash a guess, report + record a hit. Returns True if all targets cracked."""
    digest = salted_hash(guess)
    if digest in TARGETS:
        print(f"  [HIT] user={TARGETS[digest]:10} password={guess!r}")
        del TARGETS[digest]         # stop looking for this one
    return not TARGETS              # True once nothing is left

# Policy filter: only try candidates that match "alphanumeric, 5-7 chars".
ALNUM = set(string.ascii_letters + string.digits)
def policy_ok(word: str) -> bool:
    return 5 <= len(word) <= 7 and all(c in ALNUM for c in word)

# ---------------------------------------------------------------------------
# Pass 1: dictionary attack with mangling rules
# ---------------------------------------------------------------------------
BUILTIN_WORDS = [
    "password", "secret", "admin", "letmein", "welcome", "monkey",
    "dragon", "superman", "batman", "qwerty", "abc", "love", "hello",
    "master", "shadow", "ninja", "football", "jesus", "michael",
]

def mangle(word):
    """Yield rule-based variants of a base word."""
    yield word                      # as-is
    yield word.capitalize()         # Password
    yield word.upper()              # PASSWORD
    for n in range(1000):           # append 0..999  -> secret1, love123, ...
        yield word + str(n)
        yield word.capitalize() + str(n)

def dictionary_pass(words):
    print(f"Pass 1: dictionary attack over {len(words)} base words...")
    for word in words:
        for variant in mangle(word):
            if policy_ok(variant) and check(variant):
                return True
    return False

# ---------------------------------------------------------------------------
# Pass 2: exhaustive brute force (5-char lowercase+digits)
# ---------------------------------------------------------------------------
CHARSET = string.ascii_lowercase + string.digits   # 36 symbols
BRUTE_LENGTHS = (5,)    # 6 and 7 are feasible but slow in Python -> use hashcat

def brute_force():
    for length in BRUTE_LENGTHS:
        total = len(CHARSET) ** length
        print(f"Pass 2: brute forcing {length}-char space "
              f"({total:,} candidates)...")
        start = time.time()
        for i, combo in enumerate(itertools.product(CHARSET, repeat=length), 1):
            if check("".join(combo)):
                return True
            if i % 2_000_000 == 0:          # periodic progress + rate
                rate = i / (time.time() - start)
                print(f"    {i:,}/{total:,}  ({rate:,.0f} h/s)")
    return False

def main():
    words = BUILTIN_WORDS
    if len(sys.argv) > 1:               # optional external wordlist
        with open(sys.argv[1], encoding="latin-1") as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(words):,} words from {sys.argv[1]}")

    if dictionary_pass(words):
        print("\nAll targets cracked in the dictionary pass.")
        return
    print(f"\n{len(TARGETS)} still uncracked after pass 1. Moving to brute force.\n")

    if brute_force():
        print("\nAll targets cracked.")
    else:
        print(f"\nStill uncracked: {list(TARGETS.values())}")
        print("These are likely 6-7 chars -> switch to hashcat with a mask.")

if __name__ == "__main__":
    main()
