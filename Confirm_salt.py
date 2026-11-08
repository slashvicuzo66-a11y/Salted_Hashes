#!/usr/bin/env python3
"""
Step 3 - Salt confirmation harness.

Idea: the two pre-May-2010 passwords are digits only, 5-7 chars.
That is only ~11.1 million candidates, which is trivial to brute force.
So we use that tiny keyspace as an ORACLE: for each candidate salt we try
every digit string against the two easy hashes. A single match proves the
salt is correct (and cracks that password at the same time).
"""

import hashlib
import itertools

# --- The two "easy" target hashes (digit-only group, from Pass_modified < May 2010) ---
TARGETS = {
    "06f6fe0f73c6e197ee43eff4e5f7d10fb9e438b2": "Tomtom",
    "fafa4483874ec051989d53e1e432ba3a6c6b9143": "security",
}

# --- Candidate salts drawn from the document, most-likely first ---
CANDIDATE_SALTS = [
    "www.exploringsecurity.com",
    "exploringsecurity.com",
    "exploringsecurity",
    "www.exploringsecurity",
    "ExploringSecurity",
    "",                      # control: no salt at all
]

# Password policy for this group: digits only, length 5 to 7
LENGTHS = (5, 6, 7)


def sha1(text: str) -> str:
    """Return the hex SHA-1 digest of a string."""
    return hashlib.sha1(text.encode()).hexdigest()


def try_salt(salt: str) -> bool:
    """Brute force the digit keyspace for one candidate salt.
    Returns True if at least one target hash was matched."""
    found_any = False
    for length in LENGTHS:
        for digits in itertools.product("0123456789", repeat=length):
            guess = "".join(digits)              # e.g. "00042"
            digest = sha1(salt + guess)          # model: SHA1(salt + password)
            if digest in TARGETS:
                print(f"  [HIT] user={TARGETS[digest]:10} "
                      f"password={guess!r}  salt={salt!r}")
                found_any = True
    return found_any


def main():
    print("Testing candidate salts against the two digit-only hashes...\n")
    for salt in CANDIDATE_SALTS:
        print(f"Trying salt = {salt!r}")
        if try_salt(salt):
            print(f"\n>>> SALT CONFIRMED: {salt!r}\n")
            return
    print("\nNo salt matched. Next: try SHA1(password + salt) ordering, "
          "or widen the candidate list.")


if __name__ == "__main__":
    main()
