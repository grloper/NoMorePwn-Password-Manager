"""NoMorePwn — local-first credential vault and security audit tool.

Everything in this package operates on a single local SQLite file.
No plaintext secret ever leaves the machine: the only outbound network
call in the entire codebase is the k-anonymity range query in
`nomorepwn.leakcheck`, which transmits 5 hex characters of a SHA-1 hash.
"""

__version__ = "0.1.0"
