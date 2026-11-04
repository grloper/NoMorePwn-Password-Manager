"""NoMorePwn — local-first credential vault and security audit tool.

Everything in this package operates on a single local SQLite file.
Outbound network use is limited to three optional modules: the HIBP
k-anonymity range query in `nomorepwn.leakcheck` (5 hex chars of a
SHA-1), the public breach-catalog download in `nomorepwn.breachcatalog`
(no vault data transmitted; matching is local), and GitHub Releases in
`nomorepwn.updater`.
"""

__version__ = "1.0.27"
