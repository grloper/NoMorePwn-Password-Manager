# NoMorePwn bounded readiness assessment

This is not a production certification. Inspected baseline: PR #8 (`4afcc0f`); its multi-hop origin verification and native-launch repairs remain unchanged.

## Implemented security repairs

- Lock now revokes the Vault object itself. Retained references cannot enumerate metadata, delete rows, export backups, reveal secrets, or change settings after lock. A typed VaultLockedError requests a new unlock. An already-started rekey completes its atomic database rewrite if lock arrives during it, but cannot reactivate the revoked object; a fresh unlock then uses the new password. This is not a general concurrent-mutation guarantee. Python immutable key bytes cannot be reliably zeroized; live-process memory remains outside this threat model.
- KDF metadata read from vault databases is now validated before any costly derivation, including strict integer types, resource compatibility ceilings, and Argon2 memory/lane consistency. Backup inputs already had separate caps. Accepted parameters are replayed unchanged: existing ciphertext, verifier and AAD formats remain intact. The desktop budget permits at most 256 MiB, 10 Argon2 passes, a combined memory-times-passes limit of 655,360 KiB, and 2 million PBKDF2 iterations. Standard defaults remain supported. Previously accepted custom heavier files are rejected without modification and require a future explicit migration tool; this is a compatibility boundary. These budgets are not a responsiveness guarantee.
- Create refuses every nonempty existing file, including a vault with a deleted verifier. It cannot silently replace KDF/verifier metadata while stranding ciphertext. Recovery of corrupt files remains a deliberate separate action; no automatic repair overwrites data.
- Native framing rejects JSON arrays/scalars instead of crashing on `.get`; desktop IPC also rejects nonobject JSON. This does not add authentication to the local IPC protocol.

## Remaining material boundaries

Local desktop IPC trusts same-user processes; it has no authenticated credential-source proof. Native browser registration pins extension identity, but does not eliminate same-user IPC injection. Message fragmentation/size handling and local socket identity deserve a dedicated protocol revision. Capture legacy messages lacking the unverified flag are still treated as verified; this compatibility decision should be reconsidered alongside a versioned handshake.

Encrypted storage uses authenticated AES-GCM and UUID-bound AAD. Service names, usernames and groups are plaintext metadata. Integrity sweep is not a comprehensive authenticated audit of all notes/history. Editor failure paths, backup rotation/retry, and restore rollback need fault-injected coverage before a broad reliability claim.

Updater authenticity currently depends on GitHub HTTPS/TLS and repository release provenance, with no independent publisher signature trust anchor. Installed browser-to-native registration and packaged update/install flows have not been newly executed by this assessment. Prior source-launch evidence is not proof of these installed flows.

Current PR CI includes Windows/Linux Python tests, extension tests, browser capture and native E2E; releases are prereleases. The older CLAUDE.md CI description is stale. Historical secret-scanner alerts are retained; this work neither dismisses alerts nor rewrites history.

All new tests use disposable databases and synthetic credentials. No live vault, browser passwords, or production account material is used.

