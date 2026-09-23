# Security model

## Security objectives

The system protects files while they are stored, transferred, and processed on cloud infrastructure. Its security design has four objectives:

| Objective | Property |
| --- | --- |
| Confidentiality | File contents and application key material are unavailable to the host, hypervisor, cloud operator, and external storage services. |
| Integrity | Unauthorized changes to file ciphertext, wrapped keys, access-control records, and anchored database state are detected. |
| Access control | Only the owner and users who hold an authorized wrapping of a file key can recover that file. |
| Accountability | Security-relevant actions are recorded in a tamper-evident audit chain, and selected user actions carry client signatures. |

## Trust boundary

The Intel TDX confidential VM is the server-side trust boundary. The guest OS, application, runtime libraries, and Secure Key Release client execute inside it. Intel TDX encrypts and isolates the VM's memory and execution state from the Azure host and hypervisor.

| Component | Security role |
| --- | --- |
| Intel TDX confidential VM | Executes the application and holds server-side plaintext and active application keys. |
| Microsoft Azure Attestation | Validates the hardware-backed TDX evidence and issues the token used for key release. |
| Azure Key Vault Premium | Retains the HSM-backed master key and the trusted state anchor. |
| Browser client | Holds the user's plaintext, session, and signing key. |
| Azure Blob Storage | Stores encrypted file chunks. |
| PostgreSQL | Stores wrapped keys, password hashes, encrypted filenames, authenticated ACL records, and encrypted audit entries. |

Key release depends on the configured attestation and release policies. The model also assumes the guest software, browser code, Azure identity assignments, and TLS configuration are trusted and correctly deployed.

## Attestation-gated boot

At startup, the confidential VM obtains a hardware-backed TDX quote and submits it to Microsoft Azure Attestation. The resulting token carries the TEE identity and measurements evaluated by the Key Vault release policy. Key Vault releases the master key only when the token satisfies that policy.

The released key is recovered inside the TDX VM and unwraps the persistent `Service_Root`. The application derives its purpose-specific symmetric keys from that root for the lifetime of the process. The wrapped root stored on disk is not sufficient to recover application keys without a successful attested release.

## Key hierarchy

```text
Master_KEK        RSA-3072 key retained by Azure Key Vault Premium
  └─ Service_Root persistent 32-byte symmetric root, wrapped by Master_KEK
      ├─ password_pepper
      ├─ session_hmac
      ├─ user_kek_wrap
      ├─ acl_mac
      ├─ audit_hmac
      └─ audit_enc
          └─ User_KEK   random key for each user
              └─ File_DEK   random key for each file
```

The `Service_Root` exists because the asymmetric master key cannot be used as HKDF input. Deriving separate subkeys keeps password authentication, sessions, key wrapping, ACL authentication, and audit protection in distinct cryptographic domains.

A file is encrypted once under its `File_DEK`. Each authorized user receives a copy of that key wrapped by the user's `User_KEK`; the user's KEK is itself protected by `user_kek_wrap`.

## File and metadata protection

File contents are split into 4 MiB chunks and protected with AES-256-GCM. Each chunk authenticates the file identifier, format version, chunk index, and total chunk count as additional data. This binds ciphertext to both its file and its position, so reordered, duplicated, removed, or transplanted chunks fail authentication.

The same contextual binding is used when encrypting filenames and wrapping user and file keys:

| Protected object | Authenticated context |
| --- | --- |
| User KEK | User identifier and version |
| File DEK | User identifier, file identifier, and version |
| Filename | File identifier and version |
| File chunk | File identifier, version, chunk index, and total chunk count |
| ACL record | File identifier, user identifier, permission, and version |

## Sharing and revocation

The owner shares a file by wrapping its `File_DEK` for the recipient and adding an authenticated ACL record. File data does not need to be re-encrypted because every recipient receives access to the same per-file key through a separate wrapping path.

Revocation removes the recipient's ACL entry and wrapped file key. Subsequent authorization checks can no longer recover the file key for that user.

## Stored-state integrity

Authenticated encryption detects modification of encrypted values when the application opens them. A separate Key Vault state anchor protects the relationships among current database records and detects unauthorized deletion or rollback of security-relevant state.

The anchor is a SHA-256 digest over ordered file, user-key, file-key, ACL, and audit-chain state. The application verifies it at startup and before requests that can change persistent state. After a successful change, it writes the new digest to Key Vault.

The audit log adds chronological evidence. Audit payloads are encrypted, each entry authenticates the previous entry's hash, and verification walks the chain from its genesis. The anchor and audit chain serve different purposes: the anchor represents the expected current state, while the chain authenticates the recorded history.

## User authorization and signed actions

Passwords are processed with Argon2id after a server-held HMAC pepper. Successful authentication creates an HMAC-protected session token used for API authorization.

At registration, the browser generates a non-extractable P-256 signing key and registers the public key. Share, revoke, and delete statements bind the action, acting user, file, recipient, permission, timestamp, and nonce. The application verifies the signature and records the signed statement in the encrypted audit chain.

Together, the session establishes the active account, the ACL and key hierarchy determine file access, and the client signature prevents the application from fabricating a signed user action.
