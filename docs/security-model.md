# Security model

This document describes the security architecture, trust assumptions, threat model, cryptographic design, and residual risk of Secure File Sharing with TEEs. The central design goal is to protect file contents and active key material while they are processed on cloud infrastructure outside the data owner's trust boundary.

## Scope and security objectives

The system protects files while they are stored, transferred, and processed. Its security design has four primary objectives:

| Objective | Protected property |
| --- | --- |
| Confidentiality | File contents and application key material are unavailable to the host, hypervisor, cloud operator, and external storage services. |
| Integrity | Unauthorized changes to file ciphertext, wrapped keys, access-control records, and security-relevant database state are detected. |
| Access control | Only the owner and users who hold an authorized wrapping of a file key can recover that file. |
| Accountability | Security-relevant actions are recorded in a tamper-evident audit chain, and selected user actions carry client signatures. |

Availability is not a security guarantee of this design. A malicious host or cloud operator can deny service by stopping the VM, blocking network access, or withholding storage. This risk is accepted rather than hidden behind a confidentiality or integrity claim.

## Assets and protected state

| Asset or state | Why it matters | Protection |
| --- | --- | --- |
| File plaintext | Primary confidentiality asset | Present server-side only inside the TDX VM and returned to an authorized client over TLS. |
| `Master_KEK` | Root of the application key hierarchy | HSM-backed RSA-3072 key retained by Azure Key Vault Premium and released only under the attestation policy. |
| `Service_Root` and derived subkeys | Protect every application cryptographic domain | The root is stored only in wrapped form and recovered inside the attested VM. Derived keys remain in TDX-protected memory. |
| Per-user `User_KEK` and per-file `File_DEK` | Enforce cryptographic ownership and sharing | Stored only as context-bound wrapped values outside the VM. |
| Password verifier and pepper | Authenticate users while resisting offline attacks | Argon2id verifier in PostgreSQL; independent HMAC pepper derived from `Service_Root`. |
| Session token | Represents the authenticated application subject | HMAC-protected, short-lived, and revalidated on each request. |
| ACL and file-key relationships | Determine who can recover each file key | Authenticated records plus the Key Vault state anchor; the ACL alone is not sufficient to decrypt a file. |
| Audit records and client signatures | Provide chronological and user-origin evidence | Encrypted hash chain, state anchoring, and browser-generated P-256 signatures for sensitive actions. |
| Attestation evidence and token | Authorize recovery of the root key | Hardware-backed TDX evidence validated by Microsoft Azure Attestation and constrained by the Key Vault release policy. |

Ciphertext, wrapped keys, and metadata are not confidential plaintext, but they remain security-relevant state: substitution, deletion, rollback, or reassociation could otherwise violate integrity or access control.

## Security architecture and trust boundaries

The Intel TDX confidential VM is the main server-side trust boundary. File encryption and decryption, key wrapping and unwrapping, password verification, access-control decisions, and audit processing occur inside that boundary. The host OS, hypervisor, cloud operator, Blob Storage, and PostgreSQL are outside it.

| Component | Trust status and security role |
| --- | --- |
| Intel TDX confidential VM | Main trust domain. Executes the guest OS and application and holds server-side plaintext and active application keys. |
| Microsoft Azure Attestation (MAA) | Trust authority that validates TDX evidence and issues the attestation token used by the release policy. |
| Azure Key Vault Premium | Separate key-management boundary. Retains the HSM-backed master key and trusted state anchor. |
| Browser client | Outside the server trust boundary. Holds the user's plaintext, session, and non-extractable signing key. |
| Azure Blob Storage | Untrusted external storage for encrypted file chunks. |
| PostgreSQL | Untrusted external storage for wrapped keys, password verifiers, encrypted filenames, authenticated ACL records, and encrypted audit entries. |

### Trusted computing base

The server-side trusted computing base (TCB) includes Intel TDX hardware and firmware, the confidential VM's guest OS, runtime libraries, Secure Key Release client, and the application. TDX protects the VM from the host and hypervisor; it does not isolate the application from a compromised process or kernel inside the guest.

The design also depends on correct configuration and operation of Microsoft Azure Attestation, Azure Key Vault, Azure identity assignments, TLS, and the client-delivered browser code. Keeping the in-guest software stack and its dependencies small and reviewable reduces the TCB but does not eliminate it.

### Adversary model

The model considers:

- A privileged system-software attacker controlling the host OS, hypervisor, or cloud-management plane and attempting to inspect VM memory or stored state.
- A network attacker capable of passive observation or active man-in-the-middle attempts against data in transit.
- An attacker who obtains a disk, database, or Blob Storage snapshot.
- A malicious or compromised client attempting to access another user's files, replay authorization data, or repudiate a sensitive action.
- Limited physical attacks such as brief data-center access, cold-boot attempts, or DRAM probing, subject to the guarantees and limitations of the underlying TDX platform.

A malicious in-guest process or compromised software dependency is analyzed as a residual TCB risk rather than an attacker fully isolated by the architecture.

## Attack surface and threat enumeration

The attack surface is organized around data flows that cross trust boundaries. STRIDE was used to consider spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege at each boundary.

| ID | Interface and trust transition | Principal threats |
| --- | --- | --- |
| AS1 | Client to confidential VM over TLS 1.3 | Man-in-the-middle attempts, stolen sessions, cross-site attacks, login brute force, and malicious input. |
| AS2 | Confidential VM to Microsoft Azure Attestation | Forged, substituted, stale, or replayed attestation evidence and tokens. |
| AS3 | Confidential VM to Azure Key Vault | Stolen workload identity, an over-permissive release policy, unauthorized key release, and anchor manipulation. |
| AS4 | Confidential VM to Blob Storage and PostgreSQL | Snapshot disclosure, ciphertext or metadata tampering, record substitution, deletion, rollback, and metadata leakage. |

Denial of service is possible at every external boundary and is intentionally outside the system's protection goals.

## Remote attestation and secure key release

The application cannot recover its persistent root key merely because it has access to the VM disk or Azure subscription resources. Recovery is gated by the following attestation chain:

1. At startup, the confidential VM creates an ephemeral RSA transport key pair inside TDX-protected memory.
2. The VM obtains TDX evidence that binds the transport public key to the attested execution environment.
3. Microsoft Azure Attestation validates the Intel-rooted evidence and evaluates the configured attestation policy.
4. MAA issues a signed token carrying the relevant TEE identity, compliance, measurement, and transport-key binding claims.
5. Azure Key Vault validates the MAA authority and the configured TDX claims, including the pinned `tdx_mrtd` value, before releasing the HSM-backed `Master_KEK` encrypted to the ephemeral transport key.
6. The VM recovers the released key inside the TDX trust domain and uses it to unwrap `Service_Root`.

The Secure Key Release client handles the TDX evidence format and the nested MAA claims used by the Key Vault policy. A forged token, evidence replay, or unattested direct request is therefore insufficient to obtain the master key.

This is boot-state attestation, not continuous application attestation. In the evaluated Azure CVM configuration, the application is not independently measured into populated runtime measurement registers. The policy can identify an approved TDX boot state, but it cannot detect a later in-guest compromise at runtime.

## Key-management design

```text
Master_KEK          RSA-3072 key retained by Azure Key Vault Premium
  └─ Service_Root   persistent 32-byte symmetric root, wrapped by Master_KEK
      ├─ password_pepper
      ├─ session_hmac
      ├─ user_kek_wrap
      ├─ acl_mac
      ├─ audit_hmac
      └─ audit_enc

user_kek_wrap
  └─ User_KEK       random key for each user
      └─ File_DEK    random key for each file and separately wrapped for each authorized user
```

`Service_Root` provides a stable symmetric root because the asymmetric `Master_KEK` cannot be used directly as HKDF input. Domain-separated derivation prevents a key used for one purpose from being reused in another cryptographic context.

A file is encrypted once under its `File_DEK`. Each authorized user receives a separate wrapping of that DEK under the user's `User_KEK`; the user's KEK is protected under `user_kek_wrap`. Sharing therefore changes the key graph rather than duplicating or re-encrypting file contents.

## Applied cryptography

| Purpose | Mechanism and security reasoning |
| --- | --- |
| Data in transit | TLS 1.3 protects client-to-service traffic against passive observation and network modification. |
| File confidentiality and integrity | AES-256-GCM protects independently processed 4 MiB chunks. Fresh nonces and authenticated context provide confidentiality and tamper detection. |
| Key and filename protection | Context-bound authenticated encryption prevents wrapped keys or encrypted names from being transplanted to a different user, file, or version. |
| Key separation | HKDF-derived subkeys separate password, session, key-wrapping, ACL, and audit domains. |
| Password verification | Argon2id increases the cost of guessing; a TEE-held HMAC pepper means a database snapshot alone is insufficient for offline verification. |
| Sessions and ACLs | HMAC authentication detects modification of session tokens and access-control evidence. |
| Stored-state anchoring | A SHA-256 digest held in Key Vault commits to the current security-relevant database state. |
| User-origin evidence | A non-extractable browser-generated ECDSA P-256 key signs share, revoke, and delete statements. |
| Audit confidentiality and integrity | Separate encryption and HMAC-derived keys protect payloads and bind each entry to the previous entry's hash. |

### Context binding

| Protected object | Authenticated context |
| --- | --- |
| User KEK | User identifier and version |
| File DEK | User identifier, file identifier, and version |
| Filename | File identifier and version |
| File chunk | File identifier, format version, chunk index, and total chunk count |
| ACL record | File identifier, user identifier, permission, and version |

Binding every chunk to its file and position causes reordered, duplicated, removed, or transplanted chunks to fail authentication or container-consistency checks. Binding wrapped keys and ACL records to their identities prevents valid records from being reassigned to a different principal or object.

## Authorization, sharing, and revocation

Passwords are processed with Argon2id after a server-held HMAC pepper. Successful authentication creates an HMAC-protected session token. Every protected request revalidates the session and its subject rather than trusting an identifier supplied by the client.

The owner shares a file by wrapping its `File_DEK` for the recipient and adding an authenticated ACL record. File data is not re-encrypted. Authorization requires a valid session, an authorized ACL relationship, and a matching wrapped key path; no single database flag grants access by itself.

Revocation removes the recipient's ACL entry and wrapped file key, preventing future recovery through the service. Revocation cannot erase plaintext or keys that an authorized recipient previously downloaded or retained.

At registration, the browser creates a non-extractable P-256 signing key and registers the public key. Share, revoke, and delete statements bind the action, acting user, file, recipient, permission, timestamp, and nonce. The application verifies the signature and records the signed statement in the protected audit chain. This prevents the server from fabricating a valid client-signed action, but it does not protect a user whose browser or signing context is compromised.

## Stored-state integrity and audit design

Authenticated encryption detects modification when an encrypted value is opened. It does not, by itself, reveal that an entire valid row was deleted or that the database was rolled back. The design therefore adds a Key Vault state anchor over ordered file, user-key, file-key, ACL, and audit-chain state.

The application verifies the anchor at startup and before security-relevant state changes. After a successful change, it commits the updated SHA-256 digest to Key Vault. This makes unauthorized rollback or deletion detectable; it does not prevent an untrusted store from causing a denial of service.

The encrypted audit log provides chronological evidence. Every entry authenticates the previous entry's hash, and verification walks the chain from its genesis. The anchor and audit chain are complementary: the anchor commits to expected current state, while the chain authenticates the sequence of recorded events.

## Risk assessment and mitigation reasoning

The initial assessment uses likelihood and impact values from 1 (low) to 3 (high), with `risk = likelihood × impact`. Scores 1–2 are low, 3–4 medium, and 6–9 high. These are engineering estimates used to compare threats, not universal probabilities.

| Threat | L | I | Initial risk | Primary controls | Residual posture |
| --- | ---: | ---: | ---: | --- | --- |
| Host or hypervisor reads VM memory | 1 | 3 | 3 | Intel TDX memory encryption and isolation | Mitigated for the modeled host attacker; platform trust and side channels remain. |
| Malicious in-guest process or supply-chain compromise | 2 | 3 | 6 | Reduced TCB and reviewed dependencies | Partial. The whole VM is the TCB and boot attestation does not detect runtime compromise. |
| Stolen disk, database, or Blob snapshot | 2 | 3 | 6 | AEAD-protected data, wrapped keys, and no plaintext root key on disk | File contents and keys remain protected; size and operational metadata may still leak. |
| Forged or replayed attestation token | 1 | 3 | 3 | Intel-rooted evidence, MAA-signed token, claim validation, and key binding | Mitigated subject to trust in MAA and correct freshness and policy checks. |
| Over-permissive Key Vault release policy | 2 | 3 | 6 | Pinned MAA authority, TEE type, compliance claims, `tdx_mrtd`, and least privilege | Partial. Policy correctness and deployment review remain critical. |
| Stolen session or login brute force | 2 | 2 | 4 | Short-lived authenticated sessions, per-request subject validation, rate limiting, and lockout | Partial. A compromised client can act within its session and authorization scope. |
| Database dump used for offline password guessing | 2 | 2 | 4 | Argon2id plus an independent TEE-held pepper | A database dump alone is insufficient; low-entropy passwords remain a concern if the pepper or runtime is compromised. |
| Repudiation of a sensitive user action | 2 | 2 | 4 | Client P-256 signature recorded in the TEE-keyed audit chain | Mitigated against server fabrication; a compromised browser remains outside the guarantee. |
| Denial of service by the host or an external dependency | 2 | 2 | 4 | Operational recovery and monitoring only | Accepted and outside the confidentiality/integrity scope. |

Additional integrity threats are handled as follows:

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Rollback or deletion of stored rows | Key Vault state anchor verified before protected changes | Tamper evidence rather than prevention; an attacker can still make the service unavailable. |
| Modification, reordering, truncation, or transplantation of ciphertext | AES-256-GCM, identity- and position-bound AAD, container framing, and database/blob consistency checks | No material undetected modification within the modeled cryptographic assumptions. |
| Copying a wrapped key or ACL record to another user or file | User, file, permission, and version identifiers included in authenticated context | Reassociated records fail verification or cannot produce an authorized key path. |

## Adversarial validation

The deployed system was exercised against live Azure Blob Storage and PostgreSQL resources rather than only in-memory substitutes. The adversarial checks targeted the guarantees above:

| Manipulation | Expected and observed security result |
| --- | --- |
| Flip bits in an encrypted chunk | AES-GCM authentication rejects the chunk. |
| Reorder, remove, or transplant chunks | Position-bound AAD, framing, and blob/database consistency checks reject the file. |
| Copy a wrapped file-key row to another user | Identity-bound authenticated context prevents successful unwrapping for the new user. |
| Delete or roll back ACL and related database state | The recomputed state digest no longer matches the Key Vault anchor. |
| Request the master key without valid TDX attestation | Key Vault denies release under the configured policy and identity controls. |
| Verify a password with an incorrect pepper | Authentication fails even when the stored Argon2id value is unchanged. |
| Fabricate a share, revoke, or delete action on behalf of a user | The server cannot produce a valid signature under the user's browser-held private key. |

These checks demonstrate detection and enforcement for the tested attack classes. They do not prove the absence of implementation defects or attacks outside the stated model.

## Assumptions and limitations

- The VM image, guest OS, application, dependencies, release policy, Azure identities, and browser-delivered code are configured and maintained correctly.
- TDX protects against the modeled host and hypervisor attacker, but the security argument still depends on Intel and Azure platform guarantees and does not claim comprehensive side-channel resistance.
- Boot attestation does not continuously measure application execution. A successful in-guest compromise can access plaintext and active keys available to the compromised process.
- The client endpoint remains part of the end-to-end security path. Malware, XSS, or a stolen authenticated session on the client can act with that user's authority.
- External storage may reveal unavoidable operational metadata such as object sizes, access timing, and database structure even though protected filenames, contents, keys, and records remain confidential or authenticated.
- The state anchor and cryptographic integrity checks detect manipulation; they cannot force an untrusted storage service to return data or prevent denial of service.
- Revocation blocks future service-mediated access but cannot recall data already obtained by an authorized recipient.
- Availability, destructive physical attacks beyond the platform's stated guarantees, and denial of service by privileged infrastructure are outside scope.
