# Setup and operation

The system was deployed on an Azure Intel TDX confidential VM with managed identities for Key Vault, Blob Storage, and PostgreSQL. The steps below describe that deployment model.

## Prerequisites

| Requirement | Deployment profile |
| --- | --- |
| Confidential VM | Azure DCesv6-series Intel TDX VM; the evaluated deployment used `Standard_DC2es_v6` |
| Guest OS | Ubuntu 24.04 |
| Runtime | Python 3.12 |
| Database | Azure Database for PostgreSQL 16 with Microsoft Entra authentication |
| Object storage | Private Azure Blob container |
| Key management | Azure Key Vault Premium with an HSM-backed RSA-3072 key and Secure Key Release policy |
| Attestation | Microsoft Azure Attestation endpoint accepted by the release policy |
| Network | TLS certificate and private key for the application hostname |

Microsoft documents `Standard_DC2es_v6` as a two-vCPU, 8-GiB member of the [Intel TDX-backed DCesv6 series](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcesv6-series).

## 1. Provision Azure resources

1. Create an Intel TDX confidential VM by following the [Azure confidential VM guide](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-confidential-vm-portal). Enable its system-assigned managed identity.
2. Create an HSM-backed RSA-3072 key in Key Vault Premium. Configure its release policy for the Microsoft Azure Attestation authority and TDX claims used by the deployment. Azure's [Secure Key Release guidance](https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation) describes the attestation and policy flow.
3. Create a separate Key Vault secret name for the database state anchor.
4. Create a private Blob container.
5. Create the PostgreSQL database and enable Microsoft Entra authentication.
6. Allow the VM to reach PostgreSQL, Blob Storage, Key Vault, and the attestation endpoint.

Assign the VM identity these permissions at the narrowest practical scope:

| Resource | Required access |
| --- | --- |
| Key Vault master key | **Key Vault Crypto Service Release User** and **Key Vault Reader** |
| Key Vault anchor secret | Secret get and set; use a scoped custom role or **Key Vault Secrets Officer** |
| Blob container | **Storage Blob Data Contributor** |
| PostgreSQL | Connect plus read and write access to the application tables and audit sequence |

The Key Vault role assignment authorizes the identity to request release; the key's release policy independently evaluates the attestation evidence.

## 2. Prepare PostgreSQL

Following the [managed-identity connection guide](https://learn.microsoft.com/en-us/azure/postgresql/security/security-connect-with-managed-identity), map the VM identity to a database role:

```sql
SELECT * FROM pgaadauth_create_principal(
    'YOUR_MANAGED_IDENTITY_NAME',
    false,
    false
);
```

Apply the schema from the repository root:

```bash
psql "host=YOUR_POSTGRES_HOST dbname=YOUR_DATABASE_NAME user=YOUR_DATABASE_ADMIN sslmode=verify-full sslrootcert=/etc/ssl/certs/ca-certificates.crt" \
  -v ON_ERROR_STOP=1 \
  -f code/schema.sql
```

Grant the runtime identity access to the objects created by `schema.sql`:

```sql
GRANT CONNECT ON DATABASE "YOUR_DATABASE_NAME"
TO "YOUR_MANAGED_IDENTITY_NAME";

GRANT USAGE ON SCHEMA public
TO "YOUR_MANAGED_IDENTITY_NAME";

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    public.users,
    public.user_keys,
    public.files,
    public.file_keys,
    public.acl,
    public.audit_log
TO "YOUR_MANAGED_IDENTITY_NAME";

GRANT USAGE, SELECT ON SEQUENCE public.audit_log_seq
TO "YOUR_MANAGED_IDENTITY_NAME";
```

Application startup does not create the database schema.

## 3. Install the Secure Key Release client

Build and install the `AzureAttestSKR` client used by the deployment. Microsoft publishes the upstream client in the [`cvm-securekey-release-app`](https://github.com/Azure/confidential-computing-cvm-guest-attestation/tree/main/cvm-securekey-release-app) directory.

`code/boot.py` invokes the client through `sudo` with the attestation URL, versioned Key Vault key identifier, input value, and either `-w` or `-u`. Before initializing application state, verify that the installed client:

- obtains TDX attestation evidence accepted by the configured release policy;
- wraps a base64-encoded 32-byte value and prints the wrapped value as base64;
- unwraps that value to the original base64-encoded 32 bytes; and
- is executable by the application account through the configured `sudo` rule.

Set these deployment constants in `code/boot.py`:

| Constant | Value |
| --- | --- |
| `SKR` | Absolute path to the compatible `AzureAttestSKR` executable |
| `ATTEST_URL` | Microsoft Azure Attestation endpoint |
| `KEK` | Full, versioned Key Vault key identifier |
| `STATE_DIR` | Protected persistent directory for `service_root.wrapped` |

Create `STATE_DIR` with permissions limited to the application account. Its wrapped root must be preserved with the encrypted data because it reconstructs the same application keys after a restart.

## 4. Install application dependencies

From the repository root on the VM:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## 5. Configure the application

Copy the environment template:

```bash
cp .env.example .env
```

Replace every `YOUR_*` value:

| Setting | Value |
| --- | --- |
| `G8_PG_HOST` | PostgreSQL hostname |
| `G8_PG_USER` | Database principal mapped to the VM identity |
| `G8_PG_DB` | Database containing the application schema |
| `G8_PG_CA` | CA bundle used to verify PostgreSQL |
| `G8_BLOB_ACCOUNT` | Blob account HTTPS URL |
| `G8_BLOB_CONTAINER` | Existing private container name |
| `G8_VAULT_URL` | Key Vault HTTPS URL |
| `G8_ANCHOR_SECRET` | State-anchor secret name |
| `G8_ANCHOR_ENFORCE` | `strict` |
| `G8_BOOTSTRAP_ANCHOR` | `0` except during the first initialization |
| `G8_DEMO` | `0` for normal operation; `1` enables the operator inspection endpoint |

The application reads process environment variables and does not load `.env` itself. Export the file in the launch shell:

```bash
set -a
. ./.env
set +a
```

Configure the TLS listener in `code/run.py`:

| Constant | Value |
| --- | --- |
| `CERT` | Absolute path to the certificate chain |
| `KEY` | Absolute path to the matching private key |
| `HOST` | Listener address; the default is all interfaces |
| `PORT` | Listener port; the default is `8443` |

Install the browser client at the path used by `app.py`:

```bash
install -m 0644 code/g8ui.html "$HOME/g8ui.html"
```

Keep `.env`, TLS private keys, `service_root.wrapped`, and deployment logs outside version control.

## 6. Initialize and start

For a new deployment with an empty database and Blob container, run once with anchor bootstrap enabled:

```bash
cd code
G8_BOOTSTRAP_ANCHOR=1 ../.venv/bin/python run.py
```

After the first successful initialization, stop the process and start normally:

```bash
../.venv/bin/python run.py
```

Use `run.py` so the listener enforces the application's TLS 1.3 configuration.

For an existing deployment, retain the matching `service_root.wrapped`, master-key version, database, Blob contents, and state anchor. Do not initialize a new root over existing encrypted data.

## 7. Verify the deployment

From a client that trusts the application certificate:

```bash
curl --fail --show-error \
  https://YOUR_APPLICATION_HOST:8443/healthz
```

For a private CA, add:

```bash
--cacert /absolute/path/to/YOUR_CA_BUNDLE.pem
```

The response should report the application as healthy and expose the separate anchor, audit-chain, and signing-registry checks.

Open `https://YOUR_APPLICATION_HOST:8443/ui` in a browser with WebCrypto and IndexedDB support. A complete functional check is:

1. Register an account with a password of at least 12 characters.
2. Register a recipient in another browser profile.
3. Upload a file.
4. Share it with the recipient and download it from the recipient account.
5. Revoke the share and confirm that the recipient can no longer retrieve the file.

Use ASCII usernames for signed operations. The browser stores its non-extractable signing key in IndexedDB for the application origin.

## Local validation

Install the development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

These checks do not require Azure resources:

```bash
PYTHONPATH=code python -m pytest \
  code/tests/test_crypto.py \
  -k 'not attested_keys_integration' \
  -q

PYTHONPATH=code python -m pytest \
  code/tests/test_request_integrity.py \
  -q

python code/verify_signed_entry.py --self-test
```

The remaining test, measurement, and reset scripts target a live deployment. Several of them modify database rows, replace the state anchor, restart the application, or delete stored data. Review their configured paths and run them only against controlled resources.

## Operational safeguards

- Preserve `service_root.wrapped` together with the matching Key Vault master-key version and encrypted data.
- Treat anchor initialization and `reanchor.py` as trust-establishing operations. Validate the database state before replacing the anchor.
- `demo_reset.sh` deletes the Blob contents and all six application tables before rebuilding the anchor.
- `reset_and_verify.sh` clears database state, restarts the application, and updates the anchor.
- Keep logs private because diagnostic output can contain infrastructure names, account identifiers, and integrity state.
