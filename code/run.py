"""Start the API with a TLS 1.3-only listener.

Configure CERT and KEY before launch. Uvicorn constructs its SSL context in
Config.load(); both protocol bounds are set after that call and before serving.
The certificate authenticates a hostname, not an independently attested workload.
"""

import ssl
import subprocess
import sys

import uvicorn

HOST = "0.0.0.0"
PORT = 8443
CERT = "/home/YOUR_VM_USER/g8tls/cert.pem"
KEY = "/home/YOUR_VM_USER/g8tls/key.pem"


def main() -> int:
    """Build the TLS context, enforce TLS 1.3, and serve the API.

    Returns:
        Zero after normal shutdown, or one if no SSL context was constructed.
    """
    config = uvicorn.Config(
        "app:app",
        host=HOST,
        port=PORT,
        ssl_keyfile=KEY,
        ssl_certfile=CERT,
        log_level="info",
    )

    # load() is what constructs config.ssl. It must run before the context can be
    # tightened, and Server.serve() will not repeat it because config.loaded is then True.
    config.load()

    ctx = config.ssl
    if ctx is None:
        print("[tls] FATAL: uvicorn did not build an SSL context; check the cert paths")
        return 1

    # Both bounds are pinned. Setting only the minimum would leave the maximum at the
    # library default -- harmless today, but it would silently admit a future protocol
    # version this code has never been tested against.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Redundant given the bounds above, but explicit refusal documents the intent and
    # survives someone later relaxing the minimum without thinking it through.
    ctx.options |= (
        ssl.OP_NO_SSLv2
        | ssl.OP_NO_SSLv3
        | ssl.OP_NO_TLSv1
        | ssl.OP_NO_TLSv1_1
        | ssl.OP_NO_TLSv1_2
    )
    ctx.options |= ssl.OP_NO_COMPRESSION  # CRIME

    print("[tls] minimum version : %s" % ctx.minimum_version.name)
    print("[tls] maximum version : %s" % ctx.maximum_version.name)
    print("[tls] TLS 1.2 and below are refused at the handshake")

    # Read certificate details from the configured file so diagnostics follow renewal.
    print("[tls] certificate     : %s" % CERT)
    try:
        subj = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                CERT,
                "-noout",
                "-subject",
                "-issuer",
                "-enddate",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in subj.stdout.strip().splitlines():
            print("[tls]   %s" % line.strip())
    except Exception as exc:  # noqa: BLE001
        print("[tls]   (could not read certificate details: %s)" % type(exc).__name__)
    print("[tls] private key     : %s" % KEY)
    print(
        "[tls]   ^ this key is the one long-lived secret on this VM's disk. It is not"
    )
    print("[tls]     released by attestation and not wrapped; file permissions are the")
    print("[tls]     only control. See finding H15.")
    print(
        "[tls] note: this constrains HOW the channel is negotiated, not WHO is at the"
    )
    print("[tls]       far end. Client-side attestation remains future work.")
    sys.stdout.flush()

    uvicorn.Server(config).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
