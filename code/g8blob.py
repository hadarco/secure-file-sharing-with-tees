"""Store encrypted file chunks in Azure Blob Storage using managed identity.

Cryptography and associated-data construction belong to g8keys. This module
frames ciphertext as a 16-byte header followed by nonce, length, and ciphertext
records. The G8BLOB01 marker is a persistent format identifier.
"""

import os
import struct

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import ManagedIdentityCredential
from azure.storage.blob import BlobBlock, BlobServiceClient

import g8keys

# Override deployment placeholders through the documented environment settings.
ACCOUNT_URL = os.environ.get("G8_BLOB_ACCOUNT", "YOUR_STORAGE_ACCOUNT_URL")
CONTAINER = os.environ.get("G8_BLOB_CONTAINER", "YOUR_BLOB_CONTAINER")

MAGIC = b"G8BLOB01"
# A GCM ciphertext is at least the tag: a zero-byte plaintext seals to exactly 16 bytes,
# which is what an empty file's single chunk looks like (g8keys.chunk_count).
TAG_LEN_MIN = g8keys.TAG_LEN
HEADER_LEN = 16
NONCE_LEN = g8keys.NONCE_LEN  # 12
LEN_PREFIX = 4

_service = None


class BlobFormatError(Exception):
    """A stored container or upload sequence violates the expected format."""


# --------------------------------------------------------------------------------------
# Connection
# --------------------------------------------------------------------------------------


def _client() -> BlobServiceClient:
    """One BlobServiceClient per process.

    ManagedIdentityCredential caches its token internally and refreshes near expiry, so
    holding the client is safe. Fetching a token once at startup and keeping it would not
    be: these tokens last about an hour, which is long enough to pass every test and fail
    during a demonstration.
    """
    global _service
    if _service is None:
        _service = BlobServiceClient(
            ACCOUNT_URL, credential=ManagedIdentityCredential()
        )
    return _service


def _blob(file_id: str):
    """The blob for a file. Named by file_id ONLY — see D11 decision 3."""
    return _client().get_blob_client(CONTAINER, str(file_id))


def blob_path(file_id: str) -> str:
    """Derive the recorded container/file path from the file identifier.

    Blob access uses this deterministic naming rule rather than trusting
    a location supplied by the metadata database.
    """
    return "%s/%s" % (CONTAINER, file_id)


def verify_blob_path(file_id: str, stored: str) -> bool:
    """Does the recorded blob_path match the one this service would have written?"""
    return str(stored) == blob_path(file_id)


def healthcheck() -> dict:
    """Confirm the container is reachable as the managed identity."""
    props = _client().get_container_client(CONTAINER).get_container_properties()
    return {"container": CONTAINER, "account": ACCOUNT_URL, "exists": bool(props)}


# --------------------------------------------------------------------------------------
# Upload
# --------------------------------------------------------------------------------------


def _block_id(index: int) -> str:
    """Azure block IDs must be equal-length base64 strings within one blob."""
    import base64

    return base64.b64encode(b"g8blk%09d" % index).decode("ascii")


class Uploader:
    """Stage an encrypted file as Azure blocks and commit its container.

    The caller supplies the expected chunk count before encryption. Each staged
    chunk is encrypted immediately; commit publishes the assembled block list.
    Call abandon() after a failed upload rather than retaining partial metadata.
    """

    def __init__(self, file_id: str, version: int, total_chunks: int, file_dek: bytes):
        """Stage the container header for an encrypted upload.

        Args:
            file_id: Identifier used for both blob naming and authenticated context.
            version: File version authenticated by every chunk.
            total_chunks: Expected count, fixed before encrypting any chunk.
            file_dek: Raw 32-byte file encryption key retained during upload.
        """
        self.file_id = str(file_id)
        self.version = int(version)
        self.total_chunks = int(total_chunks)
        self.dek = file_dek
        self.chunk_size = g8keys.CHUNK_SIZE

        self._bc = _blob(file_id)
        self._blocks = [_block_id(0)]
        self._index = 0
        self.plaintext_bytes = 0
        self.blob_bytes = HEADER_LEN
        self._committed = False

        header = MAGIC + struct.pack(">II", self.total_chunks, self.chunk_size)
        self._bc.stage_block(self._blocks[0], header)

    def stage(self, part: bytes) -> int:
        """Encrypt and stage one chunk with its position authenticated.

        Args:
            part: Plaintext bytes, at most CHUNK_SIZE bytes.

        Returns:
            Bytes staged, including nonce, length prefix, and authentication tag.

        Raises:
            BlobFormatError: The upload is committed, the declared chunk
                count is exceeded, or the chunk is too large.
        """
        if self._committed:
            raise BlobFormatError("upload already committed")
        if self._index >= self.total_chunks:
            raise BlobFormatError(
                "more chunks supplied than the declared %d; the AAD binding of every "
                "chunk would be wrong" % self.total_chunks
            )
        if len(part) > self.chunk_size:
            raise BlobFormatError("chunk %d exceeds the chunk size" % self._index)

        nonce, ct = g8keys.encrypt_chunk(
            part, self.file_id, self.version, self._index, self.total_chunks, self.dek
        )
        record = nonce + struct.pack(">I", len(ct)) + ct

        bid = _block_id(self._index + 1)
        self._bc.stage_block(bid, record)
        self._blocks.append(bid)

        self._index += 1
        self.plaintext_bytes += len(part)
        self.blob_bytes += len(record)
        return len(record)

    @property
    def staged(self) -> int:
        """Number of chunks staged, excluding the container header."""
        return self._index

    def commit(self) -> dict:
        """Publish the block list after checking the declared chunk count.

        Returns:
            File identity, blob path, chunk count, and byte counts.

        Raises:
            BlobFormatError: The staged chunk count differs from the declaration.
        """
        if self._index != self.total_chunks:
            raise BlobFormatError(
                "declared %d chunks but received %d; upload abandoned"
                % (self.total_chunks, self._index)
            )
        self._bc.commit_block_list([BlobBlock(block_id=b) for b in self._blocks])
        self._committed = True
        return {
            "file_id": self.file_id,
            "blob_path": blob_path(self.file_id),
            "total_chunks": self.total_chunks,
            "plaintext_bytes": self.plaintext_bytes,
            "blob_bytes": self.blob_bytes,
        }

    def abandon(self) -> None:
        """Discard the local block list without committing a blob.

        This does not delete remote staged blocks; their cleanup is left to
        the storage service.
        """
        self._blocks = []


def upload(
    file_id: str, version: int, plaintext_chunks, total_chunks: int, file_dek: bytes
) -> dict:
    """Encrypt an iterable of plaintext chunks and commit the resulting blob.

    Args:
        file_id: Identifier for the blob and authenticated chunk context.
        version: File version authenticated by each chunk.
        plaintext_chunks: Iterable of plaintext bytes objects.
        total_chunks: Expected number of chunks, including one for an empty file.
        file_dek: Raw 32-byte file encryption key.

    Returns:
        File identity, blob path, chunk count, and byte counts.

    Raises:
        BlobFormatError: Supplied chunks violate the size or count declaration.
    """
    up = Uploader(file_id, version, total_chunks, file_dek)
    for part in plaintext_chunks:
        up.stage(part)
    return up.commit()


# --------------------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------------------

# The largest a single chunk record's ciphertext can legitimately be: one full plaintext
# chunk plus the GCM tag. Anything larger did not come from this service.
MAX_CT_LEN = g8keys.CHUNK_SIZE + g8keys.TAG_LEN


def _read_exact(reader, n: int) -> bytes:
    """Read exactly n bytes, or raise. A short read here means the blob was truncated.

    Pieces are collected into a list and joined once. The previous `out += piece` rebuilt
    the whole buffer on every iteration, which is quadratic in the number of pieces -- and
    the number of pieces is chosen by whoever wrote the blob, which per the threat model
    is the storage operator.
    """
    if n < 0:
        raise BlobFormatError("negative read length %d" % n)
    parts, got = [], 0
    while got < n:
        piece = reader.read(n - got)
        if not piece:
            raise BlobFormatError(
                "blob ended early: wanted %d more bytes. The stored object is truncated."
                % (n - got)
            )
        parts.append(piece)
        got += len(piece)
    return b"".join(parts)


def download(file_id: str, version: int, file_dek: bytes, expected_chunks: int = None):
    """Authenticate stored records and yield plaintext chunks in order.

    Each chunk authenticates its file, version, position, and total count.
    A later record can fail after earlier authenticated chunks were yielded.

    Args:
        file_id: File identifier used for location and authentication.
        version: Expected file version.
        file_dek: Raw 32-byte file decryption key.
        expected_chunks: Optional metadata count to compare with the header.

    Yields:
        Authenticated plaintext bytes for each chunk.

    Raises:
        BlobFormatError: A header, record length, or expected count is invalid.
        g8keys.KeyBindingError: A chunk's tag or authenticated context fails.
        ResourceNotFoundError: The requested blob does not exist.
    """
    reader = _blob(file_id).download_blob()

    header = _read_exact(reader, HEADER_LEN)
    if header[:8] != MAGIC:
        raise BlobFormatError("not a G8BLOB container (bad magic)")

    total_chunks, chunk_size = struct.unpack(">II", header[8:16])

    if chunk_size != g8keys.CHUNK_SIZE:
        raise BlobFormatError(
            "blob was written with chunk size %d, this build uses %d"
            % (chunk_size, g8keys.CHUNK_SIZE)
        )
    if expected_chunks is not None and total_chunks != expected_chunks:
        raise BlobFormatError(
            "blob header declares %d chunks, the metadata database says %d"
            % (total_chunks, expected_chunks)
        )

    for index in range(total_chunks):
        nonce = _read_exact(reader, NONCE_LEN)
        (ct_len,) = struct.unpack(">I", _read_exact(reader, LEN_PREFIX))

        # bound this BEFORE reading, not after.
        #
        # ct_len is a 32-bit field read straight out of a store the threat model names as
        # hostile (AS4). It went directly into _read_exact, so a blob rewritten with
        # ct_len = 0xFFFFFFFF made the VM try to accumulate 4 GiB in memory: a crash the
        # storage operator could trigger at will, and a direct contradiction of the
        # "peak memory is one chunk regardless of file size" claim that justifies choosing
        # a confidential VM over an SGX enclave.
        #
        # The AEAD tag would have rejected the chunk eventually. Eventually is too late:
        # the allocation happens first. A length field is not authenticated by the thing
        # it describes, so it has to be checked against what this service could possibly
        # have written.
        if not TAG_LEN_MIN <= ct_len <= MAX_CT_LEN:
            raise BlobFormatError(
                "chunk %d declares %d ciphertext bytes; a legitimate chunk is between "
                "%d and %d. The stored object was not written by this service."
                % (index, ct_len, TAG_LEN_MIN, MAX_CT_LEN)
            )

        ct = _read_exact(reader, ct_len)
        yield g8keys.decrypt_chunk(
            nonce, ct, file_id, version, index, total_chunks, file_dek
        )


def delete(file_id: str) -> bool:
    """Delete a stored blob if present.

    Returns:
        True after deletion, or False if already absent. Other storage
        errors propagate to the caller.
    """
    # catch the typed exception rather than searching the message text. `"404" in
    # str(exc)` would also match an unrelated error that merely happened to contain those
    # characters -- a request id, a timestamp, a byte count -- and would then quietly
    # report a blob as already deleted when it was not.
    try:
        _blob(file_id).delete_blob()
        return True
    except ResourceNotFoundError:
        return False


def read_raw(file_id: str, n: int = 256) -> bytes:
    """Return up to n stored bytes without decrypting the container.

    Used by diagnostics to inspect the framing and encrypted records.
    """
    return _blob(file_id).download_blob(offset=0, length=n).readall()


# --------------------------------------------------------------------------------------
# Self-test — round trip, then the arrangement attacks
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import hashlib
    import os
    import uuid

    print("=" * 78)
    print("g8blob self-test - encrypted chunk store on Azure Blob (D11)")
    print("=" * 78)

    # A small chunk size so a multi-chunk file does not mean uploading megabytes. The
    # constant is read at call time precisely so tests can do this.
    g8keys.CHUNK_SIZE = 1024
    print(
        "[setup] chunk size temporarily set to %d bytes for testing" % g8keys.CHUNK_SIZE
    )

    print("\n[0] container reachable as the managed identity?")
    print("   ", healthcheck())

    fid = str(uuid.uuid4())
    ver = 1
    dek = g8keys.new_file_dek()

    plaintext = os.urandom(3500)  # 4 chunks: 1024 x3 + 428
    total = g8keys.chunk_count(len(plaintext))
    parts = [
        plaintext[i : i + g8keys.CHUNK_SIZE]
        for i in range(0, len(plaintext), g8keys.CHUNK_SIZE)
    ]
    print(
        "\n[1] uploading %d bytes as %d chunks, file_id %s"
        % (len(plaintext), total, fid[:8] + "...")
    )
    info = upload(fid, ver, iter(parts), total, dek)
    print("   ", info)

    print("\n[2] what the storage operator sees (first 64 raw bytes):")
    raw = read_raw(fid, 64)
    print("    magic  :", raw[:8])
    print("    then   :", raw[16:48].hex(), "...")
    print("    ^ 16-byte format header, then ciphertext. No filename, no plaintext.")

    print("\n[3] download and verify byte-exact round trip")
    got = b"".join(download(fid, ver, dek, expected_chunks=total))
    ok = got == plaintext
    print(
        "    [%s] %d bytes back, sha256 %s"
        % ("PASS" if ok else "FAIL", len(got), hashlib.sha256(got).hexdigest()[:16])
    )

    print("\n[4] adversarial: the metadata database lies about the chunk count")
    try:
        b"".join(download(fid, ver, dek, expected_chunks=total + 1))
        print("    [FAIL] accepted a mismatched chunk count")
    except BlobFormatError as exc:
        print("    [PASS] rejected:", str(exc)[:70])

    print("\n[5] adversarial: download with the wrong File_DEK")
    try:
        b"".join(download(fid, ver, g8keys.new_file_dek(), expected_chunks=total))
        print("    [FAIL] decrypted with the wrong key")
    except g8keys.KeyBindingError:
        print("    [PASS] rejected - AEAD tag check failed")

    print("\n[6] adversarial: a chunk spliced in from a different file")
    n_, c_ = g8keys.encrypt_chunk(b"x", fid, ver, 0, total, dek)
    try:
        g8keys.decrypt_chunk(n_, c_, str(uuid.uuid4()), ver, 0, total, dek)
        print("    [FAIL] cross-file splice accepted")
    except g8keys.KeyBindingError:
        print("    [PASS] rejected - the chunk is bound to its own file_id")

    print("\n[7] cleanup")
    print("    deleted:", delete(fid))

    g8keys.CHUNK_SIZE = 4 * 1024 * 1024
    print("\nSELF-TEST COMPLETE")
