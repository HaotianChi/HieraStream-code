# Droplet Python 3 compatibility patches

Applied to upstream `chunkdata.py` from droplet-engine
(`5c2dbac90aa3bde837ed4989ecd78235e5d9ef8e`),
file `talosblockchain/talosstorage/chunkdata.py`.
Working copy: `chunkdata_compat.py` (crypto path unchanged: zlib + AES-GCM + ECDSA-SHA256).

1. Drop `pylepton` import (unused for byte payloads).
2. Add `import os` (`os.urandom` used without import upstream).
3. Import `TimeKeeper` from local `timebench` instead of `talosstorage.timebench`.
4. `ChunkData.encode` concatenates `bytes` (Python 2 `str`).
5. Integer division in entry decoders (`//`).
6. `CloudChunk.decode` uses `str(exc)` instead of Python 2 `exc.message`.
7. `DataStreamIdentifier.get_key_for_blockid` encodes strings before SHA-256.
8. `MultiIntegerEntry.encode` treats metadata as bytes.
9. `MultiIntegerEntry.decode` returns `MultiIntegerEntry` and unpacked ints.
10. `MultiIntegerEntry.get_encoded_size` counts 4-byte `I` values to match encode.
