# TimeCrypt TimeUtil chunk-id fix

File: `timecrypt-client/src/main/java/ch/ethz/dsg/timecrypt/client/streamHandling/TimeUtil.java`
Upstream commit: `f97d72adb9e22017cb2992c1b233ab9aa0562b8e`

`getChunkIdAtTime` used `(float) timeOffset / chunkSize`. Float32 cannot
represent large offsets, so chunk 8951 (60_000 ms chunks) is reported as
8950. `Chunk.addDataPoint` then throws `WrongChunkException`.

Replaced with integer division `timeOffset / chunkSize`, which is the
floor division the method is documented to perform. No change to AES-GCM
or HEAC.
