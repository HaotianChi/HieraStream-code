# Unversioned publication baseline

Measures stale successful commits under concurrent authorization updates.

Same crypto, segmentation, IPFS, and PeerMVCC/Fabric ledger as HieraStream.
The only intentional difference: `commit_segment_unversioned` does not
`GetState(AuthKey(ownerId))`, so the authorization key is not in the Fabric
MVCC read set. Observed snapshot fields are still recorded for staleness checks.

See `workflow.py` and `tests/baselines/test_unversioned.py`.
