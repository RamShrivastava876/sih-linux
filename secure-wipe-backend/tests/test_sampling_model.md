# Test Sampling Model (Manual Placeholder)

This placeholder documents intended automated tests (Future Enhancement #19):

Planned automated checks:
1. Deterministic sampling reproducibility given device size seed.
2. Entropy metrics: synthetic all-zero vs random file produce expected entropy ranges (<0.05 vs >0.95).
3. Probability bounds: hypergeometric p_miss monotonically decreases with added coverage.
4. Merkle root stability: modifying one sampled block changes root.
5. Resume snapshot presence: progress_*.json created after simulated updates.

To implement: create synthetic files in tmp, invoke internal verify logic, assert JSON fields.
