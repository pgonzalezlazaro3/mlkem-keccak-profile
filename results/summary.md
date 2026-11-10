## Headline, ML-KEM-768, one full key exchange (keygen + encaps + decaps)

- Portable build: 36.6 us, of which Keccak 55%.
- Optimised build: 26.0 us (speed-up 1.41x), of which Keccak 77%.
- Upper bound on the gain from a Keccak accelerator in the optimised build: 4.37x.

| Algorithm | Operation | Portable: us/op | Portable: Keccak share | Optimised: us/op | Optimised: Keccak share | Optimised: Amdahl bound | Timer overhead (opt.) |
|---|---|---|---|---|---|---|---|
| ML-KEM-512 | keygen | 7.7 | 52% | 5.7 | 79% | 4.83x | -1% |
| ML-KEM-512 | encaps | 7.6 | 58% | 5.3 | 74% | 3.87x | 3% |
| ML-KEM-512 | decaps | 8.8 | 60% | 6.3 | 76% | 4.09x | 2% |
| ML-KEM-768 | keygen | 12.8 | 50% | 7.9 | 80% | 5.03x | 3% |
| ML-KEM-768 | encaps | 11.1 | 56% | 8.3 | 75% | 4.03x | 3% |
| ML-KEM-768 | decaps | 12.7 | 59% | 9.7 | 76% | 4.21x | 3% |
| ML-KEM-1024 | keygen | 19.6 | 49% | 11.8 | 81% | 5.16x | 2% |
| ML-KEM-1024 | encaps | 16.3 | 58% | 12.9 | 77% | 4.38x | 3% |
| ML-KEM-1024 | decaps | 18.8 | 60% | 15.0 | 77% | 4.30x | 3% |
