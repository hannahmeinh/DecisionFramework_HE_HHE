# Decision Framework for Hybrid Homomorphic Encryption (HHE) vs. Homomorphic Encryption (HE)

A performance evaluation framework comparing pure Homomorphic Encryption (HE) using TFHE against Hybrid Homomorphic Encryption (HHE) combining Kreyvium and TFHE on resource-constrained devices.

---

## Overview

This project evaluates the practical trade-offs between two encryption approaches for privacy-preserving computation in IoT environments:

- **HE (Homomorphic Encryption):** Data is encrypted directly on the client using TFHE, enabling computation on encrypted data without decryption.
- **HHE (Hybrid Homomorphic Encryption):** The client encrypts data using the lightweight symmetric cipher Kreyvium; the server then performs transciphering into homomorphic TFHE format.

---

## Configuration

Encryption parameters are stored in the `Parameters/` directory. The following options can be configured:

| Parameter       | Options                          | Description                              |
|-----------------|----------------------------------|------------------------------------------|
| `method`        | `HHE`, `HE`                      | Encryption approach                      |
| `integer_size`  | `8`, `16`, `32`, `64`, `128`     | Bit width of input integers              |
| `batch_size`    | Any positive integer             | Number of integers per batch             |
| `batch_number`  | Any positive integer             | Number of batches                        |

---

## Usage

Each component (Client, Server, TTP) must be started independently, typically across different machines or in separate terminals for local testing.

---

## Performance Measurement

Runtime and memory measurements are handled by scripts in `Performance_Measurement/`. Results are averaged by default.

Metrics captured:
- Pure encryption time per integer
- Total batch processing time including I/O
- RAM and SWAP usage over time

---

## Dependencies & Attribution

- **TU Graz Hybrid-HE Framework** (included as a Git submodule — provides Kreyvium and TFHE implementations)

This project builds on the **Hybrid-HE Framework** developed by TU Graz (Dobraunig et al., 2021), which provides native implementations of Kreyvium and TFHE and integrates HElib, Microsoft SEAL, and TFHE as submodules.

- Dobraunig et al. (2023). *PASTA: A Case for Hybrid Homomorphic Encryption.* IACR Transactions on Cryptographic Hardware and Embedded Systems.

---