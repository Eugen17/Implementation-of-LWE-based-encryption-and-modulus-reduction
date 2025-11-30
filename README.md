# Implementation-of-LWE-based-encryption-and-modulus-reduction

# LWE-based Somewhat Homomorphic Encryption (BV11-style)

This project implements an educational version of a **somewhat homomorphic encryption (SHE)** scheme based on the **Learning With Errors (LWE)** problem, following the second-generation BV11-style construction with **relinearization** and **modulus switching**. It is written in **SageMath (Python syntax)** and is intended for experimentation and learning, **not for production use**. :contentReference[oaicite:0]{index=0}  

The code demonstrates:

- Key generation, encryption, and decryption for an LWE-based encryption scheme.
- Homomorphic multiplication of ciphertexts followed by **relinearization** to keep ciphertext dimension small.
- **Modulus switching** to reduce the ciphertext modulus and noise.
- Basic tests showing correctness of decryption, homomorphic multiplication, and modulus switching. :contentReference[oaicite:1]{index=1}  

## Files

- `LWE_Perehuda_modulus_switching.py` – main SageMath/Python implementation (can also be used as a `.sage` file).
- `Report_LWE_Perehuda_and_modulos_switching_.pdf` – short report explaining the scheme, the math behind it, and how the code corresponds to the theory. :contentReference[oaicite:2]{index=2}  

## Implemented Components

All functionality lives in `LWE_Perehuda_modulus_switching.py`: :contentReference[oaicite:3]{index=3}  

- `safe_prime(nbits=16)`  
  Generates an `nbits`-bit **safe prime** `q` used as the modulus.

- `KeyGen(n, q, s=None)`  
  Key generation for the basic LWE scheme.  
  - If `s` is `None`, generates a secret key `s ∈ {0,1}^n` with `s₁ = 1`.  
  - Constructs a public-key matrix `A ∈ F_q^{n×n}` such that `A * s = e (mod q)` for a small noise vector `e`.  
  - Returns `(A, s)`.

- `encrypt(message, A)`  
  Encrypts a bit `message ∈ {0,1}` using the public matrix `A`.  
  Uses a random binary vector `u` and outputs a ciphertext vector `c`.

- `decrypt(c, s, q)`  
  Decrypts ciphertext `c` with secret key `s` and modulus `q` by computing an inner product and reducing modulo `q` and then modulo `2`.

- `bit_decomp(u, q, nq)` / `power_of_2(v, q, nq)` / `mul_vector(arr1, arr2)`  
  Helper functions for bit decomposition, power-of-two expansion, and vector “outer-product flattening” used in relinearization.

- `generate_t(s, s_xx, n, q)`  
  Generates a matrix of ciphertexts encrypting the quadratic terms of the secret key, needed for relinearization.

- `relinearization_of_multiplication(c1, c2, s, n, q)`  
  Computes the homomorphic product of ciphertexts `c1` and `c2`, and then **relinearizes** the result back to a vector of length `n`.

- `modulus_switching(c, q, sk)`  
  Performs modulus switching from modulus `q` to a smaller prime `p`.  
  - Produces a ciphertext `c'` over `F_p` such that `c' ≡ c (mod 2)` and the noise is reduced (subject to a simple bound check).

- `test()`  
  Runs a small experiment using toy parameters (`n = 5`, 16-bit safe prime `q`):  
  - tests correct encryption/decryption,  
  - tests homomorphic multiplication with relinearization,  
  - tests modulus switching on ciphertexts and on a relinearized product.

At the end of the file, `test()` is called so that running the script directly prints the test results. :contentReference[oaicite:4]{index=4}  

## Requirements

- [SageMath](https://www.sagemath.org/) (version supporting `GF`, `Matrix`, `vector`, `ZZ`, etc.).  
- Python 3 is not enough on its own; the code is intended to run under SageMath’s Python environment.

## How to Run

1. Install SageMath.
2. Place `LWE_Perehuda_modulus_switching.py` and the report in a directory.
3. From that directory, run:

   ```bash
   sage LWE_Perehuda_modulus_switching.py
