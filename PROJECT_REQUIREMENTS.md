# Đề Bài Đồ Án Môn An Toàn Thông Tin (Project Requirements)

- **Sinh viên thực hiện**: Trần Gia Thuận
- **Chữ số cuối của Mã số sinh viên (SID)**: **3**

---

## 1. Project Requirements

Each student is required to complete an individual course project involving the study and implementation of modern cryptographic techniques. The project shall consist of the following four components.

### 1.1. Symmetric-key Cryptography

Study and implement:

- **AES-128** (Advanced Encryption Standard).
- **Key length:** **128 bits**.
- The secret key shall be generated according to the following procedure:
  - Use the student's **full name** as the input string.
  - Compute its **SHA-256** hash value.
  - Use the **first 128 bits** of the hash output as the secret key for AES-128.

### 1.2. Asymmetric-key Cryptography

Each student shall study and implement **one** of the following algorithms. The assigned algorithm is determined by the **last digit of the Student ID (SID)** according to the following rule:

| Last digit of SID mod 3 | Algorithm |
| :---: | :--- |
| 0 | RSA |
| 1 | Diffie-Hellman (DH) |
| 2 | Elliptic Curve Cryptography (ECC) |

### 1.3. Cryptographic Hash Function

Study and implement:

- **SHA-256** (Secure Hash Algorithm 256-bit).

### 1.4. Digital Signature

Each student shall study and implement **one** of the following digital signature algorithms. The assigned algorithm is determined by the **last digit of the Student ID (SID)** according to the following rule:

| Last digit of SID mod 4 | Algorithm |
| :---: | :--- |
| 0 | ElGamal Digital Signature |
| 1 | Schnorr Digital Signature |
| 2 | Digital Signature Algorithm (DSA) |
| 3 | Elliptic Curve Digital Signature Algorithm (ECDSA) |

---

## 2. Project Objectives

For each assigned algorithm, the report shall include the following:

1. Present the historical background, development, and design motivation of the algorithm.
2. Explain the underlying mathematical foundations and operating principles.
3. Describe the complete operational procedure (encryption/decryption, key exchange, hashing, digital signing, or signature verification, as applicable).
4. Analyze the security assumptions, security properties, and known attacks against the algorithm.
5. Discuss the advantages, limitations, and practical applications of the algorithm in modern information systems.
6. Provide a complete worked example illustrating the algorithm step by step.
7. Implement the algorithm in **Python** from first principles. The use of existing cryptographic libraries or frameworks (e.g., `cryptography`, `PyCryptodome`, `PyNaCl`, or OpenSSL APIs) is **strictly prohibited**. Only Python's standard libraries may be used for general computation and data processing.
8. Evaluate the implementation through experimental results, analyze its correctness and computational performance, and provide concluding remarks.

---

## 3. Phân công thuật toán của sinh viên (SID cuối = 3)

| Thành phần | Quy tắc đề bài | Thuật toán được giao | Mã nguồn cài đặt | Báo cáo học thuật |
| :--- | :--- | :--- | :--- | :--- |
| **Symmetric-key Cryptography** | Chung cho mọi sinh viên (khóa = 128 bit đầu của `SHA-256("Trần Gia Thuận")`) | **AES-128** | [algorithms/aes128.py](./algorithms/aes128.py) | [docs/bao_cao_aes128.md](./docs/bao_cao_aes128.md) |
| **Asymmetric-key Cryptography** | $3 \bmod 3 = 0$ | **RSA** (kèm tăng tốc Garner CRT) | [algorithms/rsa.py](./algorithms/rsa.py) | [docs/bao_cao_rsa.md](./docs/bao_cao_rsa.md) |
| **Cryptographic Hash Function** | Chung cho mọi sinh viên | **SHA-256** | [algorithms/sha256.py](./algorithms/sha256.py) | [docs/bao_cao_sha256.md](./docs/bao_cao_sha256.md) |
| **Digital Signature** | $3 \bmod 4 = 3$ | **ECDSA** (`secp256k1`) | [algorithms/ecdsa.py](./algorithms/ecdsa.py) | [docs/bao_cao_ecdsa.md](./docs/bao_cao_ecdsa.md) |
