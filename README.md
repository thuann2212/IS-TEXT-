# ĐỒ ÁN MÔN AN TOÀN THÔNG TIN (INFORMATION SECURITY)

- **Sinh viên thực hiện**: Trần Gia Thuận
- **Chữ số cuối mã số sinh viên (SID)**: **3**
  - Phân công mật mã bất đối xứng: $3 \bmod 3 = 0 \rightarrow$ **RSA kèm tăng tốc giải mã CRT**
  - Phân công chữ ký số: $3 \bmod 4 = 3 \rightarrow$ **ECDSA trên đường cong Elliptic (`secp256k1`)**
- **Ngôn ngữ & Môi trường**: Python thuần 3.12 (cài đặt từ nguyên lý gốc — *From First Principles*, tuyệt đối không sử dụng thư viện mật mã có sẵn như `hashlib`, `hmac`, `cryptography`, `pycryptodome`, `ssl`, `rsa`, `ecdsa`).

---

## Tổng quan kiến trúc liên kết 4 thuật toán

| STT | Phân nhóm mật mã | Thuật toán & Chuẩn đối chiếu | Mã nguồn Python thuần | Báo cáo học thuật (8 mục) | Liên kết dữ liệu giữa các mô-đun |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | Hàm băm mật mã | **SHA-256** (NIST FIPS 180-4) | [sha256.py](./sha256.py) | [bao_cao_sha256.md](./bao_cao_sha256.md) | Băm họ tên `"Trần Gia Thuận"` (UTF-8) để dẫn xuất khóa cho AES-128 & băm thông điệp cho ECDSA |
| **2** | Mật mã khối đối xứng | **AES-128** (NIST FIPS 197, PKCS#7) | [aes128.py](./aes128.py) | [bao_cao_aes128.md](./bao_cao_aes128.md) | Nhập trực tiếp `bam_sha256_bytes` từ [sha256.py](./sha256.py) lấy 16B đầu làm khóa $K$ và 16B sau làm $IV$ |
| **3** | Mật mã khóa công khai | **RSA & Garner's CRT** (PKCS#1 v1.5) | [rsa.py](./rsa.py) | [bao_cao_rsa.md](./bao_cao_rsa.md) | Sinh khóa nguyên tố lớn Miller-Rabin 40 vòng, đệm ngẫu nhiên PKCS#1 v1.5, giải mã nhanh CRT |
| **4** | Chữ ký số khóa công khai | **ECDSA `secp256k1`** (FIPS 186-4 / SEC 1) | [ecdsa.py](./ecdsa.py) | [bao_cao_ecdsa.md](./bao_cao_ecdsa.md) | Nhập trực tiếp `bam_sha256_bytes` từ [sha256.py](./sha256.py) để băm văn bản trước khi ký và xác minh |

---

## Chi tiết từng học phần

### 1. Hàm băm mật mã: SHA-256 ([sha256.py](./sha256.py) & [bao_cao_sha256.md](./bao_cao_sha256.md))
- Tự sinh 8 hằng số khởi tạo $H^{(0)}$ và 64 hằng số vòng $K_0 \dots K_{63}$ từ căn bậc hai và căn bậc ba của 64 số nguyên tố đầu tiên bằng tìm kiếm nhị phân số nguyên lớn (tránh sai số dấu phẩy động).
- Cài đặt đầy đủ cấu trúc lặp Merkle-Damgård, nén Davies-Meyer 64 vòng và các toán tử ARX 32-bit ($Ch, Maj, \Sigma_0, \Sigma_1, \sigma_0, \sigma_1$).
- Khớp 100% các vector chuẩn NIST FIPS 180-4 (chuỗi rỗng, 1 khối `"abc"` và đa khối biên 448-bit).

### 2. Mật mã khối đối xứng: AES-128 ([aes128.py](./aes128.py) & [bao_cao_aes128.md](./bao_cao_aes128.md))
- Cài đặt số học trường hữu hạn Galois $GF(2^8)$ theo đa thức tối giản $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`), kiểm chứng đại số toàn bộ 256 phần tử `S-Box` và `InvS-Box` từ nghịch đảo $a^{254}$ và biến đổi Affine `0x63`.
- Cài đặt đầy đủ 4 phép biến đổi vòng thuận/nghịch (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`), mở rộng khóa 10 vòng (`KeyExpansion` sinh 44 từ 32-bit).
- Hỗ trợ các chế độ vận hành khối **CBC** và **ECB** kết hợp chuẩn đệm **PKCS#7** (RFC 5652) có kiểm tra gỡ đệm chống rò rỉ thời gian.

### 3. Mật mã bất đối xứng: RSA kèm CRT ([rsa.py](./rsa.py) & [bao_cao_rsa.md](./bao_cao_rsa.md))
- Cài đặt từ nguyên lý gốc: lũy thừa nhanh `pow_mod` (*Square-and-Multiply*), thuật toán Euclid mở rộng `extended_gcd`, nghịch đảo modulo `mod_inverse`, sàng số nguyên tố nhỏ kết hợp kiểm tra nguyên tố xác suất **Miller-Rabin 40 vòng** ($P_{\text{error}} \le 4^{-40} < 10^{-24}$).
- Hỗ trợ sinh cặp khóa an toàn 512-bit, 1024-bit, 2048-bit (kiểm tra biên chống phân tích Fermat và tấn công Wiener).
- Tích hợp chuẩn đệm ngẫu nhiên **PKCS#1 v1.5** (RFC 8017) và tăng tốc giải mã bằng **Định lý Thặng dư Trung Hoa — Công thức Garner (RSA-CRT)** nhanh gấp $\sim 3.3\times - 3.8\times$.

### 4. Chữ ký số đường cong Elliptic: ECDSA ([ecdsa.py](./ecdsa.py) & [bao_cao_ecdsa.md](./bao_cao_ecdsa.md))
- Cài đặt cấu trúc nhóm cộng Abel trên đường cong Elliptic dạng Weierstrass rút gọn $y^2 \equiv x^3 + ax + b \pmod p$: điểm vô cực $\mathcal{O}$, cộng hai điểm phân biệt (*Point Addition*), nhân đôi điểm (*Point Doubling*) và nhân vô hướng (*Double-and-Add*).
- Triển khai trên đường cong chuẩn công nghiệp **`secp256k1`** (Bitcoin/Ethereum) và đường cong kiểm thử tính tay **Toy Curve trên $\mathbb{F}_{17}$** ($n = 19$).
- Kiểm tra nghiêm ngặt khóa công khai theo chuẩn SEC 1 v2, hỗ trợ chuẩn hóa chữ ký Low-S (BIP-62), và mô phỏng thực nghiệm đòn tấn công thu hồi khóa riêng khi tái sử dụng Nonce $k$ (*Nonce Reuse Attack* — sự cố Sony PlayStation 3).

---

## Hướng dẫn thực thi và kiểm định

Chạy độc lập từng thuật toán (kèm kiểm thử vector chuẩn, đối chiếu tính tay và đo hiệu năng Benchmark):

```powershell
python -X utf8 sha256.py
python -X utf8 aes128.py
python -X utf8 rsa.py
python -X utf8 ecdsa.py
```
