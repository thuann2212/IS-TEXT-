# TẬP HỢP ĐỒ ÁN AN TOÀN THÔNG TIN (INFORMATION SECURITY)

Sinh viên: **Trần Gia Thuận**  
Chữ số cuối SID: **3**

---

## 1. Mật mã bất đối xứng: RSA (Rivest - Shamir - Adleman)
- **Mã nguồn Python thuần**: [rsa.py](file:///d:/HOCTAP/IS(Text)/rsa.py)
  - Cài đặt từ nguyên lý gốc: Miller-Rabin 40 vòng, Euclid mở rộng tìm nghịch đảo, lũy thừa nhanh Square-and-Multiply.
  - Hỗ trợ sinh khóa 512-bit, 1024-bit, 2048-bit.
  - Tích hợp chuẩn đệm **PKCS#1 v1.5** và tăng tốc giải mã **RSA-CRT** (Garner's Formula, nhanh gấp ~3.5x).
  - Hỗ trợ mã hóa và giải mã văn bản tiếng Việt Unicode UTF-8 đa khối toàn vẹn 100%.
- **Báo cáo học thuật 8 mục**: [bao_cao_rsa.md](file:///d:/HOCTAP/IS(Text)/bao_cao_rsa.md)

---

## 2. Mật mã khối đối xứng: AES-128 (Advanced Encryption Standard)
- **Mã nguồn Python thuần**: [aes128.py](file:///d:/HOCTAP/IS(Text)/aes128.py)
  - Cài đặt cấu trúc SPN, trường hữu hạn $GF(2^8)$, bảng tra S-Box, InvS-Box, MixColumns, InvMixColumns, KeyExpansion.
  - Hỗ trợ các chế độ khối: ECB, CBC (PKCS#7 padding), CTR (Counter mode).
- **Báo cáo học thuật 8 mục**: [bao_cao_aes128.md](file:///d:/HOCTAP/IS(Text)/bao_cao_aes128.md)

---

## 3. Hàm băm mật mã: SHA-256 (Secure Hash Algorithm)
- **Mã nguồn Python thuần**: [sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py)
  - Cài đặt cấu trúc Merkle-Damgård, 64 hằng số $K$, các hàm logic $Ch, Maj, \Sigma_0, \Sigma_1, \sigma_0, \sigma_1$.
  - Tính toán mã băm thông điệp, xác thực tính toàn vẹn và ứng dụng trong chữ ký số / HMAC.
- **Báo cáo học thuật 8 mục**: [bao_cao_sha256.md](file:///d:/HOCTAP/IS(Text)/bao_cao_sha256.md)
