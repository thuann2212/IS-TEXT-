# BÁO CÁO ĐỒ ÁN AN TOÀN THÔNG TIN: HÀM BĂM MẬT MÃ SHA-256

- **Họ và tên sinh viên**: Trần Gia Thuận
- **Chữ số cuối SID**: 3
- **Mã nguồn thực nghiệm**: [sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py)

---

## Mục 1. Bối cảnh lịch sử, quá trình phát triển và động lực thiết kế

Vào đầu thập niên 1990, nhu cầu xác thực tính toàn vẹn dữ liệu và chữ ký số thúc đẩy Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST) phối hợp với Cơ quan An ninh Quốc gia Hoa Kỳ (NSA) xây dựng chuẩn hàm băm an toàn (Secure Hash Standard - SHS). Năm 1993, phiên bản đầu tiên là SHA-0 được công bố trong tài liệu FIPS PUB 180, nhưng nhanh chóng được thay thế bởi SHA-1 vào năm 1995 (FIPS PUB 180-1) sau khi phát hiện một điểm yếu trong lịch trình mở rộng thông điệp (thiếu phép xoay bit trong bước sinh từ khóa).

Đến cuối thập niên 1990 và đầu những năm 2000, sự gia tăng năng lực tính toán cùng với các kết quả phân tích mật mã trên họ MD4, MD5 và SHA-1 cho thấy kích thước đầu ra 128-bit (của MD5) và 160-bit (của SHA-1) không còn đủ biên độ an toàn lâu dài trước các tấn công tìm kiếm xung đột dựa trên nghịch lý ngày sinh (Birthday Attack). Đồng thời, khi chuẩn mã hóa khối AES (Advanced Encryption Standard) được phê duyệt vào năm 2001 với các kích thước khóa 128, 192 và 256 bit, hệ sinh thái mật mã cần một họ hàm băm có mức độ an toàn tương xứng (tức đạt độ phức tạp $2^{128}$, $2^{192}$ và $2^{256}$).

Từ động lực đó, năm 2001 NIST phát hành dự thảo và năm 2002 chính thức ban hành tiêu chuẩn **FIPS PUB 180-2**, giới thiệu họ hàm băm **SHA-2** gồm SHA-256, SHA-384 và SHA-512 (sau này bổ sung thêm SHA-224 và các biến thể cắt cụt trong FIPS 180-4). Trong đó, **SHA-256** được thiết kế tối ưu cho kiến trúc vi xử lý 32-bit, tạo ra bản tóm lược thông điệp (message digest) dài 256 bit, cung cấp mức an toàn kháng xung đột $2^{128}$ phép toán — khớp hoàn toàn với mức bảo mật của AES-128.

---

## Mục 2. Cơ sở toán học nền tảng và nguyên lý hoạt động

### 2.1. Cấu trúc lặp Merkle-Damgård (Merkle-Damgård Construction)
SHA-256 được xây dựng dựa trên cấu trúc lặp **Merkle-Damgård** kết hợp với kỹ thuật đệm tăng cường độ dài (Merkle-Damgård Strengthening). Một thông điệp đầu vào $M$ có độ dài bất kỳ $l < 2^{64}$ bit trước hết được đệm thêm các bit để tổng độ dài là bội số của 512 bit, sau đó chia thành $N$ khối 512-bit: $M^{(1)}, M^{(2)}, \dots, M^{(N)}$.

Quá trình băm khởi đầu từ một vector khởi tạo cố định 256-bit $H^{(0)}$ và áp dụng tuần tự hàm nén một chiều $f$:

$$H^{(i)} = f\left(H^{(i-1)}, M^{(i)}\right) \quad \text{với } i = 1, 2, \dots, N$$

Định lý Merkle-Damgård chứng minh rằng: nếu hàm nén cơ sở $f: \{0,1\}^{256} \times \{0,1\}^{512} \to \{0,1\}^{256}$ là kháng xung đột (collision-resistant) thì toàn bộ hàm băm lặp trên thông điệp độ dài tùy ý cũng kháng xung đột.

### 2.2. Hàm nén Davies-Meyer và kiến trúc ARX
Bên trong mỗi khối $M^{(i)}$, hàm nén $f$ của SHA-256 tuân theo mô hình **Davies-Meyer**: khối thông điệp $M^{(i)}$ đóng vai trò như "khóa" điều khiển một phép biến đổi 64 vòng trên trạng thái 256-bit $H^{(i-1)}$, sau đó kết quả đầu ra được cộng dồn (feed-forward) với chính trạng thái đầu vào $H^{(i-1)}$ theo phép cộng modulo $2^{32}$ trên từng từ 32-bit:

$$H_j^{(i)} = \left(H_j^{(i-1)} + \text{State}_j^{(64)}\right) \bmod 2^{32}, \quad j \in \{0, \dots, 7\}$$

Nhánh cộng dồn này ngăn chặn việc đảo ngược hàm nén ngay cả khi kẻ tấn công biết rõ toàn bộ khối thông điệp $M^{(i)}$.

Về mặt đại số, SHA-256 thuộc họ thiết kế **ARX** (*Addition – Rotation – XOR*) kết hợp hai hàm logic phi tuyến theo bit ($Ch$ và $Maj$) trên không gian các từ 32-bit $\mathbb{Z}_{2^{32}}$:
- **Phép cộng số học modulo $2^{32}$ ($\boxplus$)**: Tạo sự lan truyền bit nhớ (carry propagation) phi tuyến đối với phép XOR.
- **Phép xoay phải ($ROTR^n$) và dịch phải ($SHR^n$)**: Phá vỡ tính đối xứng vị trí bit và khuếch tán thông tin xuyên suốt 32 vị trí bit của mỗi từ.
- **Hàm phi tuyến bậc hai trên $GF(2)$**:
  - Hàm chọn lựa: $Ch(x, y, z) = (x \land y) \oplus (\neg x \land z)$
  - Hàm đa số: $Maj(x, y, z) = (x \land y) \oplus (x \land z) \oplus (y \land z)$
- **Các hàm khuếch tán tuyến tính**:
  - $\Sigma_0(x) = ROTR^2(x) \oplus ROTR^{13}(x) \oplus ROTR^{22}(x)$
  - $\Sigma_1(x) = ROTR^6(x) \oplus ROTR^{11}(x) \oplus ROTR^{25}(x)$
  - $\sigma_0(x) = ROTR^7(x) \oplus ROTR^{18}(x) \oplus SHR^3(x)$
  - $\sigma_1(x) = ROTR^{17}(x) \oplus ROTR^{19}(x) \oplus SHR^{10}(x)$

Sự đan xen liên tục giữa phép cộng trong $\mathbb{Z}_{2^{32}}$ và các phép toán trên trường nhị phân $GF(2)^{32}$ khiến hệ phương trình đại số mô tả 64 vòng nén không thể tuyến tính hóa.

---

## Mục 3. Quy trình vận hành chi tiết từng bước

Quy trình thực thi SHA-256 gồm 4 giai đoạn nối tiếp:

### Bước 1: Đệm bit thông điệp (Message Padding) và chia khối
Giả sử thông điệp gốc $M$ có độ dài $l$ bit:
1. Nối thêm một bit `1` vào cuối thông điệp (trong biểu diễn theo byte là gắn thêm byte `0x80`).
2. Nối thêm $k$ bit `0` ($k \ge 0$ nhỏ nhất) sao cho:
   $$l + 1 + k \equiv 448 \pmod{512}$$
3. Nối thêm một khối 64-bit biểu diễn số nguyên không dấu $l$ theo thứ tự **Big-Endian**.
4. Thông điệp sau khi đệm có độ dài đúng bằng $512 \times N$ bit, được cắt thành $N$ khối $M^{(1)}, \dots, M^{(N)}$, mỗi khối 512 bit (64 byte).

### Bước 2: Khởi tạo giá trị băm ban đầu $H^{(0)}$ và hằng số vòng $K$
- **8 thanh ghi trạng thái ban đầu $H_0^{(0)} \dots H_7^{(0)}$**: Lấy 32 bit đầu tiên của phần thập phân của căn bậc hai của 8 số nguyên tố đầu tiên ($2, 3, 5, 7, 11, 13, 17, 19$):
  $$\lfloor \text{frac}(\sqrt{p_i}) \times 2^{32} \rfloor$$
- **64 hằng số vòng $K_0 \dots K_{63}$**: Lấy 32 bit đầu tiên của phần thập phân của căn bậc ba của 64 số nguyên tố đầu tiên ($2, 3, 5, \dots, 311$):
  $$\lfloor \text{frac}(\sqrt[3]{p_t}) \times 2^{32} \rfloor$$

### Bước 3: Mở rộng lịch trình thông điệp (Message Schedule $W_0 \dots W_{63}$)
Với mỗi khối 512-bit $M^{(i)}$:
- 16 từ đầu tiên ($t = 0 \dots 15$): Tách trực tiếp khối 512-bit thành 16 từ 32-bit Big-Endian $W_0, W_1, \dots, W_{15}$.
- 48 từ tiếp theo ($t = 16 \dots 63$): Tính truy hồi theo công thức:
  $$W_t = \left(\sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16}\right) \bmod 2^{32}$$

### Bước 4: Vòng lặp nén 64 bước và cập nhật trạng thái
Gán 8 biến làm việc $(a, b, c, d, e, f, g, h) \leftarrow \left(H_0^{(i-1)}, \dots, H_7^{(i-1)}\right)$. Thực hiện lặp với $t = 0$ đến $63$:

$$T_1 = \left(h + \Sigma_1(e) + Ch(e, f, g) + K_t + W_t\right) \bmod 2^{32}$$

$$T_2 = \left(\Sigma_0(a) + Maj(a, b, c)\right) \bmod 2^{32}$$

$$\begin{aligned}
h &\leftarrow g, \quad g \leftarrow f, \quad f \leftarrow e, \quad e \leftarrow (d + T_1) \bmod 2^{32} \\
d &\leftarrow c, \quad c \leftarrow b, \quad b \leftarrow a, \quad a \leftarrow (T_1 + T_2) \bmod 2^{32}
\end{aligned}$$

Sau khi kết thúc 64 vòng, cộng dồn vào trạng thái băm:
$$H_0^{(i)} = (H_0^{(i-1)} + a) \bmod 2^{32}, \dots, H_7^{(i)} = (H_7^{(i-1)} + h) \bmod 2^{32}$$

Sau khi xử lý hết khối cuối cùng $M^{(N)}$, ghép nối 8 từ $H_0^{(N)} \parallel H_1^{(N)} \parallel \dots \parallel H_7^{(N)}$ theo thứ tự Big-Endian để thu được giá trị băm 256-bit cuối cùng.

---

## Mục 4. Các giả định an toàn, tính chất bảo mật và các tấn công đã biết

### 4.1. Các giả định an toàn và tính chất bảo mật cốt lõi
Một hàm băm mật mã an toàn như SHA-256 thỏa mãn ba tính chất nền tảng:
1. **Kháng tiền ảnh (Preimage Resistance / Tính một chiều)**: Cho trước giá trị băm $y$, không thể tìm được thông điệp $x$ sao cho $\text{SHA-256}(x) = y$ với chi phí thấp hơn duyệt vét cạn $2^{256}$ phép thử.
2. **Kháng tiền ảnh thứ hai (Second-Preimage Resistance)**: Cho trước thông điệp $x_1$, không thể tìm được thông điệp $x_2 \neq x_1$ sao cho $\text{SHA-256}(x_1) = \text{SHA-256}(x_2)$ với độ phức tạp thấp hơn $2^{256}$ phép thử.
3. **Kháng xung đột (Collision Resistance)**: Không thể tìm được bất kỳ cặp $(x_1, x_2)$ nào với $x_1 \neq x_2$ mà $\text{SHA-256}(x_1) = \text{SHA-256}(x_2)$ với độ phức tạp thấp hơn giới hạn nghịch lý ngày sinh là $2^{256/2} = 2^{128}$ phép tính.
4. **Hiệu ứng thác đổ (Avalanche Effect) và giả ngẫu nhiên**: Khi thay đổi chỉ 1 bit ở đầu vào, xác suất mỗi bit trong 256 bit đầu ra bị đảo giá trị xấp xỉ $50\%$ (trung bình khoảng 128 bit thay đổi), không để lộ bất kỳ tương quan thống kê nào.

Ngoài ra, tính minh bạch trong thiết kế của SHA-256 dựa trên việc sử dụng các hằng số **"Nothing-up-my-sleeve numbers"** (sinh từ căn bậc hai và căn bậc ba của các số nguyên tố đầu tiên), loại bỏ nghi ngờ về việc tác giả chèn cửa hậu toán học (backdoor) vào bảng hằng số.

### 4.2. Các tấn công đã biết
- **Tấn công mở rộng độ dài (Length Extension Attack)**: Do đặc trưng của cấu trúc Merkle-Damgård, trạng thái đầu ra 256-bit $\text{SHA-256}(M)$ chính là toàn bộ trạng thái thanh ghi nội bộ $H^{(N)}$ sau khi băm khối cuối cùng. Nếu một hệ thống xây dựng mã xác thực thông điệp một cách ngây thơ theo công thức $\text{MAC} = \text{SHA-256}(K \parallel M)$ (với khóa bí mật $K$), kẻ tấn công chỉ cần biết $\text{SHA-256}(K \parallel M)$ và độ dài của $K \parallel M$ là có thể nạp giá trị băm này làm vector khởi tạo $H^{(N)}$, từ đó tính hợp lệ giá trị $\text{SHA-256}(K \parallel M \parallel \text{Padding} \parallel M')$ với phần mở rộng $M'$ tùy ý mà không cần biết khóa $K$.
  - *Biện pháp khắc phục*: Không dùng $\text{SHA-256}(K \parallel M)$ trực tiếp để xác thực mà phải dùng cấu trúc **HMAC-SHA256** (RFC 2104), hoặc dùng biến thể cắt cụt như SHA-512/256, hoặc chuyển sang cấu trúc Sponge như SHA-3.
- **Phân tích vi sai trên phiên bản rút gọn vòng (Reduced-round cryptanalysis)**: Cho đến nay, chưa có bất kỳ tấn công thực tế nào phá vỡ toàn bộ 64 vòng của SHA-256. Các nghiên cứu lý thuyết (như tấn công tìm xung đột hoặc giả xung đột của Mendel và cộng sự) chỉ mới thực hiện được trên phiên bản rút gọn từ 31 đến 46 vòng, còn cách rất xa so với 64 vòng đầy đủ.
- **Tấn công lượng tử (Quantum Threat)**: Thuật toán Grover trên máy tính lượng tử có thể tăng tốc bậc hai đối với bài toán tìm tiền ảnh (giảm độ phức tạp từ $2^{256}$ xuống $2^{128}$) và thuật toán Brassard-Høyer-Tapp cho bài toán xung đột (còn khoảng $2^{85.3}$ đến $2^{128}$ tùy mô hình bộ nhớ lượng tử), tức là SHA-256 vẫn duy trì tính an toàn hậu lượng tử.

---

## Mục 5. Ưu điểm, hạn chế và ứng dụng thực tế

### 5.1. Ưu điểm
- **Độ tin cậy và biên độ an toàn rất cao**: Sau hơn hai thập kỷ được cộng đồng mật mã học toàn cầu phân tích, toàn bộ 64 vòng của SHA-256 vẫn hoàn toàn vững chắc.
- **Tối ưu phần cứng và phần mềm**: Các phép toán ARX 32-bit khớp trực tiếp với tập lệnh cơ bản của mọi CPU. Hơn nữa, hầu hết các vi xử lý hiện đại (Intel/AMD SHA Extensions, ARMv8 Cryptography Extensions) đều tích hợp tập lệnh phần cứng chuyên dụng cho SHA-256, giúp tốc độ đạt hàng GB/giây.
- **Tương thích trực tiếp với việc dẫn xuất khóa đối xứng**: Đầu ra 256-bit có thể dùng trực tiếp làm khóa AES-256, hoặc cắt 128-bit đầu làm khóa AES-128 mà vẫn đảm bảo phân bố bit đồng đều.

### 5.2. Hạn chế
- **Không phù hợp để băm mật khẩu trực tiếp**: Vì SHA-256 được thiết kế để chạy cực nhanh trên GPU/ASIC, nếu dùng SHA-256 đơn thuần để lưu mật khẩu thì kẻ tấn công có thể thử hàng tỷ mật khẩu mỗi giây. Để lưu mật khẩu, bắt buộc phải kết hợp muối (salt) và dùng các hàm kéo giãn khóa chậm/tốn bộ nhớ như Argon2, bcrypt hoặc PBKDF2-HMAC-SHA256.
- **Nhạy cảm với Length Extension Attack**: Như đã phân tích ở Mục 4.2, cần bọc trong HMAC khi dùng cho xác thực thông điệp có khóa.
- **Hiệu năng trên kiến trúc 64-bit thấp hơn SHA-512**: Do xử lý trên từ 32-bit mỗi vòng, trên các CPU 64-bit không có tăng tốc phần cứng SHA-NI, SHA-512 (xử lý từ 64-bit, khối 1024-bit với 80 vòng) thường có thông lượng byte/giây cao hơn SHA-256.

### 5.3. Ứng dụng thực tế
- **Giao thức bảo mật mạng**: Nền tảng cho TLS 1.2 / TLS 1.3, IPsec, SSH, chứng chỉ số X.509.
- **Chữ ký số và hạ tầng khóa công khai (PKI)**: Băm văn bản trước khi ký bằng RSA-PSS, ECDSA hoặc DSA.
- **Công nghệ Blockchain và tiền mã hóa**: Thuật toán bằng chứng công việc (Proof-of-Work) cốt lõi của Bitcoin (Double SHA-256) và cấu trúc cây Merkle (Merkle Tree) xác thực giao dịch.
- **Kiểm tra toàn vẹn phần mềm và hệ thống lưu trữ**: Xác thực gói cài đặt hệ điều hành, image container (Docker/OCI Content Addressable Storage), và hệ thống quản lý phiên bản Git (đang chuyển dịch sang SHA-256).
- **Dẫn xuất khóa mật mã (Key Derivation)**: Làm hạt nhân trong HKDF (RFC 5869) và bước tạo khóa phiên cho mã hóa đối xứng AES.

---

## Mục 6. Ví dụ tính tay minh họa bước đệm bit và 2 vòng nén đầu tiên

Ta thực hiện tính tay chi tiết cho chuỗi đầu vào ngắn $M =$ `"abc"` và đối chiếu kết quả cho chuỗi họ tên sinh viên `"Trần Gia Thuận"`.

### 6.1. Bước đệm bit (Padding) và tách từ $W_0 \dots W_{15}$ cho chuỗi `"abc"`
- Chuỗi `"abc"` gồm 3 ký tự ASCII:
  - `'a'` $= 0\text{x}61 = 01100001_2$
  - `'b'` $= 0\text{x}62 = 01100010_2$
  - `'c'` $= 0\text{x}63 = 01100011_2$
- Độ dài gốc: $l = 3 \times 8 = 24\text{ bits} = 0\text{x}18$.
- **Gắn bit `1`**: Thêm bit `1` và 7 bit `0` để tròn 1 byte $\Rightarrow$ thêm byte `0x80`. Độ dài hiện tại là $24 + 8 = 32$ bit (4 byte).
- **Tìm số bit `0` cần đệm thêm**:
  $$k = 448 - (24 + 1) = 423\text{ bits}$$
  Do đã thêm 7 bit `0` trong byte `0x80`, số byte `0x00` cần chèn tiếp là $(423 - 7) / 8 = 52$ byte `0x00`.
- **Gắn 64-bit độ dài gốc Big-Endian**: $l = 24$ biểu diễn trên 8 byte là `00 00 00 00 00 00 00 18`.
- **Khối 512-bit duy nhất $M^{(1)}$ sau khi chia làm 16 từ 32-bit ($W_0 \dots W_{15}$)**:
  - $W_0 = \text{0x61626380}$
  - $W_1 = W_2 = \dots = W_{14} = \text{0x00000000}$
  - $W_{15} = \text{0x00000018}$

*(Mở rộng chú thích cho chuỗi họ tên sinh viên `"Trần Gia Thuận"`)*:
- Khi mã hóa UTF-8, chuỗi `"Trần Gia Thuận"` gồm **18 byte** ($l = 18 \times 8 = 144\text{ bits} = 0\text{x}90$):
  `54 72 e1 ba a7 6e 20 47 69 61 20 54 68 75 e1 ba ad 6e`
  (trong đó `'ầ'` chiếm 3 byte `e1 ba a7` và `'ậ'` chiếm 3 byte `e1 ba ad`).
- Sau khi gắn byte `0x80` (vị trí byte thứ 19), cần đệm thêm $56 - 19 = 37$ byte `0x00`, rồi gắn 8 byte độ dài `00 00 00 00 00 00 00 90` để hoàn thành 1 khối 64 byte.

### 6.2. Tính tay Vòng nén thứ nhất ($t = 0$) cho `"abc"`
**Trạng thái khởi tạo ban đầu ($H^{(0)}$)**:
$$\begin{aligned}
a &= \text{0x6a09e667}, & b &= \text{0xbb67ae85}, & c &= \text{0x3c6ef372}, & d &= \text{0xa54ff53a} \\
e &= \text{0x510e527f}, & f &= \text{0x9b05688c}, & g &= \text{0x1f83d9ab}, & h &= \text{0x5be0cd19}
\end{aligned}$$

Tại $t = 0$, ta có $W_0 = \text{0x61626380}$ và hằng số $K_0 = \text{0x428a2f98}$:
1. **Tính $\Sigma_1(e)$ với $e = \text{0x510e527f}$**:
   - $ROTR^6(e) = \text{0xfd443949}$
   - $ROTR^{11}(e) = \text{0x4feaa1ca}$
   - $ROTR^{25}(e) = \text{0x87a93f28}$
   - $\Sigma_1(e) = \text{0xfd443949} \oplus \text{0x4feaa1ca} \oplus \text{0x87a93f28} = \text{0x3587272b}$
2. **Tính $Ch(e, f, g) = (e \land f) \oplus (\neg e \land g)$**:
   - $e \land f = \text{0x510e527f} \land \text{0x9b05688c} = \text{0x1104400c}$
   - $\neg e \land g = \text{0xaef1ad80} \land \text{0x1f83d9ab} = \text{0x0e818980}$
   - $Ch(e, f, g) = \text{0x1104400c} \oplus \text{0x0e818980} = \text{0x1f85c98c}$
3. **Tính $T_1 = (h + \Sigma_1(e) + Ch(e, f, g) + K_0 + W_0) \bmod 2^{32}$**:
   $$T_1 = (\text{0x5be0cd19} + \text{0x3587272b} + \text{0x1f85c98c} + \text{0x428a2f98} + \text{0x61626380}) \bmod 2^{32} = \text{0x54da50e8}$$
4. **Tính $\Sigma_0(a)$ với $a = \text{0x6a09e667}$**:
   - $ROTR^2(a) = \text{0xda827999}$
   - $ROTR^{13}(a) = \text{0xbb33b504}$
   - $ROTR^{22}(a) = \text{0xa7999da8}$
   - $\Sigma_0(a) = \text{0xda827999} \oplus \text{0xbb33b504} \oplus \text{0xa7999da8} = \text{0xce20b47e}$
5. **Tính $Maj(a, b, c) = (a \land b) \oplus (a \land c) \oplus (b \land c)$**:
   $$Maj(\text{0x6a09e667}, \text{0xbb67ae85}, \text{0x3c6ef372}) = \text{0x3a6fe667}$$
6. **Tính $T_2 = (\Sigma_0(a) + Maj(a, b, c)) \bmod 2^{32}$**:
   $$T_2 = (\text{0xce20b47e} + \text{0x3a6fe667}) \bmod 2^{32} = \text{0x08909ae5}$$
7. **Cập nhật 8 thanh ghi sau vòng $t = 0$**:
   - $a \leftarrow (T_1 + T_2) \bmod 2^{32} = (\text{0x54da50e8} + \text{0x08909ae5}) \bmod 2^{32} = \text{0x5d6aebcd}$
   - $e \leftarrow (d + T_1) \bmod 2^{32} = (\text{0xa54ff53a} + \text{0x54da50e8}) \bmod 2^{32} = \text{0xfa2a4622}$
   - Các thanh ghi còn lại dịch chuyển:
     $$b = \text{0x6a09e667}, \quad c = \text{0xbb67ae85}, \quad d = \text{0x3c6ef372}, \quad f = \text{0x510e527f}, \quad g = \text{0x9b05688c}, \quad h = \text{0x1f83d9ab}$$

### 6.3. Tính tay Vòng nén thứ hai ($t = 1$) cho `"abc"`
Tại $t = 1$, ta có $W_1 = \text{0x00000000}$ và hằng số $K_1 = \text{0x71374491}$:
1. **Tính $\Sigma_1(e)$ với $e = \text{0xfa2a4622}$**:
   $$\Sigma_1(\text{0xfa2a4622}) = \text{0x5a94fd2d}$$
2. **Tính $Ch(e, f, g)$ với $e = \text{0xfa2a4622}, f = \text{0x510e527f}, g = \text{0x9b05688c}$**:
   $$Ch(e, f, g) = \text{0x510f6aae}$$
3. **Tính $T_1 = (h + \Sigma_1(e) + Ch(e, f, g) + K_1 + W_1) \bmod 2^{32}$**:
   $$T_1 = (\text{0x1f83d9ab} + \text{0x5a94fd2d} + \text{0x510f6aae} + \text{0x71374491} + \text{0x00000000}) \bmod 2^{32} = \text{0x3c5f8617}$$
4. **Tính $\Sigma_0(a)$ và $Maj(a, b, c)$ với $a = \text{0x5d6aebcd}, b = \text{0x6a09e667}, c = \text{0xbb67ae85}$**:
   - $\Sigma_0(a) = \text{0xa29f64d1}$
   - $Maj(a, b, c) = \text{0x7b6beec5}$
   - $T_2 = (\text{0xa29f64d1} + \text{0x7b6beec5}) \bmod 2^{32} = \text{0x1e0b5396}$
5. **Cập nhật 8 thanh ghi sau vòng $t = 1$**:
   - $a \leftarrow (\text{0x3c5f8617} + \text{0x1e0b5396}) \bmod 2^{32} = \text{0x5a6ad9ad}$
   - $e \leftarrow (\text{0x3c6ef372} + \text{0x3c5f8617}) \bmod 2^{32} = \text{0x78ce7989}$
   - Các thanh ghi khác:
     $$b = \text{0x5d6aebcd}, \quad c = \text{0x6a09e667}, \quad d = \text{0xbb67ae85}, \quad f = \text{0xfa2a4622}, \quad g = \text{0x510e527f}, \quad h = \text{0x9b05688c}$$

---

## Mục 7. Giải thích cấu trúc code `sha256.py` đã viết

Tệp mã nguồn [sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py) được thiết kế theo hướng lập trình hàm rõ ràng, không phụ thuộc bất kỳ thư viện mật mã nào (chỉ sử dụng `struct` để đóng/mở gói byte Big-Endian và `time` để đo hiệu năng):

1. **Khối sinh hằng số từ nguyên lý gốc ([sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py#L17-L56))**:
   - Hàm `lay_n_so_nguyen_to_dau_tien(64)` tìm 64 số nguyên tố đầu tiên ($2 \dots 311$).
   - Hàm `trich_phan_thap_phan_32bit(so_nguyen_to, bac_can)` dùng thuật toán tìm kiếm nhị phân trên số nguyên lớn của Python để tính chính xác $\lfloor \text{frac}(\sqrt[r]{p}) \times 2^{32} \rfloor$ mà không bị sai số dấu phẩy động, tự động tạo ra danh sách `GIA_TRI_KHOI_TAO_H0` và `HANG_SO_VONG_K`.
2. **Khối các phép toán bit 32-bit cơ sở ([sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py#L63-L133))**:
   - Vì kiểu `int` trong Python có độ dài bit tự mở rộng (arbitrary-precision), mọi phép dịch trái, phép đảo bit (`~x`) và phép cộng đều được giới hạn bằng mặt nạ `MASK_32 = 0xFFFFFFFF` để mô phỏng chính xác thanh ghi 32-bit không dấu.
   - Gồm đầy đủ 8 hàm toán học: `rotr`, `shr`, `ham_ch`, `ham_maj`, `sigma_hoa_0` ($\Sigma_0$), `sigma_hoa_1` ($\Sigma_1$), `sigma_thuong_0` ($\sigma_0$), và `sigma_thuong_1` ($\sigma_1$).
3. **Khối tiền xử lý đệm bit và chia khối ([sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py#L140-L165))**:
   - Hàm `dem_thong_diep(du_lieu_bytes)` chuyển thông điệp sang `bytearray`, nối byte `0x80`, lặp nối `0x00` đến khi `len % 64 == 56`, và dùng `struct.pack(">Q", do_dai_bit)` để đóng gói độ dài bit thành 8 byte Big-Endian.
   - Hàm `chia_khoi_512bit(du_lieu_da_dem)` cắt chuỗi byte đã đệm thành từng đoạn 64 byte (512 bit).
4. **Khối nén 64 vòng và tổng hợp mã băm ([sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py#L172-L246))**:
   - Hàm `nen_mot_khoi(khoi_64_byte, trang_thai_h)` giải nén 64 byte thành 16 từ 32-bit đầu tiên bằng `struct.unpack(">16I", khoi_64_byte)`, mở rộng lên 64 từ $W_0 \dots W_{63}$, thực hiện vòng lặp 64 bước cập nhật $(a, b, c, d, e, f, g, h)$ và cộng dồn với `trang_thai_h`.
   - Hai hàm giao diện chính là `bam_sha256_bytes(du_lieu)` (trả về 32 byte thô) và `bam_sha256_hex(du_lieu)` (trả về chuỗi 64 ký tự Hex).
5. **Khối kiểm thử, trích khóa AES-128 và đo hiệu năng ([sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py#L253-L343))**:
   - Hàm `chay_benchmark()` đo thời gian thực thi trung bình qua 50 lần lặp với bộ đếm độ phân giải cao `time.perf_counter()` trên các mẫu dữ liệu 100B, 1KB và 10KB.
   - Hàm `main()` tự động đối chiếu vector chuẩn, băm chuỗi `"Trần Gia Thuận"` (UTF-8), trích 128 bit đầu làm khóa AES-128 và in bảng kết quả.

---

## Mục 8. Bảng đánh giá thực nghiệm, kiểm chứng tính đúng đắn, hiệu năng tính toán và kết luận

### 8.1. Kiểm chứng tính đúng đắn và trích xuất khóa AES-128 cho sinh viên
Chương trình [sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py) đã được chạy thực nghiệm và đối chiếu với các vector kiểm thử chuẩn FIPS 180-4 cùng dữ liệu cá nhân của sinh viên **Trần Gia Thuận** (chữ số cuối SID: **3**):

| Trường hợp kiểm thử | Đầu vào (UTF-8 / Bytes) | Số byte | Kết quả băm SHA-256 (256-bit Hex) | Trạng thái |
| :--- | :--- | :---: | :--- | :---: |
| Vector chuẩn 1 (Chuỗi rỗng) | `""` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | **ĐẠT (PASS)** |
| Vector chuẩn 2 (Chuỗi ngắn) | `"abc"` | 3 | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | **ĐẠT (PASS)** |
| **Họ tên sinh viên (SID cuối = 3)** | `"Trần Gia Thuận"` (`5472e1baa76e2047696120546875e1baad6e`) | 18 | `70c31dddb87cf9c3fd103a5669346839aa646cb3240d200a80859c06f07ef0e0` | **Chính xác 100%** |

**Kết quả trích xuất khóa cho phần AES-128**:
- **Chuỗi băm SHA-256 đầy đủ (256-bit / 32 bytes)**:
  `70c31dddb87cf9c3fd103a5669346839aa646cb3240d200a80859c06f07ef0e0`
- **Khóa AES-128 (128 bit / 16 byte đầu tiên)**:
  - Dạng chuỗi Hex liên tục (32 ký tự Hex): `70c31dddb87cf9c3fd103a5669346839`
  - Dạng mảng 16 byte Hex: `70 c3 1d dd b8 7c f9 c3 fd 10 3a 56 69 34 68 39`

### 8.2. Bảng đánh giá hiệu năng tính toán (Benchmark)
Kết quả đo thực nghiệm trực tiếp khi chạy `python -X utf8 sha256.py` (lấy trung bình trên 50 lần chạy cho mỗi kích thước dữ liệu):

| Kích thước dữ liệu | Số byte đầu vào | Số khối 512-bit sau đệm ($N$) | Tổng số vòng nén ($64 \times N$) | Thời gian chạy trung bình (ms) | Thông lượng xử lý (KB/s) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **100 Bytes** | 100 B | 2 khối | 128 vòng | `0.5140 ms` | `190.01 KB/s` |
| **1 KB** | 1,024 B | 17 khối | 1,088 vòng | `4.2872 ms` | `233.25 KB/s` |
| **10 KB** | 10,240 B | 161 khối | 10,304 vòng | `39.3219 ms` | `254.31 KB/s` |

**Phân tích hiệu năng**:
- Với dữ liệu 100 Bytes, sau khi thêm 1 byte `0x80` và 8 byte độ dài ($100 + 9 = 109 > 64$), thông điệp vượt quá 1 khối 64 byte nên phải chia thành **2 khối 512-bit**. Tương tự, 1 KB ($1024$ byte là bội số của 64) cần thêm 1 khối đệm riêng biệt nên tổng cộng có $16 + 1 = 17$ khối; 10 KB ($10240$ byte) có $160 + 1 = 161$ khối.
- Thời gian thực thi tăng tuyến tính hoàn toàn theo số khối $N$ ($\mathcal{O}(N)$): trung bình mỗi khối 512-bit mất khoảng $0.244\text{ ms}$ trên trình thông dịch Python thuần, đạt thông lượng ổn định ở mức $\sim 254\text{ KB/s}$ khi kích thước dữ liệu lớn dần.

### 8.3. Kết luận
Đồ án đã xây dựng thành công thuật toán băm mật mã **SHA-256** bằng ngôn ngữ Python thuần túy từ những nguyên lý toán học cơ sở nhất (tự sinh hằng số từ căn bậc hai/bậc ba của các số nguyên tố, tự cài đặt toàn bộ các phép toán bit 32-bit, đệm bit Merkle-Damgård và vòng lặp nén Davies-Meyer 64 bước). Kết quả kiểm thử khớp tuyệt đối với chuẩn FIPS 180-4, đồng thời cung cấp chính xác khóa 128-bit (`70c31dddb87cf9c3fd103a5669346839`) dẫn xuất từ họ tên sinh viên `"Trần Gia Thuận"` để sử dụng trực tiếp cho mô-đun mã hóa đối xứng AES-128 tiếp theo của đồ án.
