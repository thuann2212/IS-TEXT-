# BÁO CÁO ĐỒ ÁN AN TOÀN THÔNG TIN: CHỮ KÝ SỐ ĐƯỜNG CONG ELLIPTIC (ECDSA)

- **Họ và tên sinh viên**: Trần Gia Thuận
- **Chữ số cuối SID**: 3 (3 mod 4 = 3 $\rightarrow$ Phân công đề tài: **Chữ ký số: ECDSA - Elliptic Curve Digital Signature Algorithm**)
- **Mã nguồn thực nghiệm**: [ecdsa.py](file:///d:/HOCTAP/IS(Text)/ecdsa.py) (kết nối trực tiếp cùng [sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py), đối chiếu cùng [rsa.py](file:///d:/HOCTAP/IS(Text)/rsa.py) và [aes128.py](file:///d:/HOCTAP/IS(Text)/aes128.py))

---

## Mục 1. Bối cảnh lịch sử, quá trình phát triển và động lực thiết kế chữ ký số đường cong Elliptic

### 1.1. Khủng hoảng kích thước khóa của RSA/DSA và sự ra đời của ECC (1985)
Vào cuối những năm 1970 và đầu thập niên 1980, hệ thống mật mã bất đối xứng RSA (1977) và thuật toán chữ ký số DSA (Digital Signature Algorithm - 1991) đã đặt nền móng cho thương mại điện tử và an toàn mạng. Cả hai hệ mật mã này đều dựa trên độ khó của các bài toán lý thuyết số cổ điển trên nhóm nhân của trường hữu hạn:
- **RSA**: Dựa trên Bài toán phân tích thừa số nguyên tố lớn (Integer Factorization Problem - IFP).
- **DSA / Diffie-Hellman**: Dựa trên Bài toán logarit rời rạc cổ điển (Discrete Logarithm Problem - DLP) trên nhóm nhân $\mathbb{Z}_p^*$.

Tuy nhiên, vào cuối thập niên 1980, sự phát triển vượt bậc của các thuật toán tấn công dạng **Sàng trường số** (*Number Field Sieve* - NFS), đặc biệt là *General Number Field Sieve* (GNFS) và *Index Calculus*, đã làm suy giảm nghiêm trọng độ an toàn thực tế của RSA và DSA. Các thuật toán này có độ phức tạp thời gian **bán hàm mũ** (*sub-exponential time*):
$$\mathcal{O}\left( \exp \left( \left( C + o(1) \right) (\ln n)^{1/3} (\ln \ln n)^{2/3} \right) \right)$$

Hậu quả là để duy trì mức an toàn tương đương với sự gia tăng năng lực tính toán của phần cứng máy tính, độ dài khóa của RSA và DSA buộc phải tăng vọt theo cấp số mũ: từ 512-bit lên 1024-bit, 2048-bit, 3072-bit và thậm chí 4096-bit. Khóa quá lớn dẫn đến ba hệ lụy nghiêm trọng:
1. **Tiêu tốn băng thông truyền thông**: Chữ ký RSA-3072 hoặc RSA-4096 có kích thước lên tới 384 đến 512 byte cho mỗi gói tin.
2. **Quá tải bộ nhớ và năng lượng**: Trên các thiết bị nhúng hạn chế tài nguyên như thẻ thông minh (smart cards), chip thẻ ngân hàng EMV, cảm biến IoT, thiết bị y tế đeo tay, việc lưu trữ và tính toán lũy thừa modulo trên các số nguyên 4096-bit làm cạn kiệt pin và tràn bộ nhớ RAM/ROM.
3. **Độ trễ cao trong thiết lập kết nối mạng**: Quá trình bắt tay SSL/TLS giữa máy chủ và hàng triệu khách hàng di động bị tắc nghẽn do tính toán chậm.

Năm 1985, hai nhà toán học độc lập:
- **Neal Koblitz** (Đại học Washington),
- **Victor S. Miller** (Trung tâm Nghiên cứu Thomas J. Watson của IBM),

đã đề xuất một ý tưởng mang tính cách mạng: **Xây dựng hệ mật mã khóa công khai dựa trên nhóm Abel của các điểm trên đường cong Elliptic qua trường hữu hạn** (gọi tắt là **ECC** - *Elliptic Curve Cryptography*).

```mermaid
flowchart TD
    A["Khủng hoảng kích thước khóa (Thập niên 1980)"] --> B["Thuật toán sàng GNFS ra đời\nĐộ phức tạp Bán hàm mũ Sub-exponential"]
    B --> C["RSA/DSA buộc phải tăng kích thước khóa:\n1024b -> 2048b -> 3072b -> 4096b"]
    C --> D["Nghẽn băng thông, cạn kiệt pin IoT, thẻ chip quá tải"]
    
    E["Phát minh ECC (1985)\nNeal Koblitz & Victor Miller"] --> F["Đưa bài toán Logarit rời rạc lên nhóm điểm Elliptic (ECDLP)"]
    F --> G["Thuật toán tấn công tốt nhất chỉ đạt Hàm mũ đầy đủ O(sqrt(n))\nIndex Calculus KHÔNG áp dụng được!"]
    
    G --> H["ECDSA (1998 - 2005)\nChuẩn hóa quốc tế ANSI X9.62 / FIPS 186\nKhóa 256-bit an toàn ngang RSA 3072-bit!"]
```

### 1.2. Quá trình chuẩn hóa ECDSA (1998 - 2005)
Nhận thấy tiềm năng vượt trội của ECC, nhà toán học Scott Vanstone cùng các cộng sự tại công ty Certicom (Canada) đã hoàn thiện thuật toán chữ ký số dựa trên đường cong Elliptic, đặt tên là **ECDSA** (*Elliptic Curve Digital Signature Algorithm*) - phiên bản thích nghi của thuật toán DSA trên nhóm đường cong Elliptic.

Quá trình chuẩn hóa quốc tế của ECDSA diễn ra qua các mốc quan trọng:
- **1998 - 1999**: Viện Tiêu chuẩn Quốc gia Hoa Kỳ (ANSI) công bố chuẩn **ANSI X9.62** xác lập đặc tả chính thức cho ECDSA trong ngành tài chính ngân hàng.
- **2000**: Viện Kỹ sư Điện và Điện tử chuẩn hóa cấu trúc trong **IEEE 1363-2000** (*Standard Specifications for Public-Key Cryptography*).
- **2000 - 2005**: Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST) chính thức đưa ECDSA vào tiêu chuẩn xử lý thông tin liên bang **FIPS 186-2** (năm 2000) và cập nhật trong **FIPS 186-3**, **FIPS 186-4**, đồng thời công bố bộ các đường cong chuẩn NIST Curves (P-192, P-224, P-256, P-384, P-521).
- **2005**: Cơ quan An ninh Quốc gia Hoa Kỳ (NSA) đưa ECDSA vào bộ giao thức mật mã mật cấp cao **Suite B Cryptography**, khuyến nghị sử dụng đường cong P-256 và P-384 để bảo vệ thông tin mật quốc gia.
- **2008 - 2009**: Satoshi Nakamoto lựa chọn đường cong **secp256k1** kết hợp giải thuật ECDSA để xây dựng toàn bộ cơ chế sở hữu địa chỉ ví và xác thực giao dịch tài chính phi tập trung trong mạng lưới Bitcoin, mở ra kỷ nguyên bùng nổ của công nghệ Blockchain trên toàn cầu.

### 1.3. Động lực thiết kế và triết lý cốt lõi của ECDSA
Triết lý thiết kế then chốt của ECDSA tập trung vào ba động lực:
1. **Tối đa hóa tỷ lệ "Độ an toàn mật mã trên mỗi bit khóa"**: 
   Trên đường cong Elliptic không suy biến được lựa chọn đúng chuẩn, các thuật toán tấn công dựa trên cấu trúc trường số (*Index Calculus*) hoàn toàn vô hiệu. Thuật toán tấn công tổng quát mạnh nhất trên máy tính cổ điển là thuật toán Pollard's $\rho$ có độ phức tạp **hàm mũ đầy đủ** (*fully exponential time*):
   $$\mathcal{O}(\sqrt{n})$$
   Do đó, khóa riêng ECDSA 256-bit cung cấp mức bảo mật tương đương **128-bit an toàn**, bằng với khóa RSA 3072-bit.
2. **Tiết kiệm triệt để kích thước chữ ký và băng thông truyền tải**:
   Một chữ ký ECDSA 256-bit chỉ gồm một cặp số $(r, s)$ có tổng dung lượng đúng $32 + 32 = 64$ byte, nhỏ hơn gần **6 lần** so với chữ ký RSA 3072-bit (384 byte) và nhỏ hơn **8 lần** so với RSA 4096-bit (512 byte).
3. **Tối ưu hóa hiệu năng tính toán và tiêu thụ năng lượng**:
   Phép nhân vô hướng trên đường cong Elliptic 256-bit sử dụng ít chu kỳ xung nhịp CPU và năng lượng hơn hàng chục lần so với phép lũy thừa modulo trên số nguyên 3072-bit hoặc 4096-bit, đặc biệt thích hợp cho hệ thống vi điều khiển 8-bit/32-bit và môi trường biên (Edge Computing).

---

## Mục 2. Cơ sở toán học nền tảng

### 2.1. Phương trình đường cong Elliptic trên trường hữu hạn $\mathbb{F}_p$
Trong hình học đại số, một đường cong Elliptic qua trường số thực $\mathbb{R}$ là tập hợp các nghiệm thỏa mãn phương trình bậc ba hai biến. Khi ứng dụng vào mật mã học, để tránh sai số dấu phẩy động và đảm bảo tính rời rạc, đường cong Elliptic được định nghĩa trên một **trường hữu hạn** (*Galois Field*) $\mathbb{F}_p$ với $p$ là một số nguyên tố lớn ($p > 3$).

Theo dạng chuẩn tắc rút gọn **Weierstrass** (*Short Weierstrass Form*), phương trình đường cong Elliptic $E$ qua $\mathbb{F}_p$ có dạng:
$$y^2 \equiv x^3 + a \cdot x + b \pmod p$$
trong đó $a, b \in \mathbb{F}_p$.

> [!IMPORTANT]
> **Điều kiện không suy biến (Non-singularity Condition)**:
> Đường cong được gọi là trơn (không có điểm tự cắt, không có điểm lùi/điểm nhọn - *cusp* hay *node*) khi và chỉ khi biệt thức $\Delta$ khác không:
> $$\Delta = -16(4a^3 + 27b^2) \not\equiv 0 \pmod p \iff 4a^3 + 27b^2 \not\equiv 0 \pmod p$$
> Nếu $\Delta \equiv 0 \pmod p$, đường cong sẽ bị suy biến thành đường thẳng hoặc đường bậc hai, khi đó bài toán logarit rời rạc có thể bị phá vỡ dễ dàng.

Tập hợp các điểm trên đường cong Elliptic $E(\mathbb{F}_p)$ bao gồm toàn bộ các cặp tọa độ affine $(x, y) \in \mathbb{F}_p \times \mathbb{F}_p$ thỏa mãn phương trình đồng dư Weierstrass, cộng thêm một điểm đặc biệt ở vô cực gọi là **Điểm vô cực** (*Point at Infinity*), ký hiệu là $\mathcal{O}$:
$$E(\mathbb{F}_p) = \left\{ (x, y) \in \mathbb{F}_p^2 \mid y^2 \equiv x^3 + ax + b \pmod p \right\} \cup \{ \mathcal{O} \}$$

```mermaid
flowchart LR
    subgraph CurveDef["Phương trình Weierstrass trên F_p"]
        E["y² ≡ x³ + ax + b (mod p)"]
        Delta["Điều kiện không suy biến:\n4a³ + 27b² ≢ 0 (mod p)"]
    end
    subgraph Points["Tập hợp điểm E(F_p)"]
        P1["Điểm Affine: P(x, y)"]
        O["Điểm vô cực O\n(Identity Element)"]
    end
    CurveDef --> Points
```

### 2.2. Cấu trúc nhóm Abel $(E(\mathbb{F}_p), +)$
Tập hợp các điểm $E(\mathbb{F}_p)$ cùng với phép toán cộng điểm hình học lập thành một **nhóm Abel hữu hạn** (*Finite Abelian Group*).

#### 2.2.1. Quy tắc hình học hợp dây và tiếp tuyến (Chord and Tangent Rule)
Trên mặt phẳng liên tục, tổng của hai điểm $P$ và $Q$ được xác định theo quy tắc:
1. Vẽ đường thẳng $L$ đi qua $P$ và $Q$ (nếu $P \neq Q$) hoặc tiếp tuyến với đường cong tại $P$ (nếu $P = Q$).
2. Theo định lý Bézout, đường thẳng $L$ sẽ cắt đường cong bậc ba tại đúng một điểm thứ ba $R'$.
3. Lấy đối xứng điểm $R'$ qua trục hoành $Ox$, ta thu được điểm tổng $R = P + Q$.

```mermaid
flowchart TD
    A["Hai điểm P và Q trên đường cong"] --> B{"P == Q ?"}
    B -- "Không (P ≠ Q)" --> C["Kẻ đường thẳng cắt cát tuyến qua P và Q (Point Addition)\nĐộ dốc λ = (y_Q - y_P) / (x_Q - x_P) mod p"]
    B -- "Có (P == Q)" --> D["Kẻ tiếp tuyến tại điểm P (Point Doubling)\nĐộ dốc λ = (3x_P² + a) / (2y_P) mod p"]
    C --> E["Tìm giao điểm thứ ba R'\nLấy đối xứng qua trục Ox:\nx_R = λ² - x_P - x_Q mod p\ny_R = λ(x_P - x_R) - y_P mod p"]
    D --> E
    E --> F["Kết quả: R = P + Q"]
```

#### 2.2.2. Các công thức đại số tường minh trên trường hữu hạn $\mathbb{F}_p$
Cho hai điểm $P = (x_1, y_1)$ và $Q = (x_2, y_2)$ thuộc $E(\mathbb{F}_p)$:

1. **Phần tử trung hòa (Identity Element)**:
   Điểm vô cực $\mathcal{O}$ đóng vai trò là số 0 của nhóm:
   $$P + \mathcal{O} = \mathcal{O} + P = P \quad \forall P \in E(\mathbb{F}_p)$$

2. **Phần tử nghịch đảo (Point Negation)**:
   Điểm đối của $P(x_1, y_1)$ là điểm đối xứng qua trục $Ox$:
   $$-P = (x_1, -y_1 \bmod p) = (x_1, p - y_1)$$
   Thỏa mãn: $P + (-P) = \mathcal{O}$.
   Nếu một đường thẳng thẳng đứng đi qua $P(x_1, y_1)$ và $Q(x_1, -y_1)$, đường thẳng này cắt đường cong tại điểm vô cực $\mathcal{O}$.

3. **Phép cộng hai điểm phân biệt ($P \neq Q$ và $x_1 \neq x_2$) - Point Addition**:
   Hệ số góc của cát tuyến qua $P$ và $Q$:
   $$\lambda = \frac{y_2 - y_1}{x_2 - x_1} \equiv (y_2 - y_1) \cdot (x_2 - x_1)^{-1} \pmod p$$
   Tọa độ của điểm tổng $R(x_3, y_3) = P + Q$:
   $$\begin{cases}
   x_3 = \lambda^2 - x_1 - x_2 \pmod p \\
   y_3 = \lambda(x_1 - x_3) - y_1 \pmod p
   \end{cases}$$

4. **Phép nhân đôi một điểm ($P = Q$) - Point Doubling**:
   Nếu $y_1 = 0$, tiếp tuyến với đường cong là đường thẳng đứng, do đó $2P = \mathcal{O}$.
   Nếu $y_1 \neq 0$, hệ số góc của tiếp tuyến tại $P$ (được tính bằng đạo hàm ẩn $2y \frac{dy}{dx} = 3x^2 + a$):
   $$\lambda = \frac{3x_1^2 + a}{2y_1} \equiv (3x_1^2 + a) \cdot (2y_1)^{-1} \pmod p$$
   Tọa độ của điểm nhân đôi $R(x_3, y_3) = 2P$:
   $$\begin{cases}
   x_3 = \lambda^2 - 2x_1 \pmod p \\
   y_3 = \lambda(x_1 - x_3) - y_1 \pmod p
   \end{cases}$$

#### 2.2.3. Kiểm chứng các tiên đề nhóm Abel
Hệ thống $(E(\mathbb{F}_p), +)$ thỏa mãn đầy đủ 4 tiên đề nhóm cộng Abel:
- **Tính đóng (Closure)**: $\forall P, Q \in E(\mathbb{F}_p) \implies P + Q \in E(\mathbb{F}_p)$.
- **Tính kết hợp (Associativity)**: $\forall P, Q, R \in E(\mathbb{F}_p) \implies (P + Q) + R = P + (Q + R)$.
- **Phần tử trung hòa (Identity Element)**: Tồn tại $\mathcal{O}$ sao cho $P + \mathcal{O} = P$.
- **Phần tử đối (Inverse Element)**: $\forall P \in E(\mathbb{F}_p)$, luôn tồn tại $-P \in E(\mathbb{F}_p)$ sao cho $P + (-P) = \mathcal{O}$.
- **Tính giao hoán (Commutativity)**: $\forall P, Q \in E(\mathbb{F}_p) \implies P + Q = Q + P$.

### 2.3. Bậc của đường cong và Định lý Hasse
Số lượng tất cả các điểm trên đường cong Elliptic $E(\mathbb{F}_p)$ (tính cả điểm vô cực $\mathcal{O}$) được gọi là **bậc của đường cong** (*Order of the Curve*), ký hiệu là $\#E(\mathbb{F}_p)$.

Năm 1934, nhà toán học Helmut Hasse đã chứng minh định lý nền tảng:
> [!NOTE]
> **Định lý Hasse (Hasse's Theorem on Elliptic Curves)**:
> Số điểm của đường cong Elliptic trên trường hữu hạn $\mathbb{F}_p$ xấp xỉ bằng $p + 1$, và độ lệch được chặn chặt bởi:
> $$\left| \#E(\mathbb{F}_p) - (p + 1) \right| \le 2\sqrt{p}$$
> Đại lượng $t = p + 1 - \#E(\mathbb{F}_p)$ được gọi là **vết Frobenius** (*Frobenius trace*), thỏa mãn $|t| \le 2\sqrt{p}$.

Trong mật mã học, ta chọn một điểm cơ sở $G \in E(\mathbb{F}_p)$ sao cho nhóm con sinh bởi $G$:
$$\langle G \rangle = \{ \mathcal{O}, G, 2G, 3G, \dots, (n - 1)G \}$$
có bậc là một số nguyên tố lớn $n$ (nghĩa là $n \cdot G = \mathcal{O}$). Theo định lý Lagrange, bậc của nhóm con phải là ước của bậc toàn thể:
$$\#E(\mathbb{F}_p) = n \cdot h$$
trong đó $h$ được gọi là **hệ số đồng bậc** (*Cofactor*). Trong các đường cong mật mã an toàn cao như `secp256k1` hay `NIST P-256`, các tham số được thiết kế cẩn trọng để $h = 1$, nghĩa là toàn bộ nhóm điểm trên đường cong đều là nhóm xyclic sinh bởi $G$ có bậc nguyên tố $n = \#E(\mathbb{F}_p)$.

### 2.4. Phép nhân vô hướng (Scalar Multiplication) và Thuật toán Double-and-Add
Phép toán trung tâm của toàn bộ hệ mật mã đường cong Elliptic là phép nhân một số nguyên $k$ với một điểm $P$:
$$k \cdot P = \underbrace{P + P + \dots + P}_{k \text{ lần}}$$

Nếu tính toán bằng cách cộng dồn $k$ lần, độ phức tạp sẽ là $O(k)$ - hoàn toàn bất khả thi khi $k$ là một số nguyên 256-bit ($k \approx 2^{256}$). Thay vào đó, ta sử dụng thuật toán **Double-and-Add** (tương đương Square-and-Multiply trong RSA):
- Phân tích $k$ thành chuỗi bit nhị phân: $k = \sum_{i=0}^{m-1} b_i 2^i$ với $b_i \in \{0, 1\}$.
- Duyệt qua từng bit của $k$: trong mỗi bước lặp, luôn nhân đôi điểm hiện tại ($2 \cdot P_{curr}$); nếu bit $b_i = 1$, cộng dồn vào kết quả.
- Độ phức tạp thời gian giảm từ $\mathcal{O}(k)$ xuống chỉ còn $\mathcal{O}(\log_2 k)$ phép toán điểm (khoảng 256 phép nhân đôi và trung bình 128 phép cộng điểm cho khóa 256-bit).

```python
# Thuật toán Double-and-Add (Right-to-Left)
def scalar_mult(k: int, P: Point) -> Point:
    result = INFINITY_POINT
    current = P
    while k > 0:
        if k & 1:  # Nếu bit cuối là 1 -> Add
            result = point_add(result, current)
        current = point_double(current)  # Luôn luôn Double
        k >>= 1
    return result
```

### 2.5. Bài toán Logarit rời rạc trên đường cong Elliptic (ECDLP)
An toàn của toàn bộ hệ thống ECDSA dựa trên độ khó tính toán của bài toán:
> **Bài toán ECDLP (Elliptic Curve Discrete Logarithm Problem)**:
> Cho trước phương trình đường cong $E(\mathbb{F}_p)$, điểm cơ sở $G$ có bậc nguyên tố $n$, và một điểm $Q \in \langle G \rangle$.
> Hãy tìm số nguyên bí mật $d \in [1, n - 1]$ sao cho:
> $$Q = d \cdot G$$

Đặc điểm sống còn tạo nên ưu thế tuyệt đối của ECDLP so với bài toán IFP (RSA) và DLP cổ điển ($\mathbb{Z}_p^*$):
- **Phép nhân theo chiều thuận ($d, G \to Q = d \cdot G$)**: Cực kỳ dễ dàng và nhanh chóng bằng Double-and-Add ($\mathcal{O}(\log n)$).
- **Phép toán ngược ($Q, G \to d$)**: Trên các đường cong phi dị thường (*non-anomalous curves*), các nhà mật mã học đã chứng minh **không tồn tại cấu trúc đại số nào cho phép áp dụng thuật toán Sàng trường số Index Calculus**. Thuật toán cổ điển tốt nhất để giải ECDLP là thuật toán **Pollard's $\rho$**, có độ phức tạp thời gian hàm mũ đầy đủ:
  $$\mathcal{T}_{classical} = \mathcal{O}(\sqrt{n}) = \mathcal{O}(2^{b/2}) \text{ phép toán đường cong}$$
  với $b = \log_2 n$.
- Với đường cong 256-bit ($b = 256$), $\sqrt{n} \approx 2^{128} \approx 3.4 \times 10^{38}$ phép tính. Dù huy động toàn bộ siêu máy tính mạnh nhất hành tinh tính toán liên tục hàng tỷ năm cũng không thể giải được bài toán này!

---

## Mục 3. Quy trình vận hành chi tiết (Sinh khóa, Tạo chữ ký, Xác minh chữ ký)

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Người ký (Alice - Chủ khóa)
    actor Bob as Người xác minh (Bob - Công chúng)
    Note over Alice: 1. Sinh khóa (KeyGen)<br/>Chọn khóa riêng d ngẫu nhiên trong [1, n-1]<br/>Tính khóa công khai Q = d * G (Double-and-Add)
    Alice->>Bob: Công khai Q(x, y) và bộ tham số miền (p, a, b, G, n)
    Note over Alice: 2. Tạo chữ ký số (Sign)<br/>Băm thông điệp z = SHA-256(m)<br/>Chọn nonce bí mật k ngẫu nhiên trong [1, n-1]<br/>Tính R(x1, y1) = k * G<br/>r = x1 mod n<br/>s = k^(-1) * (z + r * d) mod n
    Alice->>Bob: Gửi Thông điệp m kèm Chữ ký số (r, s)
    Note over Bob: 3. Xác minh chữ ký (Verify)<br/>Kiểm tra 1 <= r, s < n và Q on curve<br/>Tính z = SHA-256(m)<br/>Tính w = s^(-1) mod n<br/>Tính u1 = z * w mod n, u2 = r * w mod n<br/>Tính điểm P = u1 * G + u2 * Q = (x_P, y_P)<br/>Xác nhận: x_P mod n == r ?
    Bob-->>Alice: Chữ ký HỢP LỆ (Toàn vẹn & Chống chối bỏ)
```

### 3.1. Thiết lập các tham số miền chuẩn (Domain Parameters)
Trước khi giao tiếp, hai bên thống nhất một bộ tham số miền gồm 6 đại lượng:
$$D = (p, a, b, G, n, h)$$

Trong đồ án này, ta sử dụng đường cong chuẩn công nghiệp quốc tế **secp256k1** do tổ chức *Standards for Efficient Cryptography Group* (SECG) ban hành:
- **Trường nguyên tố $p$**:
  $$p = 2^{256} - 2^{32} - 977 = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F}$$
  *(Số nguyên tố Koblitz đặc biệt giúp tối ưu hóa phép chia dư modulo trên kiến trúc 32-bit và 64-bit)*.
- **Hệ số phương trình Weierstrass**:
  $$a = 0, \quad b = 7 \implies y^2 \equiv x^3 + 7 \pmod p$$
- **Tọa độ điểm cơ sở $G = (G_x, G_y)$**:
  $$G_x = \text{0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798}$$
  $$G_y = \text{0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8}$$
- **Bậc nguyên tố của nhóm con $n$**:
  $$n = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}$$
- **Hệ số đồng bậc $h$**:
  $$h = 1$$

### 3.2. Quy trình sinh cặp khóa (Key Generation)
1. **Sinh khóa riêng bí mật ($d$)**:
   - Sử dụng bộ sinh số ngẫu nhiên an toàn mật mã của hệ điều hành (`secrets.randbelow` trích xuất entropy từ `/dev/urandom` hoặc `CryptGenRandom`).
   - Chọn một số nguyên ngẫu nhiên $d$ nằm trong khoảng:
     $$1 \le d \le n - 1$$
   - Khóa riêng $d$ được lưu trữ bí mật tuyệt đối bên trong thiết bị an toàn (Hardware Security Module - HSM hoặc Secure Enclave).
2. **Tính khóa công khai ($Q$)**:
   - Áp dụng thuật toán Double-and-Add nhân điểm cơ sở $G$ với $d$:
     $$Q = d \cdot G$$
   - Kết quả $Q = (Q_x, Q_y)$ là một điểm affine thuộc đường cong $E(\mathbb{F}_p)$.
   - Khóa công khai $Q$ được công bố rộng rãi trên mạng internet, đưa vào chứng thư số X.509 hoặc băm thành địa chỉ ví tiền mã hóa.

### 3.3. Quy trình tạo chữ ký số (Signature Generation)
Đầu vào: Thông điệp cần ký $m$, khóa riêng $d$, bộ tham số miền đường cong.  
Đầu ra: Cặp chữ ký số $(r, s)$.

Các bước thực hiện chi tiết:
1. **Băm thông điệp**:
   - Truyền $m$ qua hàm băm an toàn SHA-256 (tự viết từ module `sha256.py`):
     $$e = \text{SHA-256}(m)$$
   - Chuyển mảng 32 byte băm thành số nguyên lớn $z$. Nếu độ dài bit của mã băm lớn hơn độ dài bit của $n$, thực hiện cắt bit lấy $L_n$ bit cao nhất ($L_n = \lceil \log_2 n \rceil$). Với secp256k1 và SHA-256, cả hai đều có độ dài 256 bit nên $z = e$.
2. **Chọn số ngẫu nhiên tạm thời ($k$ - Ephemeral Nonce)**:
   - Chọn một số nguyên ngẫu nhiên bí mật $k$ thỏa mãn $1 \le k \le n - 1$.
   - **Yêu cầu an toàn sống còn**: $k$ phải là số ngẫu nhiên mới hoàn toàn cho mỗi lần ký, không dự đoán được và không bao giờ được lặp lại.
3. **Tính điểm tạm thời trên đường cong**:
   - Thực hiện nhân vô hướng:
     $$R = (x_1, y_1) = k \cdot G$$
4. **Tính thành phần chữ ký thứ nhất ($r$)**:
   - Lấy hoành độ $x_1$ modulo theo bậc nhóm $n$:
     $$r = x_1 \bmod n$$
   - Nếu $r = 0$, hủy bỏ $k$ và quay lại bước 2 chọn giá trị $k$ khác (vì nếu $r = 0$, chữ ký không chứa thông tin về khóa riêng).
5. **Tính thành phần chữ ký thứ hai ($s$)**:
   - Tính nghịch đảo nhân của $k$ theo modulo $n$: $k^{-1} \pmod n$ bằng thuật toán Euclid mở rộng.
   - Tính giá trị $s$:
     $$s = k^{-1} \cdot (z + r \cdot d) \pmod n$$
   - Nếu $s = 0$, hủy bỏ và quay lại bước 2 chọn $k$ khác (vì nếu $s = 0$, người xác minh không thể tính được nghịch đảo $s^{-1} \pmod n$).
6. **Xuất chữ ký**:
   - Trả về cặp số nguyên $(r, s)$ làm chữ ký số của thông điệp $m$.

### 3.4. Quy trình xác minh chữ ký số (Signature Verification)
Đầu vào: Thông điệp nhận được $m$, cặp chữ ký $(r, s)$, khóa công khai của người gửi $Q$.  
Đầu ra: Kết quả nhị phân (Chấp nhận - `True` hoặc Bác bỏ - `False`).

Các bước kiểm tra và tính toán:
1. **Kiểm tra tính hợp lệ của khóa công khai $Q$**:
   - Xác nhận $Q \neq \mathcal{O}$ (không phải điểm vô cực).
   - Xác nhận $Q$ thỏa mãn phương trình đường cong: $Q_y^2 \equiv Q_x^3 + a Q_x + b \pmod p$.
   - Xác nhận $n \cdot Q = \mathcal{O}$ (khóa công khai nằm trong nhóm con sinh bởi $G$).
   - Nếu bất kỳ điều kiện nào không thỏa, từ chối chữ ký ngay lập tức.
2. **Kiểm tra biên độ của cặp chữ ký $(r, s)$**:
   - Kiểm tra chặt chẽ:
     $$1 \le r \le n - 1 \quad \text{và} \quad 1 \le s \le n - 1$$
   - Nếu vi phạm, tuyên bố chữ ký không hợp lệ và dừng quy trình.
3. **Băm thông điệp nhận được**:
   - Tính $z = \text{SHA-256}(m)$ tương tự quy trình ký.
4. **Tính nghịch đảo nhân của $s$**:
   - Áp dụng Euclid mở rộng tìm $w$:
     $$w = s^{-1} \pmod n$$
5. **Tính các trọng số kết hợp tuyến tính ($u_1, u_2$)**:
   $$u_1 = (z \cdot w) \pmod n$$
   $$u_2 = (r \cdot w) \pmod n$$
6. **Khôi phục điểm kiểm chứng $P$ trên đường cong**:
   - Thực hiện hai phép nhân vô hướng và một phép cộng điểm:
     $$P = (x_P, y_P) = u_1 \cdot G + u_2 \cdot Q$$
7. **Đưa ra phán quyết xác minh**:
   - Nếu $P = \mathcal{O}$ $\implies$ Chữ ký **KHÔNG HỢP LỆ**.
   - Ngược lại, so sánh hoành độ $x_P$ modulo $n$ với giá trị $r$:
     $$\text{Chữ ký HỢP LỆ} \iff x_P \equiv r \pmod n$$
     $$\text{Chữ ký BỊ GIẢ MẠO} \iff x_P \not\equiv r \pmod n$$

### 3.5. Chứng minh toán học chặt chẽ tính đúng đắn của giải thuật xác minh
Để chứng minh rằng một chữ ký được tạo ra đúng luật luôn luôn vượt qua quy trình xác minh ($x_P \equiv r \pmod n$), ta tiến hành biến đổi đại số hình học như sau:

Từ công thức sinh thành phần $s$ ở bước ký:
$$s \equiv k^{-1}(z + r \cdot d) \pmod n$$

Nhân cả hai vế với $k$ và với $s^{-1} = w \pmod n$:
$$k \equiv s^{-1}(z + r \cdot d) \equiv w(z + r \cdot d) \pmod n$$
$$k \equiv (z \cdot w) + (r \cdot w) \cdot d \equiv u_1 + u_2 \cdot d \pmod n$$

Nhân vô hướng cả hai vế của phương trình đồng dư với điểm cơ sở $G$:
$$k \cdot G = (u_1 + u_2 \cdot d) \cdot G$$

Do nhóm $\langle G \rangle$ có bậc $n$ ($n \cdot G = \mathcal{O}$), phép nhân vô hướng tương thích với phép đồng dư modulo $n$. Tách theo tính phân phối của phép cộng trên nhóm Abel:
$$k \cdot G = u_1 \cdot G + u_2 \cdot (d \cdot G)$$

Theo định nghĩa, ta có:
- $k \cdot G = R = (x_1, y_1)$ (điểm tạm thời lúc ký, có $x_1 \bmod n = r$).
- $d \cdot G = Q$ (khóa công khai của người ký).

Thay vào biểu thức:
$$R = u_1 \cdot G + u_2 \cdot Q$$

Mặt khác, trong quy trình xác minh, người kiểm tra tính điểm:
$$P = u_1 \cdot G + u_2 \cdot Q$$

Do đó, ta có đẳng thức hình học tuyệt đối:
$$P = R = (x_1, y_1)$$

Suy ra hoành độ của điểm kiểm chứng $x_P$ chính là $x_1$:
$$x_P \equiv x_1 \equiv r \pmod n \quad (\text{Điều phải chứng minh - Q.E.D})$$

---

## Mục 4. Các giả định an toàn, tính chất bảo mật và các hình thức tấn công đã biết

### 4.1. Các giả định an toàn mật mã nền tảng
ECDSA an toàn dựa trên hai giả định toán học cốt lõi:
1. **Giả định ECDLP**: Không tồn tại thuật toán cổ điển nào giải được bài toán logarit rời rạc trên đường cong Elliptic đã chọn trong thời gian đa thức (độ phức tạp đạt tối thiểu $O(\sqrt{n})$).
2. **Tính kháng tiền ảnh và kháng va chạm của hàm băm (SHA-256)**: Kẻ tấn công không thể tìm được hai thông điệp $m_1 \neq m_2$ sao cho $\text{SHA-256}(m_1) = \text{SHA-256}(m_2)$ để đánh tráo nội dung chữ ký.

### 4.2. Lỗ hổng tử huyệt: Tái sử dụng số ngẫu nhiên Nonce $k$ (Nonce Reuse Attack)
Đây là lỗ hổng thực thi nghiêm trọng và phổ biến nhất trong lịch sử ứng dụng ECDSA. Nếu người ký sử dụng **cùng một giá trị nonce $k$** để ký cho **hai thông điệp khác nhau** $m_1$ và $m_2$, kẻ tấn công có thể **tính toán ra khóa riêng bí mật $d$ ngay lập tức chỉ bằng vài phép tính số học cơ bản**!

#### 4.2.1. Chứng minh toán học công thức bẻ khóa
Giả sử người ký sử dụng cùng khóa riêng $d$ và cùng nonce $k$ để tạo hai chữ ký:
- Chữ ký 1 cho thông điệp $m_1$ (mã băm $z_1$): Cặp $(r, s_1)$
- Chữ ký 2 cho thông điệp $m_2$ (mã băm $z_2$): Cặp $(r, s_2)$

> [!CAUTION]
> Dấu hiệu nhận biết trên đường truyền mạng: Cả hai chữ ký đều có **cùng giá trị $r$** vì $r = (k \cdot G)_x \bmod n$.

Theo công thức ký:
$$s_1 \equiv k^{-1}(z_1 + r \cdot d) \pmod n \iff k \cdot s_1 \equiv z_1 + r \cdot d \pmod n \quad (1)$$
$$s_2 \equiv k^{-1}(z_2 + r \cdot d) \pmod n \iff k \cdot s_2 \equiv z_2 + r \cdot d \pmod n \quad (2)$$

Lấy phương trình (1) trừ phương trình (2) theo từng vế:
$$k \cdot s_1 - k \cdot s_2 \equiv (z_1 + r \cdot d) - (z_2 + r \cdot d) \pmod n$$
$$k \cdot (s_1 - s_2) \equiv z_1 - z_2 \pmod n$$

Vì $m_1 \neq m_2 \implies z_1 \not\equiv z_2 \implies s_1 \not\equiv s_2 \pmod n$. Do đó $(s_1 - s_2)$ khả nghịch trong $\mathbb{Z}_n$. Kẻ tấn công tính ngay được nonce $k$:
$$k \equiv (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod n$$

Sau khi đã giải mã được số ngẫu nhiên $k$, kẻ tấn công thay $k$ ngược lại vào phương trình (1):
$$k \cdot s_1 - z_1 \equiv r \cdot d \pmod n$$
$$d \equiv (s_1 \cdot k - z_1) \cdot r^{-1} \pmod n$$

Khóa riêng bí mật $d$ bị lộ 100%! Kẻ tấn công từ thời điểm này có thể giả mạo chữ ký của nạn nhân cho bất kỳ tài liệu hay giao dịch nào.

#### 4.2.2. Các sự kiện thảm họa an ninh mạng trong thực tế
1. **Vụ tấn công máy chơi game Sony PlayStation 3 (2010)**:
   Tại hội nghị Chaos Communication Congress (27C3) tháng 12/2010, nhóm hacker *fail0verflow* đã công bố bẻ khóa hoàn toàn hệ thống bảo vệ của máy Sony PlayStation 3. Nguyên nhân gây sốc toàn cầu: Các kỹ sư của Sony khi triển khai mã nguồn ECDSA đã chọn **một giá trị $k$ cố định duy nhất (hardcoded constant)** cho mọi lần ký các bản cập nhật phần mềm (firmware). Nhóm hacker chỉ cần thu thập hai bản cập nhật khác nhau, áp dụng công thức trên và khôi phục thành công khóa riêng chủ (Master Private Key) của Sony, cho phép người dùng chạy firmware tùy biến và cài đặt game tự do.
2. **Thảm họa ví Bitcoin trên hệ điều hành Android (Tháng 8/2013)**:
   Các ứng dụng ví Bitcoin trên nền tảng Android (Bitcoin Wallet, blockchain.info app) bị phát hiện mất trộm hàng triệu USD. Nguyên nhân bắt nguồn từ một lỗi bảo mật nghiêm trọng trong bộ sinh số ngẫu nhiên `java.security.SecureRandom` của nhân Android, khiến các thiết bị khác nhau hoặc cùng một thiết bị trong các phiên khác nhau sinh ra các giá trị $k$ trùng lặp hoặc có tính chu kỳ. Tin tặc quét trên mạng lưới Blockchain Bitcoin, tìm các giao dịch có chung giá trị $r$, áp dụng công thức bẻ khóa và rút sạch tiền trong ví các nạn nhân.

### 4.3. Tấn công Nonce thiên vị (Biased Nonce / Bleichenbacher Attack)
Nguy hiểm hơn, kẻ tấn công thậm chí **không cần $k$ phải trùng khớp hoàn toàn**. Chỉ cần bộ sinh số ngẫu nhiên bị "thiên vị" (chẳng hạn vài bit cao nhất hoặc thấp nhất của $k$ bị cố định bằng 0 do lỗi lập trình), kẻ tấn công thu thập khoảng vài chục đến vài trăm chữ ký có thể lập nên bài toán **Ẩn số (Hidden Number Problem - HNP)**. Bằng cách chuyển bài toán HNP về bài toán tìm vector ngắn nhất trên dàn (Shortest Vector Problem - SVP) và giải bằng thuật toán **Lenstra–Lenstra–Lovász (LLL)**, kẻ tấn công vẫn khôi phục chính xác khóa riêng $d$ trong vài giây!

### 4.4. Giải pháp khắc phục chuẩn mực: Deterministic ECDSA (RFC 6979)
Để loại bỏ vĩnh viễn rủi ro từ bộ sinh số ngẫu nhiên phần cứng hay lỗi phần mềm, tháng 8/2013, Thomas Pornin đã công bố tiêu chuẩn **RFC 6979** (*Deterministic Usage of the Digital Signature Algorithm and Elliptic Curve Digital Signature Algorithm*).

Triết lý của RFC 6979:
- Giá trị $k$ không được sinh ngẫu nhiên tự do mà được tính toán một cách **tất định** (*deterministic*) thông qua hàm băm dựa trên khóa HMAC-SHA256 kết hợp giữa khóa riêng $d$ và mã băm thông điệp $H(m)$:
  $$k = \text{HMAC-SHA256}(d, H(m))$$
- **Đặc tính an toàn**:
  - Đối với cùng một thông điệp $m$, chữ ký tạo ra luôn là duy nhất.
  - Đối với hai thông điệp khác nhau $m_1 \neq m_2$, giá trị $k_1$ và $k_2$ hoàn toàn độc lập, ngẫu nhiên giả và phân phối đều trên $[1, n - 1]$.
  - Kẻ tấn công không thể suy đoán được $k$ nếu không biết $d$.
  - Triệt tiêu 100% nguy cơ tái sử dụng nonce và nguy cơ rò rỉ bit của nonce.

### 4.5. Tính uốn dẻo của chữ ký (Signature Malleability - BIP-62)
Với mỗi chữ ký $(r, s)$ hợp lệ của thông điệp $m$, cặp chữ ký $(r, n - s)$ cũng là một chữ ký hoàn toàn hợp lệ cho cùng thông điệp đó:
- Chứng minh: Do $s^{-1} \equiv -(n - s)^{-1} \pmod n$, nên $u_1' \equiv -u_1$ và $u_2' \equiv -u_2$. Điểm kiểm chứng $P' = -u_1 G - u_2 Q = -(u_1 G + u_2 Q) = -P = (x_P, -y_P \pmod p)$. Tọa độ hoành độ $x_{P'} = x_P \equiv r \pmod n$ vẫn giữ nguyên không đổi!
- Điều này cho phép kẻ trung gian trên đường truyền thay đổi chữ ký từ $(r, s)$ thành $(r, n - s)$, làm thay đổi mã hash của giao dịch (Transaction ID) trong mạng Bitcoin mà không cần biết khóa riêng.
- **Giải pháp**: Chuẩn **BIP-62** quy định chữ ký chỉ được coi là chuẩn tắc (*canonical*) nếu $s \le \frac{n - 1}{2}$. Nếu $s > \frac{n - 1}{2}$, người ký bắt buộc phải chuyển sang $s' = n - s$.

### 4.6. Tấn công kênh kề (Side-Channel Attacks) và Nguy cơ Điện toán Lượng tử
1. **Tấn công thời gian (Timing Attacks)**:
   Thuật toán Double-and-Add cơ bản có thời gian thực thi phụ thuộc vào số lượng bit 1 của số nhân $k$. Kẻ tấn công đo thời gian thực thi phép ký qua mạng có thể lần lượt trích xuất từng bit của $k$ và $d$.
   - **Giải pháp**: Sử dụng thuật toán Montgomery Ladder hoặc cấu trúc tính toán thời gian hằng số (*Constant-time arithmetic*).
2. **Nguy cơ Điện toán Lượng tử (Quantum Threat)**:
   Trên máy tính lượng tử tương lai đủ mạnh, **Thuật toán Shor (1994)** có khả năng giải quyết bài toán logarit rời rạc ECDLP trong thời gian đa thức:
   $$\mathcal{O}((\log_2 n)^3)$$
   Điều này đồng nghĩa với việc toàn bộ hệ thống ECDSA (cũng như RSA và DSA) sẽ bị phá vỡ hoàn toàn khi máy tính lượng tử với hàng ngàn qubit logic ra đời. Do đó, viện NIST hiện đang tích cực chuẩn hóa các thuật toán chữ ký số **Hậu lượng tử (Post-Quantum Cryptography - PQC)** dựa trên mạng tinh thể (*lattice-based*) như ML-DSA (Dilithium) và hàm băm trạng thái như SLH-DSA (SPHINCS+).

---

## Mục 5. Ưu điểm, hạn chế và ứng dụng thực tế

### 5.1. Bảng so sánh toàn diện giữa ECDSA, RSA và DSA
Bảng dưới đây tổng hợp đánh giá theo tiêu chuẩn khuyến nghị an toàn mật mã của NIST SP 800-57 Part 1 Rev. 5:

| Thuộc tính so sánh | ECDSA (secp256k1 / P-256) | RSA (2048-bit / 3072-bit) | DSA (2048-bit, q=224-bit) |
| :--- | :--- | :--- | :--- |
| **Cơ sở toán học** | Bài toán Logarit rời rạc đường cong Elliptic (ECDLP) | Bài toán Phân tích thừa số nguyên tố lớn (IFP) | Bài toán Logarit rời rạc trên trường nguyên $\mathbb{Z}_p^*$ (DLP) |
| **Độ an toàn tương đương** | **128-bit an toàn** (NIST Security Level) | RSA 2048-bit: **112-bit**<br/>RSA 3072-bit: **128-bit** | DSA 2048-bit: **112-bit** |
| **Kích thước khóa riêng** | **32 bytes** (256 bits) | 256 bytes (2048-bit) / **384 bytes** (3072-bit) | 28 bytes (224-bit) |
| **Kích thước khóa công khai** | **64 bytes** (chưa nén) hoặc **33 bytes** (nén) | 256 bytes (2048-bit) / **384 bytes** (3072-bit) | 256 bytes (2048-bit) |
| **Kích thước chữ ký** | **64 bytes** (Cặp $(r, s)$, mỗi số 32 bytes) | **256 bytes** (2048-bit) / **384 bytes** (3072-bit) | ~56 bytes (Cặp $(r, s)$, mỗi số 28 bytes) |
| **Tốc độ sinh khóa** | **Cực nhanh** ($< 25 \text{ ms}$ trên Python thuần) | Rất chậm (phải tìm 2 số nguyên tố lớn ngẫu nhiên) | Chậm (phải tìm số nguyên tố $p, q$) |
| **Tốc độ tạo chữ ký** | **Rất nhanh** (chỉ 1 phép nhân vô hướng $k \cdot G$) | Chậm (lũy thừa modulo số mũ lớn $d$) | Tương đương ECDSA |
| **Tốc độ xác minh** | Trung bình (2 phép nhân vô hướng $u_1 G + u_2 Q$) | **Cực nhanh** (số mũ nhỏ $e = 65537$) | Tương đương ECDSA |
| **Tiêu thụ năng lượng** | **Rất thấp** (tối ưu cho thiết bị nhúng, thẻ chip) | Cao (tiêu hao pin lớn trên IoT) | Trung bình |
| **Độ nhạy cảm với Nonce** | **Cực kỳ nguy hiểm** (lộ hoặc trùng $k \implies$ mất khóa) | Không phụ thuộc vào Nonce khi ký chuẩn | Cực kỳ nguy hiểm (tương tự ECDSA) |

```mermaid
xychart-beta
    title "So sánh kích thước chữ ký số (Bytes) - Mức an toàn 128-bit"
    x-axis ["ECDSA (256-bit)", "DSA (2048-bit)", "RSA (3072-bit)", "RSA (4096-bit)"]
    y-axis "Kích thước chữ ký (Bytes)" 0 --> 550
    bar [64, 56, 384, 512]
```

### 5.2. Các ứng dụng thực tế quy mô lớn
1. **Công nghệ Blockchain và Tiền mã hóa phi tập trung**:
   - **Bitcoin & Ethereum**: Sử dụng đường cong **secp256k1** kết hợp giải thuật ECDSA để ký các giao dịch chuyển tiền. Khóa công khai $Q$ được băm qua SHA-256 và RIPEMD-160 (đối với Bitcoin) hoặc Keccak-256 (đối với Ethereum) để tạo ra địa chỉ ví của người dùng.
   - Tính nhỏ gọn của chữ ký ECDSA (64 byte) đóng vai trò quyết định giúp mạng Blockchain tiết kiệm dung lượng lưu trữ phân tán của mỗi khối (Block Size).
2. **Giao thức Bảo mật Tầng Giao vận (TLS 1.3 / HTTPS)**:
   - Các chứng chỉ số X.509 hiện đại của các tập đoàn công nghệ lớn (Google, Cloudflare, Apple) đều chuyển đổi từ RSA sang **ECDSA trên đường cong NIST P-256 (secp256r1)**.
   - Giúp giảm độ trễ bắt tay mạng (Handshake latency) khi truy cập web trên điện thoại thông minh và thiết bị mạng di động.
3. **Căn cước công dân gắn chip và Hộ chiếu điện tử (e-Passport)**:
   - Chuẩn quốc tế ICAO 9303 quy định chip không tiếp xúc (NFC) trong hộ chiếu điện tử lưu trữ chữ ký số ECDSA của cơ quan xuất nhập cảnh quốc gia nhằm chống làm giả giấy tờ tùy thân.
4. **Bảo mật thiết bị IoT, Ô tô thông minh và Cập nhật Firmware (Secure Boot)**:
   - Các vi điều khiển của Apple (Secure Enclave), chip Google Titan M trong điện thoại Pixel, và hệ thống ECU ô tô sử dụng ECDSA để xác thực chữ ký của hệ điều hành trước khi khởi động máy.

---

## Mục 6. Ví dụ tính tay hoàn chỉnh với tham số đường cong số nhỏ (Toy Curve trên $\mathbb{F}_{17}$)

Để minh họa nguyên lý toán học vận hành tường minh của ECDSA mà không bị che khuất bởi các số nguyên 256-bit khổng lồ, ta thiết lập một đường cong số nhỏ (*Toy Elliptic Curve*) trên trường hữu hạn $\mathbb{F}_{17}$.

### 6.1. Thiết lập các tham số đường cong
- Số nguyên tố: $p = 17$.
- Các hệ số: $a = 2, b = 2 \implies y^2 \equiv x^3 + 2x + 2 \pmod{17}$.
- Kiểm tra điều kiện không suy biến:
  $$\Delta = 4a^3 + 27b^2 = 4(2^3) + 27(2^2) = 32 + 108 = 140 \equiv 4 \not\equiv 0 \pmod{17} \quad (\text{Thỏa mãn!})$$
- Bảng liệt kê toàn bộ các điểm thuộc đường cong:
  Bằng cách duyệt $x \in \{0, 1, \dots, 16\}$, ta tìm được đúng 18 điểm affine thỏa mãn phương trình:
  $$(0, 6), (0, 11), (3, 1), (3, 16), (5, 1), (5, 16), (6, 3), (6, 14), (7, 6), (7, 11),$$
  $$(9, 1), (9, 16), (10, 6), (10, 11), (13, 7), (13, 10), (16, 4), (16, 13)$$
  Cộng thêm điểm vô cực $\mathcal{O}$, tổng số điểm của nhóm là:
  $$\#E(\mathbb{F}_{17}) = 18 + 1 = 19$$
- Bậc của nhóm là $n = 19$, là một **số nguyên tố**. Do đó mọi điểm khác $\mathcal{O}$ đều là phần tử sinh với hệ số đồng bậc $h = 1$.
- Ta chọn **Điểm cơ sở sinh**:
  $$G = (5, 1)$$
  *(Kiểm tra: $y^2 = 1^2 = 1$; $x^3 + 2x + 2 = 5^3 + 2(5) + 2 = 125 + 10 + 2 = 137 \equiv 1 \pmod{17} \implies G \in E(\mathbb{F}_{17})$)*.

---

### 6.2. Bước 1: Sinh cặp khóa (Key Generation)
1. Chọn khóa riêng bí mật:
   $$d = 7 \quad (1 \le d < 19)$$
2. Tính khóa công khai $Q = d \cdot G = 7 \cdot (5, 1)$:
   Áp dụng thuật toán Double-and-Add với $7 = 111_2$:
   - **Tính $2G = G + G$** (Point Doubling tại $G(5, 1)$):
     $$\lambda_1 = \frac{3x_1^2 + a}{2y_1} = \frac{3(5^2) + 2}{2(1)} = \frac{75 + 2}{2} = \frac{77}{2} \equiv \frac{9}{2} \pmod{17}$$
     Nghịch đảo của 2 modulo 17 là $2^{-1} \equiv 9 \pmod{17}$ (vì $2 \times 9 = 18 \equiv 1$).
     $$\lambda_1 = (9 \times 9) \bmod 17 = 81 \bmod 17 = 13$$
     $$x_{2G} = \lambda_1^2 - 2x_1 = 13^2 - 2(5) = 169 - 10 = 159 \equiv 6 \pmod{17}$$
     $$y_{2G} = \lambda_1(x_1 - x_{2G}) - y_1 = 13(5 - 6) - 1 = -13 - 1 = -14 \equiv 3 \pmod{17}$$
     $$\implies 2G = (6, 3)$$
   - **Tính $3G = 2G + G$** (Point Addition giữa $(6, 3)$ và $(5, 1)$):
     $$\lambda_2 = \frac{1 - 3}{5 - 6} = \frac{-2}{-1} = 2$$
     $$x_{3G} = 2^2 - 6 - 5 = 4 - 11 = -7 \equiv 10 \pmod{17}$$
     $$y_{3G} = 2(6 - 10) - 3 = 2(-4) - 3 = -11 \equiv 6 \pmod{17}$$
     $$\implies 3G = (10, 6)$$
   - **Tính $6G = 2 \cdot (3G)$** (Point Doubling tại $(10, 6)$):
     $$\lambda_3 = \frac{3(10^2) + 2}{2(6)} = \frac{302}{12} \equiv \frac{13}{12} \pmod{17}$$
     Nghịch đảo của 12 modulo 17 là $12^{-1} \equiv 10 \pmod{17}$ (vì $12 \times 10 = 120 = 7 \times 17 + 1$).
     $$\lambda_3 = (13 \times 10) \bmod 17 = 130 \bmod 17 = 11$$
     $$x_{6G} = 11^2 - 2(10) = 121 - 20 = 101 \equiv 16 \pmod{17}$$
     $$y_{6G} = 11(10 - 16) - 6 = 11(-6) - 6 = -72 \equiv 13 \pmod{17}$$
     $$\implies 6G = (16, 13)$$
   - **Tính $7G = 6G + G$** (Point Addition giữa $(16, 13)$ và $(5, 1)$):
     $$\lambda_4 = \frac{1 - 13}{5 - 16} = \frac{-12}{-11} = \frac{12}{11} \pmod{17}$$
     Nghịch đảo của 11 modulo 17 là $11^{-1} \equiv 14 \pmod{17}$ (vì $11 \times 14 = 154 = 9 \times 17 + 1$).
     $$\lambda_4 = (12 \times 14) \bmod 17 = 168 \bmod 17 = 15$$
     $$x_{7G} = 15^2 - 16 - 5 = 225 - 21 = 204 \equiv 0 \pmod{17}$$
     $$y_{7G} = 15(16 - 0) - 13 = 240 - 13 = 227 \equiv 6 \pmod{17}$$
     $$\implies Q = 7G = (0, 6)$$

Khóa công khai thu được là điểm:
$$Q = (0, 6)$$

---

### 6.3. Bước 2: Tạo chữ ký số (Signature Generation)
Giả sử thông điệp sau khi băm có giá trị số nguyên:
$$z = 10$$
1. Chọn số ngẫu nhiên nonce bí mật:
   $$k = 13 \quad (1 \le k < 19)$$
2. Tính điểm tạm thời $R = k \cdot G = 13 \cdot (5, 1)$:
   - Qua các bước tính tương tự Double-and-Add, ta thu được:
     $$R = (16, 4)$$
   *(Kiểm tra: $4^2 = 16$; $16^3 + 2(16) + 2 = 4096 + 32 + 2 = 4130 \equiv 16 \pmod{17} \implies R \in E(\mathbb{F}_{17})$)*.
3. Tính thành phần $r$:
   $$r = x_R \bmod n = 16 \bmod 19 = 16 \neq 0$$
4. Tính nghịch đảo của $k$ theo modulo $n = 19$:
   Áp dụng Euclid mở rộng tìm $13^{-1} \pmod{19}$:
   $$19 = 1 \times 13 + 6$$
   $$13 = 2 \times 6 + 1 \implies 1 = 13 - 2 \times 6 = 13 - 2 \times (19 - 13) = 3 \times 13 - 2 \times 19$$
   $$\implies 13^{-1} \equiv 3 \pmod{19} \quad (\text{vì } 13 \times 3 = 39 = 2 \times 19 + 1)$$
5. Tính thành phần $s$:
   $$s = k^{-1} \cdot (z + r \cdot d) \pmod n$$
   $$s = 3 \cdot (10 + 16 \times 7) \pmod{19}$$
   $$s = 3 \cdot (10 + 112) \pmod{19} = 3 \cdot 122 \pmod{19}$$
   Ta có $122 = 6 \times 19 + 8 \equiv 8 \pmod{19}$:
   $$s = (3 \times 8) \bmod 19 = 24 \bmod 19 = 5 \neq 0$$

Cặp chữ ký số được tạo ra là:
$$(r, s) = (16, 5)$$

---

### 6.4. Bước 3: Xác minh chữ ký số (Signature Verification)
Người xác minh nhận được thông điệp có $z = 10$, chữ ký $(r, s) = (16, 5)$ và khóa công khai $Q = (0, 6)$.
1. Kiểm tra biên độ:
   $$1 \le r = 16 < 19 \quad \text{và} \quad 1 \le s = 5 < 19 \quad (\text{Hợp lệ})$$
2. Tính nghịch đảo của $s = 5$ modulo $n = 19$:
   $$w = s^{-1} \equiv 5^{-1} \pmod{19}$$
   Vì $5 \times 4 = 20 \equiv 1 \pmod{19}$, nên:
   $$w = 4$$
3. Tính các trọng số kết hợp $u_1$ và $u_2$:
   $$u_1 = (z \cdot w) \bmod 19 = (10 \times 4) \bmod 19 = 40 \bmod 19 = 2$$
   $$u_2 = (r \cdot w) \bmod 19 = (16 \times 4) \bmod 19 = 64 \bmod 19 = 7$$
4. Tính các điểm thành phần:
   - $P_1 = u_1 \cdot G = 2 \cdot (5, 1)$: Đã tính ở trên $\implies P_1 = (6, 3)$.
   - $P_2 = u_2 \cdot Q = 7 \cdot (0, 6)$:
     Ta đã biết $Q = 7G$, do đó $P_2 = 7 \cdot (7G) = 49G$.
     Vì bậc của nhóm là 19, ta lấy $49 \bmod 19 = 11$, suy ra $P_2 = 11G$.
     Tính toán đại số cho ta kết quả tọa độ:
     $$P_2 = (13, 10)$$
     *(Kiểm tra: $10^2 = 100 \equiv 15 \pmod{17}$; $13^3 + 2(13) + 2 = 2197 + 26 + 2 = 2225 \equiv 15 \pmod{17}$)*.
5. Tính điểm kiểm chứng $P = P_1 + P_2 = (6, 3) + (13, 10)$:
   Hệ số góc cát tuyến qua $(6, 3)$ và $(13, 10)$:
   $$\lambda = \frac{10 - 3}{13 - 6} = \frac{7}{7} = 1$$
   Hoành độ $x_P$:
   $$x_P = \lambda^2 - x_1 - x_2 = 1^2 - 6 - 13 = 1 - 19 = -18 \equiv 16 \pmod{17}$$
   Tung độ $y_P$:
   $$y_P = \lambda(x_1 - x_P) - y_1 = 1(6 - 16) - 3 = -10 - 3 = -13 \equiv 4 \pmod{17}$$
   $$\implies P = (16, 4)$$
6. Đối chiếu kết quả xác minh:
   $$x_P \bmod n = 16 \bmod 19 = 16$$
   So sánh với $r = 16$:
   $$x_P \equiv r \equiv 16 \pmod{19} \implies \mathbf{CHỮ\ KÝ\ HOÀN\ TOÀN\ HỢP\ LỆ!}$$

Ví dụ tính tay nhỏ này đã kiểm chứng chuẩn xác 100% từng phép cộng, nhân đôi điểm và các công thức đồng dư modulo của giải thuật ECDSA!

---

## Mục 7. Giải thích cấu trúc code `ecdsa.py` đã viết

Mã nguồn [ecdsa.py](file:///d:/HOCTAP/IS(Text)/ecdsa.py) được thiết kế theo cấu trúc module hóa phân tầng, đáp ứng triệt để yêu cầu không sử dụng bất kỳ thư viện mật mã nào bên ngoài, chỉ dựa trên thư viện chuẩn của Python (`secrets`, `time`, `math`, `typing`, `dataclasses`).

```mermaid
flowchart TD
    subgraph Layer1["Tầng 1: Số học Modulo cơ sở"]
        A["extended_gcd(a, b)"] --> B["mod_inverse(a, m)"]
    end
    subgraph Layer2["Tầng 2: Hình học & Đại số Đường cong"]
        C["Class Point (x, y, is_infinity)"]
        D["Class EllipticCurve (p, a, b, G, n, h)"]
        D --> E["point_add / point_double"]
        D --> F["scalar_mult (Double-and-Add)"]
    end
    subgraph Layer3["Tầng 3: Tích hợp Hàm băm & Chuẩn hóa"]
        G["sha256.py (bam_sha256_bytes)"] --> H["hash_message_to_int (FIPS 186-4 Truncation)"]
    end
    subgraph Layer4["Tầng 4: Giải thuật Chữ ký số ECDSA"]
        I["generate_keypair() -> (d, Q)"]
        J["sign_message() -> (r, s)"]
        K["verify_signature() -> bool"]
    end
    subgraph Layer5["Tầng 5: Thực nghiệm, Khai thác & Benchmark"]
        L["attack_nonce_reuse()"]
        M["verify_toy_curve_calculation()"]
        N["run_comprehensive_tests()"]
        O["benchmark_ecdsa_performance()"]
    end
    Layer1 --> Layer2
    Layer2 --> Layer4
    Layer3 --> Layer4
    Layer4 --> Layer5
```

### 7.1. Chi tiết các module và chức năng của từng hàm/lớp

#### 1. Lớp biểu diễn điểm `Point`
- Biểu diễn tọa độ affine $(x, y)$ dưới dạng số nguyên lớn (arbitrary-precision integer).
- Hỗ trợ biểu diễn điểm vô cực $\mathcal{O}$ bằng thuộc tính `is_infinity` (khi $x$ và $y$ đều mang giá trị `None`).
- Triển khai `__repr__` và `to_short_str()` hỗ trợ xuất chuỗi hexa thẩm mỹ cho việc ghi log và in báo cáo.

#### 2. Lớp đường cong Elliptic `EllipticCurve`
- Khởi tạo với đầy đủ bộ tham số miền $(p, a, b, G, n, h)$. Tự động kiểm tra điều kiện không suy biến $4a^3 + 27b^2 \not\equiv 0 \pmod p$ và xác nhận điểm sinh $G$ thuộc đường cong ngay khi khởi tạo.
- `point_add(P, Q)`: Xử lý toàn diện mọi trường hợp biên hình học:
  - Một trong hai điểm là $\mathcal{O}$.
  - Hai điểm đối xứng qua trục $Ox$ ($P = -Q$) trả về $\mathcal{O}$.
  - Hai điểm trùng nhau ($P = Q$) chuyển hướng sang công thức tiếp tuyến nhân đôi điểm (Point Doubling).
  - Hai điểm phân biệt áp dụng công thức cát tuyến (Point Addition).
- `scalar_mult(k, P)`: Cài đặt thuật toán Double-and-Add tối ưu, dịch phải nhị phân `k >>= 1` và kiểm tra bit `k & 1`.

#### 3. Tích hợp trực tiếp module băm `sha256.py`
- Tích hợp hàm `bam_sha256_bytes` từ file [sha256.py](file:///d:/HOCTAP/IS(Text)/sha256.py) cùng thư mục.
- Hàm `hash_message_to_int`: Chuyển đổi chuỗi văn bản UTF-8 hoặc mảng byte thành số nguyên lớn $z$, đồng thời tự động cắt bit (*truncation*) nếu số bit của mã băm vượt quá số bit của bậc nhóm $n$ theo đặc tả của chuẩn SEC 1.

#### 4. Các hàm vận hành ECDSA
- `generate_keypair(curve)`: Sử dụng nguồn ngẫu nhiên CSPRNG `secrets.randbelow(n - 1) + 1` để đảm bảo phân phối đều tuyệt đối trên $[1, n - 1]$, tính $Q = d \cdot G$.
- `sign_message(message, private_key, curve, k_custom)`: Sinh số ngẫu nhiên nonce $k$, tính $R = k \cdot G$, $r = R_x \bmod n$, nghịch đảo $k^{-1}$, và $s = k^{-1}(z + rd) \bmod n$. Hỗ trợ tham số `k_custom` phục vụ tái lập chính xác các vector kiểm thử và ví dụ tính tay.
- `verify_signature(message, signature, public_key, curve)`: Kiểm tra toàn diện tính hợp lệ của khóa công khai $Q$ (nằm trên đường cong, khác $\mathcal{O}$, $n \cdot Q = \mathcal{O}$), kiểm tra biên $1 \le r, s < n$, tính $w, u_1, u_2$ và khôi phục điểm $P = u_1 G + u_2 Q$. Trả về `True` khi $x_P \bmod n == r$.

#### 5. Module mô phỏng tấn công và khai thác `attack_nonce_reuse`
- Thực thi chính xác đòn tấn công toán học khôi phục $k$ và $d$ khi phát hiện hai chữ ký có cùng thành phần $r$.

---

## Mục 8. Bảng đánh giá thực nghiệm, kiểm chứng tính đúng đắn, hiệu năng tính toán và kết luận

### 8.1. Kiểm chứng tính đúng đắn và an toàn mật mã (Functional & Security Tests)
Mã nguồn [ecdsa.py](file:///d:/HOCTAP/IS(Text)/ecdsa.py) đã được thực thi và vượt qua 100% các ca kiểm thử:

| STT | Kịch bản kiểm thử | Mô tả chi tiết dữ liệu thử nghiệm | Kết quả mong đợi | Kết quả thực tế | Đánh giá |
| :---: | :--- | :--- | :---: | :---: | :---: |
| **TC1** | **Xác thực ví dụ tính tay** | Đường cong số nhỏ $\mathbb{F}_{17}$, $d=7, z=10, k=13$ | Chữ ký $(16, 5)$, $x_P \equiv 16$ | $(r, s)=(16, 5)$, $x_P = 16$ | **ĐẠT (PASS)** |
| **TC2** | **Chữ ký hợp lệ secp256k1** | Thông điệp tiếng Việt có dấu, khóa riêng 256-bit | `verify_signature() == True` | `True` | **ĐẠT (PASS)** |
| **TC3** | **Giả mạo thông điệp** | Thêm 1 ký tự dấu chấm `.` vào cuối chuỗi | `verify_signature() == False` | `False` | **ĐẠT (PASS)** |
| **TC4** | **Can thiệp chữ ký $(r, s)$** | Sửa đổi thành phần $r \to r + 1$ | `verify_signature() == False` | `False` | **ĐẠT (PASS)** |
| **TC5** | **Khóa công khai sai lệch** | Dùng khóa công khai của người dùng khác | `verify_signature() == False` | `False` | **ĐẠT (PASS)** |
| **TC6** | **Tấn công tái sử dụng nonce** | Ký 2 lệnh chuyển tiền với cùng nonce $k$ | Khôi phục chính xác $100\%$ khóa $d$ | $d_{khôi\ phục} == d_{gốc}$ | **ĐẠT (PASS)** |

```
[*] Minh chứng chạy thực nghiệm từ ecdsa.py:
================================================================================
VÍ DỤ TÍNH TAY VỚI THAM SỐ ĐƯỜNG CONG SỐ NHỎ (TOY CURVE TRÊN F_17)
================================================================================
[*] Phương trình: y^2 = x^3 + 2x + 2 (mod 17)
[*] Điểm sinh G = (5, 1), Bậc nhóm n = 19
[Bước 1: Sinh khóa] -> d = 7, Q = (0, 6)
[Bước 2: Tạo chữ ký số] -> z = 10, k = 13, R = (16, 4) => (r=16, s=5)
[Bước 3: Xác minh chữ ký số] -> w=4, u1=2, u2=7, P=(16, 4) => P.x mod 19 == 16 (KHỚP 100%)
=> KẾT QUẢ XÁC MINH: HỢP LỆ (TRUE - ĐẠT)
```

---

### 8.2. Đánh giá hiệu năng tính toán thực tế (Benchmark Results)
Đo đạc thực nghiệm được thực hiện trên môi trường máy tính sinh viên, ngôn ngữ Python 3.12 thuần 64-bit, thực hiện trung bình qua 30 lần chạy độc lập trên đường cong `secp256k1`:

| Thao tác nghiệp vụ | Thời gian trung bình (ms) | Thời gian nhanh nhất (ms) | Thời gian chậm nhất (ms) | Tốc độ xử lý (ops/giây) |
| :--- | :---: | :---: | :---: | :---: |
| **Sinh cặp khóa (KeyGen)** | **24.52 ms** | 22.92 ms | 30.23 ms | **40.8 ops/s** |
| **Tạo chữ ký số (Sign)** | **25.62 ms** | 23.47 ms | 36.87 ms | **39.0 ops/s** |
| **Xác minh chữ ký (Verify)** | **50.26 ms** | 47.29 ms | 54.90 ms | **19.9 ops/s** |

#### Nhận xét và phân tích chuyên sâu về hiệu năng:
1. **Tỷ lệ thời gian giữa Xác minh (Verify) và Ký (Sign)**:
   - Dữ liệu thực nghiệm cho thấy thời gian hàm `Verify` ($\approx 50.26 \text{ ms}$) gấp xấp xỉ **2 lần** thời gian của hàm `Sign` ($\approx 25.62 \text{ ms}$).
   - **Lý giải nguyên lý tính toán**:
     - Trong quá trình Ký (`Sign`), chương trình chỉ thực hiện **duy nhất 1 phép nhân vô hướng** $R = k \cdot G$.
     - Trong quá trình Xác minh (`Verify`), chương trình bắt buộc phải thực hiện **2 phép nhân vô hướng độc lập** $u_1 \cdot G$ và $u_2 \cdot Q$, sau đó thực hiện thêm một phép cộng điểm $P = (u_1 \cdot G) + (u_2 \cdot Q)$. Do phép nhân vô hướng chiếm tới hơn 95% tổng thời gian tính toán của đường cong Elliptic, thời gian xác minh tự nhiên gấp đôi thời gian ký.
     *(Trong các thư viện tối ưu hóa chuyên sâu như `libsecp256k1` bằng ngôn ngữ C, kỹ thuật nhân vô hướng đôi Strauss-Shamir Trick có thể rút ngắn thời gian xác minh xuống chỉ còn gấp khoảng 1.3 lần)*.
2. **Hiệu năng Python thuần**:
   - Dù không sử dụng bất kỳ thư viện C tăng tốc hay thư viện mật mã có sẵn nào, chương trình Python thuần vẫn đạt tốc độ xấp xỉ **40 chữ ký/giây**, hoàn toàn đáp ứng tốt cho các ứng dụng xác thực, ví tiền mã hóa cá nhân và các hệ thống phân tán quy mô vừa.

---

### 8.3. Kết luận đồ án và Khuyến nghị triển khai kỹ thuật
1. **Kết luận**:
   - Đồ án đã hiện thực hóa trọn vẹn và thành công hệ thống chữ ký số **ECDSA từ nguyên lý gốc (From First Principles)** trên đường cong tiêu chuẩn **secp256k1**, kết nối trực tiếp với module băm tự viết **SHA-256**.
   - Chứng minh được tính ưu việt của mật mã đường cong Elliptic về kích thước khóa, độ an toàn và kích thước chữ ký so với các hệ mật mã cổ điển như RSA và DSA.
   - Làm rõ cơ chế tấn công tái sử dụng nonce và kiểm chứng bằng code thực nghiệm, làm nổi bật tầm quan trọng của nguồn sinh entropy và chuẩn hóa RFC 6979.
2. **Khuyến nghị triển khai trong môi trường sản xuất (Production)**:
   - **Bắt buộc áp dụng RFC 6979**: Luôn sử dụng Deterministic ECDSA để loại bỏ hoàn toàn nguy cơ rò rỉ khóa riêng do lỗi bộ sinh số ngẫu nhiên CSPRNG.
   - **Chuẩn hóa chữ ký Low-S (BIP-62)**: Luôn kiểm tra và ép $s \le (n - 1) / 2$ để triệt tiêu lỗ hổng uốn dẻo chữ ký (Signature Malleability) trong các hệ thống tài chính và Blockchain.
   - **Chống tấn công kênh kề**: Khi biên dịch trên phần cứng nhúng, cần triển khai thuật toán nhân vô hướng thời gian hằng số (Constant-time Double-and-Add hoặc Montgomery Ladder) để chống lại các đòn tấn công phân tích thời gian và đo điện năng tiêu thụ.
