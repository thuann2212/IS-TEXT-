# BÁO CÁO ĐỒ ÁN AN TOÀN THÔNG TIN: MẬT MÃ KHÓA BẤT ĐỐI XỨNG RSA

- **Họ và tên sinh viên**: Trần Gia Thuận
- **Chữ số cuối SID**: 3 ($3 \bmod 3 = 0 \rightarrow$ Phân công đề tài: **Mật mã bất đối xứng RSA**)
- **Ngôn ngữ & Môi trường thực thi**: Python thuần 3.12 (cài đặt từ nguyên lý gốc — *From First Principles*, không sử dụng thư viện mật mã có sẵn)
- **Mã nguồn thực nghiệm**: [rsa.py](../algorithms/rsa.py) (đối chiếu trong hệ sinh thái đồ án cùng [sha256.py](../algorithms/sha256.py), [aes128.py](../algorithms/aes128.py) và [ecdsa.py](../algorithms/ecdsa.py))

---

## Mục 1. Bối cảnh lịch sử (Rivest, Shamir, Adleman) và động lực thiết kế mật mã khóa công khai

### 1.1. Khủng hoảng phân phối khóa của mật mã đối xứng và tiền đề Diffie-Hellman (1976)
Trước năm 1976, toàn bộ nền tảng mật mã học nhân loại đều vận hành theo mô hình **mật mã khóa đối xứng** (*Symmetric-key Cryptography*), điển hình như chuẩn mã hóa dữ liệu DES (*Data Encryption Standard*). Trong mô hình này, hai bên truyền thông (Alice và Bob) buộc phải cùng chia sẻ một khóa bí mật duy nhất $K$ dùng chung cho cả quá trình mã hóa lẫn giải mã. Mô hình này làm nảy sinh một nghịch lý nghiêm trọng:
1. **Khủng hoảng phân phối khóa (Key Distribution Problem)**: Để truyền thông an toàn, Alice và Bob cần trao đổi khóa bí mật $K$. Nhưng để trao đổi $K$ an toàn, họ lại cần một kênh bảo mật có sẵn. Trong các mạng truyền thông quy mô lớn toàn cầu, việc gặp mặt trực tiếp hoặc sử dụng giao liên tín nhiệm để vận chuyển khóa bí mật là bất khả thi về mặt kinh tế lẫn kỹ thuật.
2. **Bùng nổ số lượng khóa ($O(N^2)$)**: Trong một mạng lưới gồm $N$ người dùng muốn giao tiếp bí mật từng đôi một, tổng số cặp khóa bí mật cần thiết lập và lưu trữ an toàn là:
   $$\frac{N(N - 1)}{2} = O(N^2)$$
   Khi $N = 1.000.000$ người, hệ thống cần quản lý tới gần 500 tỷ khóa bí mật. Nếu bất kỳ một điểm lưu trữ nào bị lộ, toàn bộ các kênh liên quan đều bị tổn thương.
3. **Thiếu khả năng chống chối bỏ (Non-repudiation)**: Do cả Alice và Bob đều nắm giữ cùng một khóa $K$, Alice hoàn toàn có thể tạo ra một thông điệp rồi tuyên bố rằng Bob đã gửi thông điệp đó, hoặc ngược lại Bob có thể phủ nhận việc mình đã gửi thông điệp.

Tháng 11/1976, hai nhà nghiên cứu tại Đại học Stanford là **Whitfield Diffie** và **Martin Hellman** đã xuất bản bài báo mang tính cách mạng *"New Directions in Cryptography"* trên tạp chí *IEEE Transactions on Information Theory*. Lần đầu tiên, khái niệm **Mật mã khóa công khai** (*Public-Key Cryptography*) được đề xuất:
- Mỗi thực thể sở hữu một cặp khóa riêng biệt: một **khóa công khai ($PK$)** được phổ biến rộng rãi cho toàn thế giới và một **khóa bí mật ($SK$)** được chủ sở hữu lưu giữ tuyệt đối.
- Phép mã hóa vận hành dựa trên khái niệm **Hàm một chiều có cửa sập (Trapdoor One-Way Function - TOFU)**: một hàm số $f$ có tính chất dễ tính theo chiều thuận $y = f(x)$, nhưng cực kỳ khó tìm lại $x = f^{-1}(y)$ nếu không có thông tin bổ trợ bí mật (gọi là "cửa sập" - *trapdoor*). Khi có thông tin cửa sập $k_{trap}$, việc tính toán $f^{-1}(y)$ lại trở nên vô cùng dễ dàng.

Tuy nhiên, giao thức Diffie-Hellman (DH) công bố năm 1976 mới chỉ dừng lại ở cơ chế thỏa thuận khóa chung (*Key Exchange*), chưa phải là một hệ mật mã hoàn chỉnh có khả năng mã hóa thông điệp trực tiếp cũng như ký số điện tử.

```mermaid
flowchart LR
    A["Bản rõ (Plaintext) m"] --> B["Khóa công khai PK: Hàm một chiều f(m)"]
    B --> C["Bản mã (Ciphertext) c"]
    C --> D["Kẻ thù không có cửa sập: Giải bài toán IFP => BẤT KHẢ THI"]
    C --> E["Khóa bí mật SK ('Cửa sập' Trapdoor) => Giải mã đa thức"]
    E --> F["Bản rõ ban đầu m"]
```

### 1.2. Phát minh đột phá của Rivest, Shamir và Adleman tại MIT (1977)
Nhận thấy khoảng trống lý thuyết mà Diffie và Hellman để lại, ba nhà khoa học tại Viện Công nghệ Massachusetts (MIT) gồm:
- **Ron Rivest** (nhà khoa học máy tính chuyên về cấu trúc dữ liệu và giải thuật),
- **Adi Shamir** (nhà mật mã học có tư duy giải thuật xuất sắc),
- **Leonard Adleman** (nhà toán học chuyên sâu về lý thuyết số và độ phức tạp tính toán),

đã phối hợp nghiên cứu từ đầu năm 1977. Rivest và Shamir liên tục đề xuất các cấu trúc toán học tiềm năng, trong khi Adleman đảm nhận vai trò phản biện và tìm lỗ hổng tấn công (*cryptanalysis*). Sau hàng chục ý tưởng bị bác bỏ, vào tháng 4 năm 1977, sau một đêm dài suy ngẫm, Ron Rivest đã hình thành cấu trúc hoàn chỉnh dựa trên bài toán phân tích thừa số nguyên tố lớn. Leonard Adleman đã chứng minh tính vững chắc của cấu trúc này.

Tháng 2 năm 1978, bài báo chính thức mang tên *"A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"* được xuất bản trên tạp chí uy tín *Communications of the ACM* (Vol. 21, No. 2), khai sinh ra thuật toán **RSA** (viết tắt từ chữ cái đầu của **R**ivest, **S**hamir, **A**dleman). 

*(Ghi chú lịch sử: Năm 1997, chính phủ Anh giải mật tài liệu cho thấy nhà toán học Clifford Cocks tại cơ quan tình báo GCHQ đã từng mô tả một ý tưởng tương tự vào năm 1973 nhưng không được công bố và không có phần cứng đủ mạnh để hiện thực hóa vào thời điểm đó).*

### 1.3. Động lực thiết kế và triết lý cốt lõi của RSA
Triết lý thiết kế của RSA dựa trên hai động lực then chốt:
1. **Thống nhất hai chức năng mã hóa bí mật và ký số xác thực trong cùng một cấu trúc đối ngẫu đại số**:
   - Nếu mã hóa bằng khóa công khai $e$, chỉ người giữ khóa bí mật $d$ mới giải mã được (bảo mật thông tin - *Confidentiality*).
   - Nếu biến đổi dữ liệu bằng khóa bí mật $d$, bất kỳ ai có khóa công khai $e$ cũng có thể kiểm chứng được tính toàn vẹn và nguồn gốc của dữ liệu (chữ ký số - *Digital Signature & Non-repudiation*).
2. **Khai thác triệt để sự bất đối xứng độ phức tạp tính toán giữa phép nhân và phép phân tích thừa số nguyên tố**:
   - Cho hai số nguyên tố lớn $p$ và $q$, máy tính chỉ mất vài micro-giây để tính tích $n = p \times q$.
   - Ngược lại, chỉ cho biết $n$, các thuật toán cổ điển tiên tiến nhất hiện nay đều đòi hỏi thời gian bán hàm mũ (*sub-exponential time*) để tách ngược lại thành $p$ và $q$. Khoảng cách độ phức tạp này tạo ra một "bức tường bảo vệ" vững chắc cho an toàn thông tin toàn cầu.

---

## Mục 2. Cơ sở toán học nền tảng

### 2.1. Số học Modulo và quan hệ đồng dư
Cho số nguyên dương $n > 1$. Hai số nguyên $a$ và $b$ được gọi là **đồng dư với nhau theo modulo $n$**, ký hiệu:
$$a \equiv b \pmod n \iff n \mid (a - b) \iff a \bmod n = b \bmod n$$

Tập hợp các lớp thặng dư theo modulo $n$ lập thành vành số nguyên $\mathbb{Z}_n = \{0, 1, 2, \dots, n - 1\}$. Trong vành $\mathbb{Z}_n$:
- Phép cộng và phép nhân đều tương thích với quan hệ đồng dư:
  $$(a_1 \cdot a_2) \bmod n = \left((a_1 \bmod n) \cdot (a_2 \bmod n)\right) \bmod n$$
- Một phần tử $a \in \mathbb{Z}_n$ có nghịch đảo nhân $a^{-1}$ trong $\mathbb{Z}_n$ khi và chỉ khi $a$ nguyên tố cùng nhau với $n$, tức $\gcd(a, n) = 1$. Nhóm các phần tử khả nghịch trong $\mathbb{Z}_n$ lập thành nhóm nhân $\mathbb{Z}_n^*$.

### 2.2. Hàm số phi Euler ($\phi(n)$ - Euler's Totient Function)
Hàm phi Euler $\phi(n)$ định nghĩa số lượng các số nguyên dương trong khoảng từ $1$ đến $n$ nguyên tố cùng nhau với $n$:
$$\phi(n) = \left| \{ k \in \mathbb{Z} \mid 1 \le k \le n \text{ và } \gcd(k, n) = 1 \} \right| = |\mathbb{Z}_n^*|$$

Các tính chất số học cơ bản:
1. Nếu $p$ là số nguyên tố, toàn bộ $p - 1$ số từ $1$ đến $p - 1$ đều nguyên tố cùng nhau với $p$, do đó:
   $$\phi(p) = p - 1$$
2. Hàm $\phi(n)$ là **hàm nhân tính** (*multiplicative function*): nếu $\gcd(a, b) = 1$ thì:
   $$\phi(a \cdot b) = \phi(a) \cdot \phi(b)$$
3. **Trường hợp cốt lõi của RSA**: Modulo $n = p \cdot q$ với $p, q$ là hai số nguyên tố phân biệt ($p \neq q$):
   $$\phi(n) = \phi(p) \cdot \phi(q) = (p - 1)(q - 1) = n - (p + q - 1)$$

> [!NOTE]
> Người tạo ra khóa nắm giữ $p$ và $q$ nên tính $\phi(n) = (p - 1)(q - 1)$ chỉ trong $1$ phép trừ và $1$ phép nhân ($O(1)$). Ngược lại, kẻ thù chỉ biết $n$ muốn tính $\phi(n)$ bắt buộc phải tìm lại được $p$ và $q$, bởi vì nếu biết cả $n$ và $\phi(n)$, kẻ thù có thể giải phương trình bậc hai $X^2 - (n - \phi(n) + 1)X + n = 0$ để tìm ra $p$ và $q$ ngay lập tức!

### 2.3. Định lý nhỏ Fermat và Định lý Euler
- **Định lý nhỏ Fermat (Fermat's Little Theorem - 1640)**:
  Nếu $p$ là một số nguyên tố và số nguyên $a$ không chia hết cho $p$ ($\gcd(a, p) = 1$), thì:
  $$a^{p - 1} \equiv 1 \pmod p$$
  Nhân cả hai vế với $a$, ta có dạng tổng quát đúng với mọi số nguyên $a$:
  $$a^p \equiv a \pmod p$$

- **Định lý Euler (Euler's Totient Theorem - 1736)**:
  Mở rộng định lý nhỏ Fermat cho modulo $n$ hợp số bất kỳ: Nếu $\gcd(a, n) = 1$, thì:
  $$a^{\phi(n)} \equiv 1 \pmod n$$

- **Hệ quả cho quy trình giải mã RSA**:
  Nếu ta chọn hai số mũ $e$ và $d$ thỏa mãn đồng dư:
  $$e \cdot d \equiv 1 \pmod{\phi(n)} \iff e \cdot d = 1 + k \cdot \phi(n) \quad (k \in \mathbb{Z}^+)$$
  Thì với mọi thông điệp $m \in \mathbb{Z}_n^*$ ($\gcd(m, n) = 1$):
  $$m^{e \cdot d} = m^{1 + k \cdot \phi(n)} = m^1 \cdot \left(m^{\phi(n)}\right)^k \equiv m \cdot (1)^k \equiv m \pmod n$$
  Đây chính là chìa khóa chứng minh bản giải mã $m = c^d \bmod n$ sẽ khôi phục chính xác thông điệp bản rõ ban đầu.

### 2.4. Bài toán phân tích thừa số nguyên tố lớn (Integer Factorization Problem - IFP)
An toàn của hệ thống RSA đặt trọn vẹn trên độ phức tạp của bài toán: Cho trước số nguyên dương $n$ là tích của hai số nguyên tố lớn bí mật $p$ và $q$, tìm $p$ và $q$.
- Thuật toán vét cạn chia thử (*Trial Division*) có độ phức tạp $O(\sqrt{n}) = O(2^{k/2})$ với $k = \log_2 n$. Với khóa 2048-bit, $2^{1024}$ phép tính vượt xa tổng số nguyên tử trong vũ trụ quan sát được ($\approx 10^{80}$).
- Thuật toán phân tích tổng quát mạnh nhất hiện nay trên máy tính cổ điển là **Sàng trường số tổng quát** (**GNFS** - *General Number Field Sieve*), có độ phức tạp tính toán dạng bán hàm mũ:
  $$\mathcal{O}\left( \exp \left( \left( \sqrt[3]{\frac{64}{9}} + o(1) \right) (\ln n)^{1/3} (\ln \ln n)^{2/3} \right) \right)$$
  - Năm 1999: RSA-512 (155 chữ số thập phân) bị phá vỡ sau vài tháng tính toán phân tán.
  - Năm 2009: RSA-768 (232 chữ số thập phân) bị phân tích thành công bởi nhóm nghiên cứu quốc tế.
  - Hiện nay: Khóa RSA 1024-bit được khuyến cáo ngừng sử dụng; chuẩn công nghiệp hiện hành bắt buộc tối thiểu **RSA 2048-bit** (tương đương độ an toàn 112-bit của khóa đối xứng) hoặc **RSA 4096-bit** (tương đương 128-bit an toàn).

### 2.5. Thuật toán Euclid mở rộng (Extended Euclidean Algorithm)
Để tìm số mũ giải mã $d$ sao cho $e \cdot d \equiv 1 \pmod{\phi(n)}$, ta cần giải phương trình đồng dư bậc nhất, tương đương với phương trình Diophantine tuyến tính:
$$e \cdot d + \phi(n) \cdot y = \gcd(e, \phi(n)) = 1$$

Theo **Định lý Bézout**, phương trình luôn có nghiệm nguyên $(d, y)$ khi và chỉ khi $\gcd(e, \phi(n)) = 1$. Thuật toán Euclid mở rộng thực hiện các phép chia có dư liên tiếp:
$$r_{i-1} = q_i \cdot r_i + r_{i+1}$$
đồng thời duy trì hai dãy truy hồi cho các hệ số $x_i$ và $y_i$:
$$x_{i+1} = x_{i-1} - q_i \cdot x_i, \quad y_{i+1} = y_{i-1} - q_i \cdot y_i$$
Kết thúc thuật toán, ta thu được nghiệm $x$, và nghịch đảo modulo là $d = (x \bmod \phi(n) + \phi(n)) \bmod \phi(n)$. Độ phức tạp của thuật toán là $O(\log^2 \phi(n))$.

### 2.6. Thuật toán kiểm tra số nguyên tố xác suất Miller-Rabin
Để sinh các số nguyên tố lớn 512-bit hay 1024-bit, việc kiểm tra bằng phương pháp tất định (deterministic) như AKS rất chậm. Do đó, chuẩn mật mã sử dụng thuật toán xác suất **Miller-Rabin**:
1. Phân tích $n - 1$ thành tích $2^s \cdot d$, với $d$ là số lẻ.
2. Chọn ngẫu nhiên một cơ số chứng nhân $a \in [2, n - 2]$.
3. Tính $x = a^d \bmod n$. Nếu $x = 1$ hoặc $x = n - 1$, $n$ vượt qua vòng kiểm tra đối với cơ số $a$.
4. Lặp lại $s - 1$ lần phép bình phương: $x = x^2 \bmod n$. Nếu xuất hiện $x = n - 1$, $n$ tiếp tục vượt qua.
5. Nếu không thỏa mãn bất kỳ điều kiện nào, $n$ chắc chắn 100% là **hợp số** (*Composite*).

> [!TIP]
> Với mỗi vòng kiểm tra độc lập sử dụng một cơ số ngẫu nhiên $a$, xác suất một hợp số vượt qua kiểm định không vượt quá $\frac{1}{4}$. Khi thực hiện $k = 40$ vòng kiểm tra độc lập, xác suất một hợp số bị nhận nhầm là số nguyên tố bị chặn trên bởi:
> $$P_{error} \le \left(\frac{1}{4}\right)^{40} = 2^{-80} \approx 8.27 \times 10^{-25}$$
> Xác suất này nhỏ hơn rất nhiều so với xác suất phần cứng CPU bị lỗi bit do bức xạ vũ trụ!

### 2.7. Thuật toán Lũy thừa nhanh theo modulo (Square-and-Multiply)
Để tính $c = m^e \bmod n$ hoặc $m = c^d \bmod n$ với các số nguyên hàng ngàn bit, nếu tính $m^e$ trước rồi mới lấy modulo $n$ sẽ gây tràn bộ nhớ máy tính vì số lượng chữ số có thể lên đến hàng triệu. Thuật toán **Square-and-Multiply** tính toán modulo ngay trong từng bước lặp dựa trên phân tích nhị phân của số mũ $e = (b_k b_{k-1} \dots b_1 b_0)_2$:

**Thuật toán Square-and-Multiply (Right-to-Left)**:
- Khởi tạo: $\text{res} \leftarrow 1$, $\text{base} \leftarrow \text{base} \bmod \text{mod}$.
- Trong khi $\text{exp} > 0$:
  - Nếu bit thấp nhất $(\text{exp} \land 1) = 1$: $\text{res} \leftarrow (\text{res} \cdot \text{base}) \bmod \text{mod}$ (*Multiply*).
  - $\text{base} \leftarrow (\text{base} \cdot \text{base}) \bmod \text{mod}$ (*Square*).
  - $\text{exp} \leftarrow \text{exp} \gg 1$.
- Trả về $\text{res}$.

Số phép nhân modulo được tối ưu hóa từ $O(e)$ xuống chỉ còn tối đa $2 \log_2 e$ phép toán, giúp việc mã hóa và giải mã số nguyên 2048-bit diễn ra chỉ trong vài phần nghìn giây.

---

## Mục 3. Quy trình vận hành chi tiết (Sinh khóa, Mã hóa, Giải mã)

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Người nhận (Alice)
    actor Bob as Người gửi (Bob)
    Note over Alice: 1. Sinh khóa: chọn p, q nguyên tố bí mật, tính n = p*q và phi(n) = (p-1)*(q-1)
    Note over Alice: Chọn e = 65537 với gcd(e, phi(n)) = 1, tính d = e^(-1) mod phi(n)
    Alice->>Bob: Công khai Khóa công khai PK = (e, n)
    Note over Bob: 2. Mã hóa: đệm PKCS#1 v1.5 tạo m thuộc [0, n-1], tính c = m^e mod n
    Bob->>Alice: Gửi Bản mã c (Ciphertext)
    Note over Alice: 3. Giải mã: dùng Khóa bí mật SK (RSA-CRT) tính m = c^d mod n và gỡ đệm
```

### 3.1. Quy trình sinh cặp khóa (Key Generation)
1. **Sinh tham số nguyên tố**: Sử dụng nguồn sinh số ngẫu nhiên an toàn mật mã (`secrets`), sinh độc lập hai số nguyên tố lớn ngẫu nhiên $p$ và $q$ có cùng độ dài bit xấp xỉ $\frac{\text{key\_size}}{2}$ (ví dụ 1024-bit mỗi số cho khóa 2048-bit). Kiểm tra điều kiện:
   - $p \neq q$.
   - Hiệu số $|p - q|$ phải đủ lớn (ví dụ $|p - q| > 2^{\frac{\text{key\_size}}{2} - 100}$) nhằm triệt tiêu hoàn toàn nguy cơ bị phân tích thừa số bằng thuật toán Fermat.
2. **Tính Modulo công khai $n$**:
   $$n = p \times q$$
   Độ dài bit của $n$ chính là kích thước khóa (`key_size`).
3. **Tính hàm số Euler $\phi(n)$**:
   $$\phi(n) = (p - 1)(q - 1)$$
   *(Hoặc hàm Carmichael $\lambda(n) = \operatorname{lcm}(p - 1, q - 1)$)*.
4. **Lựa chọn số mũ công khai $e$**:
   Chọn số nguyên $e$ thỏa mãn:
   $$1 < e < \phi(n) \quad \text{và} \quad \gcd(e, \phi(n)) = 1$$
   Trong toàn bộ các chuẩn công nghiệp quốc tế (PKCS#1, X.509, TLS), giá trị $e$ hầu như luôn được chọn cố định là:
   $$e = 65537 = 2^{16} + 1 = F_4 \quad (\text{Số nguyên tố Fermat thứ tư})$$
   *Lý do kỹ thuật*: Dưới dạng nhị phân, $65537 = 10000000000000001_2$ chỉ gồm đúng hai bit 1. Khi áp dụng thuật toán Square-and-Multiply, phép lũy thừa $m^e \bmod n$ chỉ tốn đúng 16 phép bình phương và 1 phép nhân duy nhất, giúp tối ưu hóa tối đa tốc độ mã hóa và kiểm tra chữ ký số!
5. **Tính số mũ bí mật $d$**:
   Áp dụng thuật toán Euclid mở rộng giải phương trình:
   $$d \equiv e^{-1} \pmod{\phi(n)} \iff (e \cdot d) \bmod \phi(n) = 1$$
6. **Xác lập cặp khóa**:
   - **Khóa công khai (Public Key)**: $PK = (e, n)$.
   - **Khóa bí mật (Private Key)**: $SK = (d, n)$ cùng các thông tin hỗ trợ $\{p, q, d_p, d_q, q_{inv}\}$.

### 3.2. Quy trình Mã hóa (Encryption)
- Bên gửi chuyển đổi thông điệp văn bản cần truyền thành số nguyên $m$ thỏa mãn điều kiện tiên quyết:
  $$0 \le m < n$$
- Tính toán bản mã số nguyên $c$:
  $$c = m^e \bmod n$$
- Bản mã $c$ được gửi công khai trên kênh truyền không an toàn.

### 3.3. Quy trình Giải mã (Decryption)
- Bên nhận sở hữu khóa bí mật $d$ nhận bản mã $c$, khôi phục lại số nguyên $m$:
  $$m = c^d \bmod n$$
- Chuyển đổi số nguyên $m$ trở lại định dạng byte và văn bản ban đầu.

### 3.4. Chứng minh toán học chặt chẽ tính đúng đắn của phép giải mã
Cần chứng minh rằng với mọi $m \in \{0, 1, \dots, n - 1\}$, ta luôn có:
$$c^d \equiv (m^e)^d \equiv m^{ed} \equiv m \pmod n$$

Vì $e \cdot d \equiv 1 \pmod{\phi(n)}$, tồn tại số nguyên $k \ge 1$ sao cho:
$$ed = 1 + k \cdot \phi(n) = 1 + k(p - 1)(q - 1)$$

Ta xét hai trường hợp bao quát toàn bộ không gian số nguyên:

#### Trường hợp 1: $m$ nguyên tố cùng nhau với $n$ ($\gcd(m, n) = 1$)
Theo Định lý Euler, vì $\gcd(m, n) = 1$, ta có $m^{\phi(n)} \equiv 1 \pmod n$. Do đó:
$$m^{ed} = m^{1 + k\phi(n)} = m \cdot \left(m^{\phi(n)}\right)^k \equiv m \cdot (1)^k \equiv m \pmod n \quad (\text{đpcm})$$

#### Trường hợp 2: $m$ không nguyên tố cùng nhau với $n$ ($\gcd(m, n) > 1$)
Vì $n = p \cdot q$ với $p, q$ là hai số nguyên tố, $\gcd(m, n) > 1$ đồng nghĩa với việc $m$ phải là bội số của $p$ hoặc bội số của $q$ (nhưng không thể là bội số của cả hai vì $m < n = pq$).
Giả sử $m$ chia hết cho $p$, tức $m \equiv 0 \pmod p$. Khi đó:
$$m^{ed} \equiv 0^{ed} \equiv 0 \equiv m \pmod p$$

Mặt khác, vì $m < pq$ và $m$ chia hết cho $p$, nên $m$ chắc chắn không chia hết cho $q$, suy ra $\gcd(m, q) = 1$. Áp dụng định lý nhỏ Fermat theo modulo $q$:
$$m^{q - 1} \equiv 1 \pmod q$$
Từ đó:
$$m^{ed} = m^{1 + k(p - 1)(q - 1)} = m \cdot \left( m^{q - 1} \right)^{k(p - 1)} \equiv m \cdot (1)^{k(p - 1)} \equiv m \pmod q$$

Như vậy, ta có hệ hai phương trình đồng dư:
$$\begin{cases} m^{ed} \equiv m \pmod p \\ m^{ed} \equiv m \pmod q \end{cases}$$
Vì $p$ và $q$ là hai số nguyên tố phân biệt ($\gcd(p, q) = 1$), theo hệ quả của **Định lý Thặng dư Trung Hoa (Chinese Remainder Theorem - CRT)**:
$$m^{ed} \equiv m \pmod{p \cdot q} \iff m^{ed} \equiv m \pmod n \quad (\text{đpcm})$$

Chứng minh hoàn tất cho mọi trường hợp của $m \in \mathbb{Z}_n$.

### 3.5. Tăng tốc giải mã bằng Định lý Thặng dư Trung Hoa (RSA-CRT)
Trong khi phép mã hóa với $e = 65537$ diễn ra cực kỳ nhanh, phép giải mã tiêu chuẩn $m = c^d \bmod n$ đòi hỏi lũy thừa với số mũ $d$ có kích thước toàn phần (ví dụ 2048-bit), rất tốn kém tài nguyên tính toán. Để tối ưu hóa, chuẩn mật mã ứng dụng **Định lý Thặng dư Trung Hoa kết hợp công thức Garner (Garner's Formula)**:
1. **Tiền tính toán các tham số CRT trong quá trình sinh khóa**:
   $$d_p = d \bmod (p - 1)$$
   $$d_q = d \bmod (q - 1)$$
   $$q_{inv} = q^{-1} \bmod p$$
2. **Quy trình giải mã tăng tốc**:
   - Tính hai giá trị thặng dư trên hai trường nhỏ hơn một nửa:
     $$m_1 = c^{d_p} \bmod p$$
     $$m_2 = c^{d_q} \bmod q$$
   - Kết hợp hai nghiệm bằng công thức Garner:
     $$h = \left( q_{inv} \times ((m_1 - m_2) \bmod p) \right) \bmod p$$
     $$m = m_2 + h \times q$$

> [!TIP]
> **Giải thích vì sao RSA-CRT tăng tốc khoảng 4 lần**:
> Độ phức tạp của phép nhân và lấy modulo hai số $k$-bit là $O(k^2)$, và số phép lặp lũy thừa tỉ lệ thuận với $k$. Do đó độ phức tạp tổng thể của phép tính $c^d \bmod n$ là $O(k^3)$.
> Khi sử dụng CRT, $p$ và $q$ chỉ có kích thước $\frac{k}{2}$ bit.
> - Chi phí tính $m_1$: $\left(\frac{1}{2}\right)^3 = \frac{1}{8}$ chi phí ban đầu.
> - Chi phí tính $m_2$: $\left(\frac{1}{2}\right)^3 = \frac{1}{8}$ chi phí ban đầu.
> - Tổng chi phí giải mã CRT là: $\frac{1}{8} + \frac{1}{8} = \frac{1}{4}$ so với giải mã trực tiếp theo modulo $n$.
> Do đó, trên thực tế, giải mã RSA-CRT luôn đạt hiệu năng **nhanh gấp ~3.5 đến 4 lần** so với giải mã thông thường!

---

## Mục 4. Các giả định an toàn, tính chất bảo mật và các hình thức tấn công đã biết

### 4.1. Các giả định an toàn (Security Assumptions)
An toàn của RSA dựa trên hai giả định lý thuyết nền tảng:
1. **Giả định phân tích thừa số nguyên tố (Factoring Assumption)**: Không tồn tại thuật toán xác định trên máy tính cổ điển có thể phân tích số nguyên $n = pq$ thành thừa số trong thời gian đa thức hữu hạn $O(k^c)$.
2. **Giả định RSA (RSA Problem Assumption)**: Cho trước $n, e$ và $c = m^e \bmod n$, việc tìm lại $m$ mà không biết các thừa số của $n$ là bài toán khó giải tương đương với bài toán phân tích thừa số.

### 4.2. Tấn công số mũ công khai nhỏ $e$ (Small Public Exponent Attacks)
Việc chọn số mũ công khai nhỏ (như $e = 3$) nhằm tăng tốc mã hóa tiềm ẩn các nguy cơ nghiêm trọng nếu không có đệm an toàn:
1. **Khai căn trực tiếp khi thông điệp nhỏ ($m^e < n$)**:
   Nếu thông điệp ngắn và $e = 3$ sao cho $m^3 < n$, thì phép lấy modulo không có tác dụng: $c = m^3 \bmod n = m^3$. Kẻ tấn công chỉ cần lấy căn bậc ba thông thường trên tập số thực $\sqrt[3]{c}$ để thu hồi $m$ ngay lập tức.
2. **Tấn công phát tán Håstad (Håstad's Broadcast Attack)**:
   Nếu một người gửi phát tán cùng một thông điệp $m$ cho $k \ge e$ người nhận khác nhau có cùng số mũ công khai $e = 3$ nhưng có modulo riêng biệt $n_1, n_2, n_3$ (với $\gcd(n_i, n_j) = 1$):
   $$\begin{cases} c_1 \equiv m^3 \pmod{n_1} \\ c_2 \equiv m^3 \pmod{n_2} \\ c_3 \equiv m^3 \pmod{n_3} \end{cases}$$
   Kẻ tấn công áp dụng Định lý Thặng dư Trung Hoa (CRT) tính ra $C \equiv m^3 \pmod{n_1 n_2 n_3}$. Do $m < n_i$ nên $m^3 < n_1 n_2 n_3$. Lúc này $C = m^3$ chính xác trên trường số thực, kẻ tấn công chỉ cần lấy căn bậc ba $\sqrt[3]{C}$ để lấy được $m$.
3. **Tấn công Coppersmith**: Sử dụng mạng hình học LLL (*Lenstra-Lenstra-Lovász*) để tìm nghiệm đa thức nhỏ modulo $n$, khôi phục bản rõ nếu biết trước một phần thông điệp khi $e$ nhỏ.

### 4.3. Tấn công dùng chung Modulo (Common Modulus Attack)
Kịch bản: Một cơ quan quản lý tạo chung một modulo $n$ cho toàn bộ nhân viên để tiết kiệm tài nguyên, cấp cho mỗi người một cặp khóa $(e_i, d_i)$ riêng biệt sao cho $\gcd(e_1, e_2) = 1$.
Khi Alice gửi cùng một bức điện $m$ cho cả Bob và Charlie:
$$c_1 = m^{e_1} \bmod n \quad \text{và} \quad c_2 = m^{e_2} \bmod n$$
Kẻ nghe lén Eve bắt được cả $c_1$ và $c_2$. Vì $\gcd(e_1, e_2) = 1$, Eve áp dụng thuật toán Euclid mở rộng tìm được hai số nguyên $r, s$ thỏa mãn:
$$r \cdot e_1 + s \cdot e_2 = 1$$
Khi đó Eve khôi phục $m$ dễ dàng mà không cần bất kỳ khóa bí mật nào:
$$(c_1^r \cdot c_2^s) \bmod n = (m^{e_1})^r \cdot (m^{e_2})^s \bmod n = m^{r e_1 + s e_2} \equiv m^1 \equiv m \pmod n$$
*(Nếu $r < 0$, Eve tính $(c_1^{-1})^{-r} \bmod n$)*.

### 4.4. Tính chất đồng cấu đại số (Homomorphic Property / Malleability) và Tấn công bản mã chọn trước (CCA)
Mật mã RSA nguyên bản (*Textbook RSA*) có tính đồng cấu nhân:
$$E(m_1) \cdot E(m_2) = (m_1^e \bmod n) \cdot (m_2^e \bmod n) \equiv (m_1 \cdot m_2)^e \equiv E(m_1 \cdot m_2) \pmod n$$

Hệ quả tiêu cực: Kẻ tấn công có thể chỉnh sửa bản mã $c$ thành $c' = c \cdot r^e \bmod n$ (với $r$ ngẫu nhiên khả nghịch theo modulo $n$). Khi nạn nhân giải mã $c'$, kết quả thu được là $m' = m \cdot r \bmod n$. Sau đó kẻ tấn công chỉ cần nhân $m'$ với $r^{-1} \bmod n$ để tìm ra bản rõ $m$ gốc (kịch bản **Tấn công bản mã chọn trước** — *Chosen-Ciphertext Attack – CCA*).

### 4.5. Tấn công phân tích Fermat khi $p$ và $q$ quá gần nhau
Nếu hai số nguyên tố $p$ và $q$ được sinh ngẫu nhiên nhưng khoảng cách $|p - q|$ quá nhỏ (ví dụ $|p - q| < n^{1/4}$), ta đặt:
$$a = \frac{p + q}{2}, \quad b = \frac{|p - q|}{2}$$
Khi đó:
$$n = p \cdot q = (a - b)(a + b) = a^2 - b^2 \iff a^2 - n = b^2$$
Do $p \approx q$, giá trị $a = \frac{p+q}{2}$ chỉ lớn hơn $\lceil \sqrt{n} \rceil$ một lượng rất nhỏ. Thuật toán phân tích Fermat chỉ cần thử tuần tự $a = \lceil \sqrt{n} \rceil, \lceil \sqrt{n} \rceil + 1, \dots$ và kiểm tra xem $a^2 - n$ có phải là số chính phương $b^2$ hay không. Kẻ tấn công sẽ tìm ra $p = a + b$ và $q = a - b$ chỉ sau vài mili-giây!

### 4.6. Tấn công Wiener và Boneh-Durfee khi khóa bí mật $d$ nhỏ
Nếu người dùng cố tình chọn số mũ bí mật $d$ nhỏ nhằm tối ưu hóa thời gian giải mã trên các thiết bị hạn chế tài nguyên:
- **Định lý Wiener (1990)**: Nếu $d < \frac{1}{3} n^{1/4}$, thì phân số $\frac{k}{d}$ chính là một trong các phân số giản ước (*convergents*) của phân số liên tục biểu diễn $\frac{e}{n}$. Kẻ tấn công có thể khôi phục toàn bộ khóa bí mật $d$ trong thời gian đa thức $O(\log^2 n)$.
- **Boneh và Durfee (1999)**: Mở rộng ngưỡng tấn công lên tới $d < n^{0.292}$ bằng phương pháp cơ sở rút gọn mạng LLL.

### 4.7. Tấn công kênh kề (Side-Channel Attacks) và kỹ thuật làm mù (RSA Blinding)
- **Tấn công thời gian (Timing Attack - Paul Kocher 1996)**: Do phép nhân trong Square-and-Multiply chỉ diễn ra khi bit số mũ bằng 1, kẻ tấn công đo thời gian thực thi giải mã chính xác qua mạng để suy đoán từng bit của khóa bí mật $d$.
- **Giải pháp phòng thủ - Cơ chế làm mù RSA (RSA Blinding)**:
  Trước khi giải mã, nhân bản mã với một giá trị ngẫu nhiên bí mật $r$:
  $$c' = (c \cdot r^e) \bmod n$$
  Giải mã giá trị đã làm mù:
  $$m' = (c')^d \equiv (c^d \cdot r^{ed}) \equiv m \cdot r \pmod n$$
  Bên giải mã gỡ mù bằng cách nhân với nghịch đảo của $r$:
  $$m = m' \cdot r^{-1} \bmod n$$
  Kẻ tấn công đo thời gian trên $c'$ hoàn toàn không thu được mối tương quan nào với thông điệp gốc $m$ hay khóa $d$.

### 4.8. Sự cần thiết của các chuẩn đệm an toàn: PKCS#1 v1.5 và RSA-OAEP
Để khắc phục hoàn toàn tính đồng cấu nhân, tính tất định (cùng một bản rõ luôn cho ra cùng một bản mã), và các kiểu tấn công toán học, chuẩn mật mã bắt buộc phải bổ sung cơ chế đệm ngẫu nhiên trước khi thực hiện mã hóa:
1. **Chuẩn đệm PKCS#1 v1.5**:
   Định dạng khối dữ liệu trước khi mã hóa có độ dài $k$ byte ($k = \lceil \text{bits}/8 \rceil$):
   $$\text{EB} = \text{0x00} \parallel \text{0x02} \parallel \text{PS} \parallel \text{0x00} \parallel \text{Data}$$
   Trong đó $\text{PS}$ là chuỗi các byte ngẫu nhiên khác 0 có độ dài tối thiểu 8 byte. Byte ngẫu nhiên giúp biến đổi bản mã trở nên phi tất định, triệt tiêu tấn công từ điển và tấn công đồng cấu.
   *(Năm 1998, Daniel Bleichenbacher công bố tấn công Million Message Attack khai thác phản hồi lỗi đệm của máy chủ SSL/TLS)*.
2. **Chuẩn đệm tối ưu RSA-OAEP (Optimal Asymmetric Encryption Padding - Bellare & Rogaway)**:
   Sử dụng mạng Feistel 2 vòng kết hợp hàm băm mật mã để tạo nên cơ chế đệm đạt cấp độ an toàn cao nhất **IND-CCA2** (*Indistinguishability under Adaptive Chosen Ciphertext Attack*) trong mô hình Random Oracle Model.

---

## Mục 5. Ưu điểm, hạn chế và ứng dụng thực tế

### 5.1. So sánh toàn diện giữa RSA, Mật mã đối xứng (AES) và Mật mã đường cong Elliptic (ECC)

| Tiêu chí kỹ thuật | RSA (Rivest-Shamir-Adleman) | AES-128 / AES-256 | ECC (ECDSA / Ed25519) |
| :--- | :--- | :--- | :--- |
| **Phân loại mật mã** | Bất đối xứng (Khóa công khai) | Đối xứng (Mật mã khối SPN) | Bất đối xứng (Đường cong Elliptic) |
| **Kích thước khóa an toàn** | 2048-bit hoặc 3072-bit | 128-bit hoặc 256-bit | 256-bit (tương đương RSA 3072-bit) |
| **Cơ sở toán học** | Bài toán phân tích thừa số (IFP) | Trường Galois $GF(2^8)$, S-Box | Bài toán Logarithm rời rạc ECDLP |
| **Tốc độ mã hóa** | Nhanh với $e = 65537$ | Cực nhanh (hỗ trợ phần cứng AES-NI) | Trung bình |
| **Tốc độ giải mã / Ký** | Chậm (ngay cả khi có CRT) | Cực nhanh | Rất nhanh |
| **Băng thông bản mã / Chữ ký**| Lớn (256 - 512 bytes) | Cực nhỏ (bằng đúng dữ liệu + pad) | Nhỏ gọn (chỉ 64 bytes) |
| **Khả năng quản lý khóa** | Tuyệt vời ($2N$ khóa cho $N$ người) | Kém ($O(N^2)$ khóa chia sẻ) | Tuyệt vời ($2N$ khóa) |
| **Hỗ trợ Ký số điện tử** | Có (đối ngẫu toán học hoàn hảo) | Không (chỉ hỗ trợ MAC) | Có (rất tối ưu cho chữ ký) |
| **Nguy cơ máy tính lượng tử** | **Bị phá hủy bởi thuật toán Shor** | An toàn (Grover chỉ giảm một nửa bit) | **Bị phá hủy bởi thuật toán Shor** |

### 5.2. Các ứng dụng thực tế trụ cột của RSA trong kỷ nguyên số
Mặc dù tốc độ xử lý dữ liệu lớn không thể sánh bằng các thuật toán đối xứng như AES, RSA đóng vai trò hạ tầng không thể thay thế trong các ứng dụng:
1. **Hạ tầng khóa công khai (PKI - Public Key Infrastructure) và Chứng chỉ số X.509**:
   Hàng tỷ website trên thế giới sử dụng chứng chỉ số SSL/TLS có chữ ký số RSA từ các tổ chức chứng thực (Certificate Authorities - CA) để xác thực danh tính tên miền.
2. **Giao thức bảo mật tầng truyền vận TLS / HTTPS**:
   - Trong TLS 1.2 trở về trước: RSA được dùng để mã hóa trao đổi khóa phiên bí mật (*Pre-Master Secret*).
   - Trong TLS 1.3: RSA được dùng kết hợp với thuật toán RSA-PSS để tạo chữ ký số xác thực máy chủ, chống tấn công Man-In-The-Middle.
3. **Mô hình mã hóa lai (Hybrid Cryptography System)**:
   Để tối ưu hóa cả độ an toàn phân phối khóa lẫn hiệu năng truyền tải dữ liệu dung lượng lớn:
   - RSA được dùng làm cơ chế bao bọc khóa (**Key Encapsulation Mechanism - KEM**): mã hóa một khóa phiên ngẫu nhiên (AES Session Key 256-bit).
   - Dữ liệu thực tế (file, video, email) được mã hóa bằng thuật toán đối xứng tốc độ cao (AES-GCM hoặc ChaCha20-Poly1305).
4. **Giao thức SSH (Secure Shell)**:
   Xác thực người dùng từ xa không cần mật khẩu (*Passwordless Authentication*) bằng cặp khóa công khai và riêng tư RSA (thường từ 2048-bit đến 4096-bit).
5. **Chữ ký số văn bản và xác thực Token (JWT - RS256)**:
   Chuẩn định danh OAuth2 / OpenID Connect sử dụng thuật toán RS256 (RSA Signature với SHA-256) để ký các access token, cho phép các microservices kiểm tra tính hợp lệ của token mà không cần truy vấn cơ sở dữ liệu xác thực tập trung.

---

## Mục 6. Ví dụ tính tay hoàn chỉnh với tham số số nguyên tố nhỏ

Để làm sáng tỏ toàn bộ các bước toán học mà không bị chi phối bởi các con số hàng ngàn bit, ta tiến hành một ví dụ kinh điển với các tham số nhỏ: chọn $p = 61$ và $q = 53$.

### Bước 1: Khởi tạo hệ thống và tính tham số modulo
1. Chọn hai số nguyên tố:
   $$p = 61, \quad q = 53$$
2. Tính modulo công khai $n$:
   $$n = p \times q = 61 \times 53 = 3233$$
3. Tính hàm số Euler $\phi(n)$:
   $$\phi(n) = (p - 1)(q - 1) = (61 - 1)(53 - 1) = 60 \times 52 = 3120$$

### Bước 2: Chọn số mũ công khai $e$
Ta cần chọn số nguyên $e$ sao cho $1 < e < 3120$ và $\gcd(e, 3120) = 1$.
Chọn $e = 17$. Kiểm tra nguyên tố cùng nhau:
$$3120 = 17 \times 183 + 9$$
$$17 = 9 \times 1 + 8$$
$$9 = 8 \times 1 + 1$$
$$8 = 1 \times 8 + 0$$
Ước số chung lớn nhất $\gcd(17, 3120) = 1$. Do đó $e = 17$ là hợp lệ.

### Bước 3: Tìm số mũ bí mật $d$ bằng thuật toán Euclid mở rộng
Ta cần tìm số nguyên $d$ sao cho:
$$17 \cdot d \equiv 1 \pmod{3120} \iff 17 \cdot d + 3120 \cdot y = 1$$

Bảng thực thi từng bước thuật toán Euclid mở rộng cho cặp $(a_0 = 3120, b_0 = 17)$ với bất biến Bézout $3120 \cdot x_k + 17 \cdot y_k = r_k$:

| Bước $i$ | Số bị chia $a$ | Số chia $b$ | Thương $q$ | Số dư $r$ | Hệ số $x$ (ứng với 3120) | Hệ số $y$ (ứng với 17) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Khởi tạo | - | - | - | - | $x_0 = 1,\; x_1 = 0$ | $y_0 = 0,\; y_1 = 1$ |
| 1 | 3120 | 17 | 183 | 9 | $x_2 = 1 - 183 \times 0 = 1$ | $y_2 = 0 - 183 \times 1 = -183$ |
| 2 | 17 | 9 | 1 | 8 | $x_3 = 0 - 1 \times 1 = -1$ | $y_3 = 1 - 1 \times (-183) = 184$ |
| 3 | 9 | 8 | 1 | 1 | $x_4 = 1 - 1 \times (-1) = 2$ | $y_4 = -183 - 1 \times 184 = -367$ |
| 4 | 8 | 1 | 8 | 0 | **Dừng ($r = 0$)** | **Nghiệm: $y_4 = -367$** |

Truy hồi ngược kiểm chứng phương trình $17 \cdot d + 3120 \cdot k = 1$:
$$1 = 9 - 1 \times 8$$
$$1 = 9 - 1 \times (17 - 1 \times 9) = 2 \times 9 - 1 \times 17$$
$$1 = 2 \times (3120 - 183 \times 17) - 1 \times 17 = 2 \times 3120 - 367 \times 17$$
Vậy:
$$(-367) \times 17 + 2 \times 3120 = 1$$
Số mũ bí mật $d$:
$$d \equiv -367 \pmod{3120} \equiv 3120 - 367 = 2753$$

**Kiểm tra tính đúng đắn**:
$$e \times d = 17 \times 2753 = 46801 = 15 \times 3120 + 1 \implies 17 \times 2753 \equiv 1 \pmod{3120} \quad (\text{Chính xác tuyệt đối!})$$

- **Khóa công khai**: $PK = (e = 17, n = 3233)$
- **Khóa bí mật**: $SK = (d = 2753, n = 3233)$

### Bước 4: Thực nghiệm mã hóa thông điệp $m = 65$ (Ký tự `'A'` trong bảng mã ASCII)
Ta cần tính:
$$c = m^e \bmod n = 65^{17} \bmod 3233$$
Biểu diễn số mũ 17 dưới dạng nhị phân: $17 = 10001_2 = 2^4 + 2^0$.
Áp dụng thuật toán lũy thừa nhanh Square-and-Multiply:
1. $65^1 \equiv 65 \pmod{3233}$
2. $65^2 = 4225 = 1 \times 3233 + 992 \equiv 992 \pmod{3233}$
3. $65^4 \equiv 992^2 = 984064 = 304 \times 3233 + 1232 \equiv 1232 \pmod{3233}$
4. $65^8 \equiv 1232^2 = 1517824 = 469 \times 3233 + 1547 \equiv 1547 \pmod{3233}$
5. $65^{16} \equiv 1547^2 = 2393209 = 740 \times 3233 + 789 \equiv 789 \pmod{3233}$
6. Tích lũy kết quả theo hai bit `1` tại $2^4$ và $2^0$:
   $$c = 65^{17} = 65^{16} \times 65^1 \equiv 789 \times 65 = 51285 = 15 \times 3233 + 2790 \equiv 2790 \pmod{3233}$$
Bản mã gửi đi là:
$$c = 2790$$

### Bước 5: Thực nghiệm giải mã bản mã $c = 2790$ bằng Garner's CRT
Bên nhận cần tính $m = c^d \bmod n = 2790^{2753} \bmod 3233$. Áp dụng Định lý Thặng dư Trung Hoa (CRT):
- $d_p = 2753 \bmod (61 - 1) = 2753 \bmod 60 = 53$
- $d_q = 2753 \bmod (53 - 1) = 2753 \bmod 52 = 49$
- Tính $q_{inv} = 53^{-1} \bmod 61$ bằng Euclid mở rộng:
  $$\begin{aligned}
  61 &= 53 \times 1 + 8, \quad 53 = 8 \times 6 + 5, \quad 8 = 5 \times 1 + 3, \quad 5 = 3 \times 1 + 2, \quad 3 = 2 \times 1 + 1 \\
  \implies 1 &= 3 - 2 = 3 - (5 - 3) = 2 \times 3 - 5 = 2(8 - 5) - 5 = 2 \times 8 - 3 \times 5 \\
  &= 2 \times 8 - 3(53 - 6 \times 8) = 20 \times 8 - 3 \times 53 = 20(61 - 53) - 3 \times 53 = 20 \times 61 - 23 \times 53
  \end{aligned}$$
  Do đó $q_{inv} \equiv -23 \equiv 61 - 23 = 38 \pmod{61}$ *(kiểm tra: $53 \times 38 = 2014 = 33 \times 61 + 1 \equiv 1 \pmod{61}$)*.
- Tính hai thành phần thặng dư bằng bình phương và nhân liên tiếp:
  - $m_1 = 2790^{53} \bmod 61 = 45^{53} \bmod 61$ (với $53 = 32 + 16 + 4 + 1$):
    $45^2 = 2025 \equiv 12$, $45^4 \equiv 12^2 = 144 \equiv 22$, $45^8 \equiv 22^2 = 484 \equiv 57 \equiv -4$, $45^{16} \equiv (-4)^2 = 16$, $45^{32} \equiv 16^2 = 256 \equiv 12 \pmod{61}$.
    $$\implies m_1 \equiv 12 \times 16 \times 22 \times 45 \equiv (192 \bmod 61) \times (990 \bmod 61) \equiv 9 \times 14 = 126 \equiv 4 \pmod{61}$$
  - $m_2 = 2790^{49} \bmod 53 = 34^{49} \bmod 53$ (với $49 = 32 + 16 + 1$):
    $34^2 = 1156 \equiv 43 \equiv -10$, $34^4 \equiv (-10)^2 = 100 \equiv 47 \equiv -6$, $34^8 \equiv (-6)^2 = 36$, $34^{16} \equiv 36^2 = 1296 \equiv 24$, $34^{32} \equiv 24^2 = 576 \equiv 46 \equiv -7 \pmod{53}$.
    $$\implies m_2 \equiv (-7) \times 24 \times 34 = -5712 = -108 \times 53 + 12 \equiv 12 \pmod{53}$$
- Áp dụng công thức Garner kết hợp nghiệm:
  $$h = \left(q_{inv} \times (m_1 - m_2)\right) \bmod p = \left(38 \times (4 - 12)\right) \bmod 61 = -304 \bmod 61 = 1$$
  $$m = m_2 + h \times q = 12 + 1 \times 53 = 65$$

Kết quả giải mã ra đúng số nguyên $m = 65$ (tương ứng ký tự **'A'**). Quy trình đã được kiểm chứng tính đúng đắn toán học 100%!

---

## Mục 7. Giải thích cấu trúc code `rsa.py` đã viết

Mã nguồn thực nghiệm [rsa.py](../algorithms/rsa.py) (620 dòng) được thiết kế theo kiến trúc 5 tầng phân lớp độc lập, hoàn toàn sử dụng Python 3.12 thuần từ nguyên lý gốc, tuân thủ nguyên tắc không sử dụng bất kỳ thư viện mật mã có sẵn nào:

```mermaid
graph TD
    subgraph L5["Tầng 5: Kiểm chứng & Thực nghiệm"]
        V["verify_hand_calculation_example()"]
        B["benchmark_rsa_performance()"]
        I["interactive_demo()"]
    end
    subgraph L4["Tầng 4: Xử lý chuỗi & Giao diện ứng dụng"]
        ET["encrypt_text()"]
        DT["decrypt_text()"]
    end
    subgraph L3["Tầng 3: Cơ chế đệm an toàn"]
        P1["pkcs1_pad()"]
        UP1["pkcs1_unpad()"]
    end
    subgraph L2["Tầng 2: Quản lý khóa & Lõi mã hóa"]
        GK["generate_keypair()"]
        RE["rsa_encrypt_int()"]
        RD["rsa_decrypt_int() / RSA-CRT"]
    end
    subgraph L1["Tầng 1: Toán học nền tảng"]
        PM["pow_mod() (Square-and-Multiply)"]
        EG["extended_gcd()"]
        MI["mod_inverse()"]
        MR["is_prime_miller_rabin()"]
        GP["generate_prime()"]
    end

    ET --> P1
    DT --> UP1
    P1 --> RE
    UP1 --> RD
    RE --> PM
    RD --> PM
    GK --> GP
    GK --> MI
    GP --> MR
    MR --> PM
    MI --> EG
    V --> L1
    B --> L4
    I --> L4
```

### 7.1. Phân tích chi tiết các hàm toán học nền tảng ([rsa.py](../algorithms/rsa.py#L23-L181))
1. **`pow_mod(base, exp, mod)`**:
   - Hiện thực thuật toán Square-and-Multiply (Binary Exponentiation).
   - Kiểm tra chặt chẽ các trường hợp biên ($\text{mod} \le 0 \rightarrow$ lỗi, $\text{mod} = 1 \rightarrow 0$, $\text{exp} < 0 \rightarrow$ lỗi).
   - Duyệt từng bit của $\text{exp}$ bằng các phép toán bitmask nhanh (`exp & 1` và `exp >>= 1`), nhân và bình phương kết hợp rút gọn modulo liên tục để kiểm soát kích thước bộ nhớ.
2. **`extended_gcd(a, b)`**:
   - Vòng lặp Euclid mở rộng duy trì các biến $x_0, x_1, y_0, y_1$.
   - Trả về bộ ba số nguyên $(g, x, y)$ thỏa mãn $a \cdot x + b \cdot y = g = \gcd(a, b)$.
3. **`mod_inverse(e, phi)`**:
   - Kiểm tra $\phi > 1$ và gọi `extended_gcd(e % phi, phi)`. Nếu ước chung lớn nhất khác 1, tung ngoại lệ `ValueError`.
   - Chuẩn hóa nghiệm $x$ về khoảng $[0, \phi - 1]$ qua phép `x % phi`.
4. **`is_prime_miller_rabin(n, k=40)`**:
   - Xử lý biên cho $n < 2$, $n \in \{2, 3\}$, và $n$ chẵn.
   - Sàng nhanh với danh sách 168 số nguyên tố lẻ nhỏ đầu tiên `SMALL_PRIMES` ($3 \le p < 1000$), giúp loại bỏ hơn 85% hợp số ngẫu nhiên chỉ bằng phép chia lấy dư nhanh trước khi chạy Miller-Rabin.
   - Tách $n - 1 = 2^s \cdot d$.
   - Lặp $k = 40$ vòng: dùng `secrets.randbelow(n - 3) + 2` để chọn ngẫu nhiên cơ số chứng nhân an toàn mật mã $a \in [2, n - 2]$, kiểm tra điều kiện căn nguyên bậc hai của 1.
5. **`generate_prime(bits)`**:
   - Dùng `secrets.randbits(bits)` tạo số ngẫu nhiên.
   - Bật bit MSB (`1 << (bits - 1)`) để đảm bảo đủ chiều dài bit, và bật bit LSB (`| 1`) để luôn là số lẻ.
   - Lặp kiểm định cho đến khi tìm thấy số vượt qua Miller-Rabin 40 vòng.

### 7.2. Phân tích hàm sinh khóa và lõi mã hóa ([rsa.py](../algorithms/rsa.py#L188-L313))
1. **`generate_keypair(key_size=1024, e=65537)`**:
   - Kiểm tra điều kiện tiên quyết của tham số đầu vào ($e \ge 3$ lẻ, $\text{key\_size} \ge 16$, $1 < e < \phi(n)$) nhằm loại bỏ hoàn toàn nguy cơ vòng lặp vô tận khi $e$ chẵn hoặc quá lớn so với kích thước khóa.
   - Sinh $p$ và $q$ sao cho $n = p \cdot q$ đạt đúng `key_size` bit và kiểm tra khoảng cách $|p - q|$ nhằm phòng vệ thuật toán phân tích Fermat.
   - Kiểm tra $\gcd(e, \phi(n)) = 1$, tính $d = \operatorname{mod\_inverse}(e, \phi(n))$ và xác nhận ngưỡng chống tấn công Wiener ($3d > n^{1/4}$).
   - Tiền tính toán các tham số tăng tốc CRT: $d_p, d_q, q_{inv}$.
2. **`rsa_encrypt_int(m, pubkey)`** & **`rsa_decrypt_int(c, privkey, use_crt=True)`**:
   - Đảm bảo miền giá trị hợp lệ $0 \le m, c < n$.
   - Nếu `use_crt=True`: áp dụng công thức Garner tính $m_1, m_2, h$ và khôi phục $m$ với tốc độ cao.

### 7.3. Phân tích cơ chế đệm và xử lý văn bản tiếng Việt ([rsa.py](../algorithms/rsa.py#L320-L620))
1. **`pkcs1_pad(data, target_len)`** & **`pkcs1_unpad(padded, target_len)`**:
   - Triển khai cấu trúc chuẩn RFC 8017: `0x00 || 0x02 || PS || 0x00 || Data` với $\text{PS}$ gồm tối thiểu 8 byte ngẫu nhiên khác `0x00` sinh bởi `secrets.randbelow(256)`.
   - Hàm `pkcs1_unpad` quét toàn bộ khối không rẽ nhánh thoát sớm và chỉ ném một thông báo lỗi đồng nhất nhằm phòng vệ tấn công **Bleichenbacher Padding Oracle**.
2. **`encrypt_text(plaintext, pubkey, use_padding=True)`** & **`decrypt_text(...)`**:
   - Mã hóa xâu Unicode/tiếng Việt (bao gồm cả trường hợp biên chuỗi rỗng `""`) sang mảng byte UTF-8.
   - Tính kích thước khối dữ liệu tối đa $k - 11$ byte đối với PKCS#1 v1.5 (hoặc $k - 3$ byte theo cấu trúc khung `0x00 || len(2B) || chunk || 0x00...` đối với chế độ chia khối thô `use_padding=False`, đảm bảo $m < n$ và bảo toàn các byte `0x00` dẫn đầu).
   - Chuyển từng khối byte thành số nguyên $m < n$ theo thứ tự `big-endian`, mã hóa/giải mã từng khối và khôi phục nguyên vẹn văn bản UTF-8 ban đầu.

---

## Mục 8. Bảng đánh giá thực nghiệm, kiểm chứng tính đúng đắn, hiệu năng tính toán và kết luận

### 8.1. Bảng số liệu thực nghiệm đo đạc thực tế
Thực nghiệm được thực hiện trực tiếp bằng lệnh `python -X utf8 algorithms/rsa.py` trên môi trường Python 3.12 thuần 64-bit. Dữ liệu kiểm thử là chuỗi văn bản tiếng Việt Unicode có dấu gồm **171 ký tự** (**218 bytes** UTF-8):
> *"Khoa Công nghệ Thông tin - Đồ án An toàn thông tin RSA. Sinh viên: Trần Gia Thuận. Mã hóa chuỗi ký tự tiếng Việt: Bảo mật thông tin là nền tảng của chuyển đổi số quốc gia!"*

Bảng kết quả đo lường hiệu năng thực tế (thời gian tính bằng mili-giây – ms):

| Kích thước khóa | Thời gian Sinh khóa | Thời gian Mã hóa | Thời gian Giải mã chuẩn | Thời gian Giải mã CRT | Gia tốc giải mã CRT | Số khối bản mã |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **512-bit** ($k = 64\text{ B}$) | 12.26 ms | 0.14 ms | 3.01 ms | **1.29 ms** | **2.33x** | 5 khối |
| **1024-bit** ($k = 128\text{ B}$) | 76.98 ms | 0.12 ms | 6.93 ms | **2.47 ms** | **2.81x** | 2 khối |
| **2048-bit** ($k = 256\text{ B}$) | 1010.05 ms | 0.17 ms | 22.75 ms | **6.59 ms** | **3.45x** | 1 khối |

```mermaid
xychart-beta
    title "So sánh thời gian Giải mã: Chuẩn vs RSA-CRT (ms)"
    x-axis ["512-bit", "1024-bit", "2048-bit"]
    y-axis "Thời gian thực thi (ms)" 0 --> 25
    bar [3.01, 6.93, 22.75]
    bar [1.29, 2.47, 6.59]
```

### 8.2. Phân tích định lượng và đánh giá hiệu quả giải thuật
1. **Quy luật chia khối PKCS#1 v1.5 và thời gian sinh khóa**:
   - Với bản rõ 218 bytes UTF-8 và chi phí đệm tối thiểu 11 bytes mỗi khối: ở mức 512-bit ($64 - 11 = 53\text{ B/khối}$) cần $\lceil 218 / 53 \rceil = 5$ khối; ở mức 1024-bit ($128 - 11 = 117\text{ B/khối}$) cần $\lceil 218 / 117 \rceil = 2$ khối; và ở mức 2048-bit ($256 - 11 = 245\text{ B/khối}$) toàn bộ thông điệp nằm gọn trong **1 khối duy nhất**.
   - Thời gian sinh khóa tăng phi tuyến khi nâng kích thước khóa (từ 12.26 ms ở 512-bit lên 1010.05 ms ở 2048-bit) do mật độ số nguyên tố giảm theo $\approx \frac{1}{\ln N}$ và chi phí phép nhân modulo $O(k^2)$ trong mỗi vòng kiểm định Miller-Rabin tăng lên, nhưng vẫn hoàn tất chỉ trong $\sim 1.01$ giây trên Python thuần.
2. **Thời gian mã hóa**:
   - Diễn ra cực kỳ nhanh trên mọi kích thước khóa ($< 0.2\text{ ms}$), minh chứng trực quan cho tính ưu việt của số mũ công khai Fermat $e = 65537 = 2^{16} + 1$ (chỉ cần 16 phép bình phương và 1 phép nhân cho mỗi khối).
3. **Hiệu quả gia tốc vượt trội của Định lý Thặng dư Trung Hoa (RSA-CRT)**:
   - Khi kích thước khóa càng lớn, hệ số gia tốc của Garner's CRT càng tăng rõ rệt (từ **2.33x** ở 512-bit lên **3.45x** ở 2048-bit: rút ngắn từ 22.75 ms xuống chỉ còn **6.59 ms**, tiệm cận mức lý thuyết $4.0\times$).
   - Trong các máy chủ TLS/PKI thực hiện hàng triệu tác vụ ký và giải mã mỗi ngày, việc áp dụng RSA-CRT giúp tiết kiệm trên 70% tài nguyên tính toán CPU.

### 8.3. Kiểm chứng tính toàn vẹn và an toàn
- **Kiểm chứng tính đúng đắn**: Bản rõ sau khi giải mã hoàn toàn trùng khớp 100% với chuỗi ký tự ban đầu, bảo toàn tuyệt đối mọi ký tự tiếng Việt Unicode đa byte.
- **Kiểm chứng an toàn đệm**: Với cơ chế đệm PKCS#1 v1.5, mỗi lần mã hóa cùng một bản rõ sẽ sinh ra một chuỗi bản mã hoàn toàn khác nhau nhờ chuỗi ngẫu nhiên $\text{PS}$, triệt tiêu hoàn toàn tấn công phân tích thống kê và tấn công bản rõ chọn trước (CPA).

### 8.4. Kết luận tổng kết đồ án
1. Đồ án đã hoàn thành xuất sắc toàn bộ mục tiêu đề ra:
   - Cài đặt hoàn chỉnh thuật toán mật mã bất đối xứng RSA trên Python thuần 3.12 từ nguyên lý toán học sơ cấp, không phụ thuộc thư viện ngoài.
   - Tự viết các hàm toán học nền tảng: thuật toán Euclid mở rộng, hàm tìm nghịch đảo modulo, lũy thừa nhanh Square-and-Multiply, kiểm tra số nguyên tố lớn Miller-Rabin, sàng số nguyên tố nhỏ.
   - Hiện thực hóa thành công kỹ thuật tăng tốc giải mã bằng Định lý Thặng dư Trung Hoa (Garner's CRT) và cơ chế đệm an toàn PKCS#1 v1.5.
2. **Xu hướng phát triển tương lai**:
   Trong tương lai khi máy tính lượng tử quy mô lớn xuất hiện, thuật toán Shor (*Shor's Algorithm*) sẽ giải được bài toán phân tích thừa số nguyên tố trong thời gian đa thức hữu hạn $O(k^3)$, đe dọa trực tiếp sự tồn vong của RSA và ECC. Do đó, các cơ quan an ninh tiêu chuẩn (như NIST) đang dẫn dắt quá trình chuyển đổi sang **Mật mã Hậu lượng tử** (**PQC** - *Post-Quantum Cryptography*) dựa trên bài toán lưới (*Lattice-based Cryptography*), tiêu biểu là chuẩn **ML-KEM** (*Kyber*) cho trao đổi khóa và **ML-DSA** (*Dilithium*) cho chữ ký số. Dẫu vậy, RSA vẫn tiếp tục là tượng đài kinh điển và là bài học nhập môn không thể thiếu đối với mọi sinh viên chuyên ngành An toàn thông tin.
