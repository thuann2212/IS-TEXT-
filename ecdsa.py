# -*- coding: utf-8 -*-
"""
================================================================================
HỆ THỐNG CHỮ KÝ SỐ ĐƯỜNG CONG ELLIPTIC (ECDSA - ELLIPTIC CURVE DIGITAL SIGNATURE ALGORITHM)
Môn học: An toàn thông tin (Information Security)
Sinh viên thực hiện: Trần Gia Thuận
Chữ số cuối SID: 3 (3 mod 4 = 3 -> Đề tài phân công: Chữ ký số ECDSA)
Ngôn ngữ: Python thuần (Không dùng thư viện mật mã bên ngoài, chỉ dùng secrets, time, math, typing)
Đường cong tiêu chuẩn: secp256k1 (Bitcoin/Ethereum) và NIST P-256 / Toy Curve F_17
Kết hợp trực tiếp: Module băm SHA-256 từ nguyên lý gốc (sha256.py)
================================================================================
"""

import math
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Union

# Tích hợp trực tiếp module băm SHA-256 tự viết từ nguyên lý gốc (sha256.py)
from sha256 import bam_sha256_bytes


# ==============================================================================
# PHẦN 1: CÁC PHÉP TOÁN SỐ HỌC MODULO CƠ SỞ (MATHEMATICAL PRIMITIVES)
# ==============================================================================

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Thuật toán Euclid mở rộng (Extended Euclidean Algorithm).
    Tìm ước số chung lớn nhất gcd(a, b) và các hệ số Bézout (x, y) thỏa mãn:
        a * x + b * y = gcd(a, b)
    
    Độ phức tạp: O(log(min(a, b)))
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """
    Tính phần tử nghịch đảo nhân của a theo modulo m: a^(-1) mod m
    Thỏa mãn: (a * a^(-1)) = 1 (mod m).
    
    Yêu cầu bắt buộc: gcd(a, m) == 1 (a và m nguyên tố cùng nhau).
    Sử dụng thuật toán Euclid mở rộng, đảm bảo kết quả luôn nằm trong [0, m - 1].
    """
    if m <= 0:
        raise ValueError(f"Modulo m phải là số nguyên dương (m={m}).")
    a = a % m
    if a == 0:
        raise ZeroDivisionError(f"Số 0 không tồn tại nghịch đảo modulo {m}.")

    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError(f"Không tồn tại nghịch đảo modulo {m} cho {a} vì gcd({a}, {m}) = {gcd_val} != 1.")

    return x % m


# ==============================================================================
# PHẦN 2: BIỂU DIỄN HÌNH HỌC VÀ ĐẠI SỐ ĐƯỜNG CONG ELLIPTIC (ELLIPTIC CURVE ARITHMETIC)
# ==============================================================================

@dataclass(frozen=True)
class Point:
    """
    Biểu diễn một điểm P(x, y) trên đường cong Elliptic.
    Nếu x is None và y is None: Điểm vô cực (Point at Infinity) ký hiệu O,
    đóng vai trò là phần tử trung hòa (Identity Element) của nhóm Abel.
    """
    x: Optional[int] = None
    y: Optional[int] = None

    @property
    def is_infinity(self) -> bool:
        """Kiểm tra xem điểm có phải là điểm vô cực O hay không."""
        return self.x is None and self.y is None

    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(Infinity)"
        return f"Point(0x{self.x:x}, 0x{self.y:x})"

    def to_short_str(self) -> str:
        """Chuỗi rút gọn biểu diễn tọa độ hex phục vụ in ấn."""
        if self.is_infinity:
            return "Point(Infinity)"
        sx = hex(self.x)
        sy = hex(self.y)
        sx_str = f"{sx[:10]}...{sx[-6:]}" if len(sx) > 18 else sx
        sy_str = f"{sy[:10]}...{sy[-6:]}" if len(sy) > 18 else sy
        return f"Point(x={sx_str}, y={sy_str})"


# Điểm vô cực định nghĩa sẵn
INFINITY_POINT = Point(None, None)


class EllipticCurve:
    """
    Đường cong Elliptic dạng rút gọn Weierstrass trên trường hữu hạn F_p:
        y^2 = x^3 + a*x + b (mod p)
    
    Điều kiện không suy biến (Non-singularity):
        4*a^3 + 27*b^2 != 0 (mod p)
    
    Các tham số miền chuẩn (Domain Parameters):
    - p: Đặc số số nguyên tố của trường F_p.
    - a, b: Các hệ số của phương trình Weierstrass.
    - G: Điểm cơ sở (Base Generator Point).
    - n: Bậc nguyên tố của nhóm con sinh bởi G (n * G = O).
    - h: Hệ số đồng bậc (Cofactor = #E(F_p) / n).
    """

    def __init__(self, name: str, p: int, a: int, b: int, G_x: int, G_y: int, n: int, h: int = 1):
        self.name = name
        self.p = p
        self.a = a % p
        self.b = b % p
        self.n = n
        self.h = h

        # Kiểm tra điều kiện không suy biến
        delta = (4 * (self.a ** 3) + 27 * (self.b ** 2)) % self.p
        if delta == 0:
            raise ValueError(f"Đường cong bị suy biến! 4*a^3 + 27*b^2 = 0 (mod {self.p}).")

        self.G = Point(G_x % self.p, G_y % self.p)

        # Kiểm tra điểm cơ sở G phải thuộc đường cong
        if not self.is_on_curve(self.G):
            raise ValueError(f"Điểm cơ sở G({G_x}, {G_y}) không thuộc đường cong {self.name}!")

    def is_on_curve(self, pt: Point) -> bool:
        """
        Kiểm tra điểm pt có thỏa mãn phương trình đường cong y^2 = x^3 + a*x + b (mod p) hay không.
        Điểm vô cực O luôn được coi là thuộc đường cong.
        """
        if pt.is_infinity:
            return True
        lhs = (pt.y ** 2) % self.p
        rhs = (pt.x ** 3 + self.a * pt.x + self.b) % self.p
        return lhs == rhs

    def point_neg(self, pt: Point) -> Point:
        """
        Tìm điểm đối -P của P(x, y):
            -P = (x, -y mod p)
        Thỏa mãn: P + (-P) = O.
        """
        if pt.is_infinity:
            return pt
        return Point(pt.x, (-pt.y) % self.p)

    def point_add(self, P: Point, Q: Point) -> Point:
        """
        Phép cộng hai điểm trên đường cong Elliptic: R = P + Q.
        
        Quy tắc hình học & đại số:
        1. Nếu P = O thì R = Q. Nếu Q = O thì R = P.
        2. Nếu P = -Q (x_P == x_Q và y_P + y_Q = 0 mod p) -> Tiếp tuyến/cát tuyến thẳng đứng: R = O.
        3. Nếu P != Q (Cộng hai điểm phân biệt - Point Addition):
           Độ dốc tiếp tuyến qua P và Q:
               lambda = (y_Q - y_P) / (x_Q - x_P) mod p
        4. Nếu P == Q (Nhân đôi điểm - Point Doubling):
           Nếu y_P = 0 -> Tiếp tuyến thẳng đứng: R = O.
           Độ dốc tiếp tuyến tại P:
               lambda = (3 * x_P^2 + a) / (2 * y_P) mod p
        5. Tọa độ điểm tổng R(x_R, y_R):
           x_R = lambda^2 - x_P - x_Q mod p
           y_R = lambda * (x_P - x_R) - y_P mod p
        """
        # Trường hợp 1: Có điểm vô cực
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P

        # Trường hợp 2: Hai điểm đối xứng qua trục Ox (cùng hoành độ, tổng tung độ = 0 mod p)
        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return INFINITY_POINT

        # Tính hệ số góc lambda (slope)
        if P.x != Q.x:
            # Phép cộng điểm thông thường (Point Addition)
            numerator = (Q.y - P.y) % self.p
            denominator = (Q.x - P.x) % self.p
            inv_denom = mod_inverse(denominator, self.p)
            lam = (numerator * inv_denom) % self.p
        else:
            # P == Q: Phép nhân đôi điểm (Point Doubling)
            if P.y == 0:
                return INFINITY_POINT
            numerator = (3 * (P.x ** 2) + self.a) % self.p
            denominator = (2 * P.y) % self.p
            inv_denom = mod_inverse(denominator, self.p)
            lam = (numerator * inv_denom) % self.p

        # Tính tọa độ điểm kết quả
        x_r = ((lam ** 2) - P.x - Q.x) % self.p
        y_r = (lam * (P.x - x_r) - P.y) % self.p

        return Point(x_r, y_r)

    def point_double(self, P: Point) -> Point:
        """Phép nhân đôi điểm: 2P = P + P."""
        return self.point_add(P, P)

    def scalar_mult(self, k: int, P: Point) -> Point:
        """
        Phép nhân vô hướng k * P trên đường cong Elliptic.
        Sử dụng thuật toán Double-and-Add (tương đương Square-and-Multiply).
        Độ phức tạp: O(log k) phép cộng/nhân đôi điểm.
        
        Nguyên lý:
        - Phân tích số nguyên k thành chuỗi bit nhị phân.
        - Lặp qua từng bit từ bit có trọng số thấp nhất đến cao nhất (hoặc ngược lại).
        - Nếu bit bằng 1: R = R + Current_P
        - Trong mỗi vòng: Current_P = 2 * Current_P
        """
        if k == 0 or P.is_infinity:
            return INFINITY_POINT

        # Chuẩn hóa k nếu k âm hoặc k lớn hơn bậc nhóm n
        if k < 0:
            k = -k
            P = self.point_neg(P)

        k = k % self.n if self.n else k
        if k == 0:
            return INFINITY_POINT

        result = INFINITY_POINT
        current = P

        while k > 0:
            if k & 1:  # Bit hiện tại là 1 -> Add
                result = self.point_add(result, current)
            current = self.point_double(current)  # Luôn luôn Double
            k >>= 1

        return result


# ==============================================================================
# PHẦN 3: ĐỊNH NGHĨA CÁC ĐƯỜNG CONG TIÊU CHUẨN
# ==============================================================================

# 1. Đường cong secp256k1 (Chuẩn SECG - Chuẩn sử dụng trong Bitcoin và Ethereum)
# Phương trình: y^2 = x^3 + 7 (mod p)  [a = 0, b = 7]
# Đặc số p = 2^256 - 2^32 - 977
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0x0000000000000000000000000000000000000000000000000000000000000000
SECP256K1_B = 0x0000000000000000000000000000000000000000000000000000000000000007
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_H = 1

SECP256K1 = EllipticCurve(
    name="secp256k1",
    p=SECP256K1_P,
    a=SECP256K1_A,
    b=SECP256K1_B,
    G_x=SECP256K1_GX,
    G_y=SECP256K1_GY,
    n=SECP256K1_N,
    h=SECP256K1_H
)

# 2. Đường cong số nhỏ TOY_CURVE_F17 phục vụ giảng dạy, tính tay và kiểm thử
# Phương trình: y^2 = x^3 + 2x + 2 (mod 17)
# Nhóm điểm có cấp n = 19 (nguyên tố), điểm sinh G = (5, 1)
TOY_CURVE_F17 = EllipticCurve(
    name="Toy_Curve_F17",
    p=17,
    a=2,
    b=2,
    G_x=5,
    G_y=1,
    n=19,
    h=1
)


# ==============================================================================
# PHẦN 4: THUẬT TOÁN CHỮ KÝ SỐ ECDSA (KEYGEN, SIGN, VERIFY)
# ==============================================================================

def generate_keypair(curve: EllipticCurve = SECP256K1) -> Tuple[int, Point]:
    """
    Quy trình Sinh cặp khóa ECDSA (Key Generation):
    1. Chọn một số nguyên ngẫu nhiên d trong khoảng [1, n - 1] làm Khóa riêng (Private Key).
       Sử dụng secrets.randbelow() của hệ điều hành để đảm bảo an toàn mật mã CSPRNG.
    2. Tính Khóa công khai (Public Key): Q = d * G bằng phép nhân vô hướng.
    3. Trả về cặp (d, Q).
    """
    # Chọn d bí mật thỏa 1 <= d <= n - 1
    d = secrets.randbelow(curve.n - 1) + 1
    # Tính Q = d * G
    Q = curve.scalar_mult(d, curve.G)
    return d, Q


def hash_message_to_int(message: Union[str, bytes], curve: EllipticCurve = SECP256K1) -> int:
    """
    Băm thông điệp bằng SHA-256 (tự viết từ sha256.py) và chuyển đổi thành số nguyên z.
    Nếu độ dài bit của mã băm lớn hơn độ dài bit của bậc nhóm n,
    thực hiện phép cắt bit (truncation) lấy các bit cao nhất theo chuẩn SEC 1 / FIPS 186-4.
    """
    if isinstance(message, str):
        msg_bytes = message.encode("utf-8")
    else:
        msg_bytes = bytes(message)

    # Gọi trực tiếp hàm băm SHA-256 từ file sha256.py
    digest_bytes = bam_sha256_bytes(msg_bytes)
    digest_int = int.from_bytes(digest_bytes, byteorder="big")

    # Cắt bit nếu hash_bitlen > n_bitlen
    digest_bitlen = len(digest_bytes) * 8
    n_bitlen = curve.n.bit_length()

    if digest_bitlen > n_bitlen:
        digest_int >>= (digest_bitlen - n_bitlen)

    return digest_int


def sign_message(
    message: Union[str, bytes],
    private_key: int,
    curve: EllipticCurve = SECP256K1,
    k_custom: Optional[int] = None
) -> Tuple[int, int]:
    """
    Quy trình Ký số ECDSA (Signature Generation):
    Đầu vào: Thông điệp m, khóa riêng d, tham số đường cong.
    Đầu ra: Cặp chữ ký (r, s).
    
    Các bước thực hiện chi tiết:
    1. Tính giá trị số nguyên đại diện cho mã băm: z = H(m).
    2. Vòng lặp sinh chữ ký:
       a. Chọn số nguyên ngẫu nhiên bí mật k (nonce) trong [1, n - 1].
          (Cực kỳ quan trọng: k phải ngẫu nhiên đồng đều và TUYỆT ĐỐI KHÔNG ĐƯỢC TÁI SỬ DỤNG!).
       b. Tính điểm tạm thời R = k * G = (x_1, y_1).
       c. Tính r = x_1 mod n. Nếu r == 0, quay lại bước a chọn k khác.
       d. Tính nghịch đảo k^(-1) mod n.
       e. Tính s = k^(-1) * (z + r * d) mod n. Nếu s == 0, quay lại bước a chọn k khác.
    3. Trả về cặp chữ ký số (r, s).
    """
    d = private_key
    if not (1 <= d < curve.n):
        raise ValueError(f"Khóa riêng d không hợp lệ! Bắt buộc phải nằm trong [1, {curve.n - 1}].")

    z = hash_message_to_int(message, curve)

    while True:
        # Nếu truyền k_custom (dùng cho ví dụ tính tay hoặc kiểm thử), sử dụng k đó
        if k_custom is not None:
            k = k_custom
        else:
            k = secrets.randbelow(curve.n - 1) + 1

        # b. Tính R = k * G = (x_1, y_1)
        R = curve.scalar_mult(k, curve.G)
        if R.is_infinity:
            if k_custom is not None:
                raise ValueError("k sinh ra điểm vô cực R, không thể ký!")
            continue

        # c. Tính r = x_1 mod n
        r = R.x % curve.n
        if r == 0:
            if k_custom is not None:
                raise ValueError("r = 0, cần chọn k khác!")
            continue

        # d. Tính k^(-1) mod n
        k_inv = mod_inverse(k, curve.n)

        # e. Tính s = k^(-1) * (z + r * d) mod n
        s = (k_inv * (z + r * d)) % curve.n
        if s == 0:
            if k_custom is not None:
                raise ValueError("s = 0, cần chọn k khác!")
            continue

        # Nếu truyền k_custom thì chỉ chạy 1 lần rồi thoát
        return r, s


def verify_signature(
    message: Union[str, bytes],
    signature: Tuple[int, int],
    public_key: Point,
    curve: EllipticCurve = SECP256K1
) -> bool:
    """
    Quy trình Xác minh chữ ký số ECDSA (Signature Verification):
    Đầu vào: Thông điệp m, cặp chữ ký (r, s), khóa công khai Q.
    Đầu ra: True nếu chữ ký hợp lệ, False nếu chữ ký bị giả mạo hoặc sai lệch.
    
    Các bước kiểm chứng chặt chẽ:
    1. Kiểm tra tính hợp lệ của khóa công khai Q:
       - Q != Point(Infinity)
       - Q thuộc đường cong (y_Q^2 = x_Q^3 + a*x_Q + b mod p)
       - n * Q = Point(Infinity)
    2. Kiểm tra biên độ của chữ ký (r, s):
       - 1 <= r <= n - 1
       - 1 <= s <= n - 1
       Nếu không thỏa, từ chối chữ ký ngay lập tức.
    3. Tính z = H(m).
    4. Tính w = s^(-1) mod n.
    5. Tính u_1 = z * w mod n và u_2 = r * w mod n.
    6. Tính điểm kiểm chứng P = u_1 * G + u_2 * Q = (x_P, y_P).
    7. Nếu P là điểm vô cực -> Chữ ký KHÔNG HỢP LỆ.
    8. Chữ ký hợp lệ khi và chỉ khi: r == x_P mod n.
    """
    r, s = signature
    Q = public_key

    # 1. Kiểm tra khóa công khai Q
    if Q.is_infinity:
        return False
    if not curve.is_on_curve(Q):
        return False
    if not curve.scalar_mult(curve.n, Q).is_infinity:
        return False

    # 2. Kiểm tra biên chữ ký r, s
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False

    # 3. Tính z = H(m)
    z = hash_message_to_int(message, curve)

    # 4. Tính w = s^(-1) mod n
    try:
        w = mod_inverse(s, curve.n)
    except (ZeroDivisionError, ValueError):
        return False

    # 5. Tính u_1 = z * w mod n và u_2 = r * w mod n
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    # 6. Tính P = u_1 * G + u_2 * Q
    point_u1_G = curve.scalar_mult(u1, curve.G)
    point_u2_Q = curve.scalar_mult(u2, Q)
    P = curve.point_add(point_u1_G, point_u2_Q)

    # 7. Nếu P là điểm vô cực, chữ ký không hợp lệ
    if P.is_infinity:
        return False

    # 8. Chữ ký đúng khi r == x_P mod n
    return (P.x % curve.n) == r


# ==============================================================================
# PHẦN 5: KIỂM CHỨNG TẤN CÔNG LỘ KHÓA DO TÁI SỬ DỤNG NONCE K (NONCE REUSE ATTACK)
# ==============================================================================

def attack_nonce_reuse(
    m1: Union[str, bytes],
    sig1: Tuple[int, int],
    m2: Union[str, bytes],
    sig2: Tuple[int, int],
    curve: EllipticCurve = SECP256K1
) -> int:
    """
    Mô phỏng đòn tấn công toán học kinh điển: Khôi phục khóa riêng d khi người ký
    tái sử dụng cùng một số nonce k cho hai thông điệp khác nhau (m1, m2).
    
    Cơ sở toán học:
        s1 = k^(-1) * (z1 + r * d) mod n
        s2 = k^(-1) * (z2 + r * d) mod n
        (r giống hệt nhau vì R = k * G)
    
    Nhân k cả 2 vế rồi trừ theo vế:
        k * (s1 - s2) = (z1 - z2) mod n
        => k = (z1 - z2) * (s1 - s2)^(-1) mod n
    
    Khi đã biết k, khôi phục khóa riêng d dễ dàng:
        d = (s1 * k - z1) * r^(-1) mod n
    """
    r1, s1 = sig1
    r2, s2 = sig2

    if r1 != r2:
        raise ValueError("Hai chữ ký không có cùng giá trị r (chưa tái sử dụng k)!")
    if s1 == s2:
        raise ValueError("s1 == s2: Hai thông điệp có thể trùng nhau hoặc chữ ký giống nhau hoàn toàn!")

    z1 = hash_message_to_int(m1, curve)
    z2 = hash_message_to_int(m2, curve)

    # Tính k bị lộ
    numerator_k = (z1 - z2) % curve.n
    denominator_k = (s1 - s2) % curve.n
    k_leaked = (numerator_k * mod_inverse(denominator_k, curve.n)) % curve.n

    # Khôi phục khóa riêng d
    numerator_d = (s1 * k_leaked - z1) % curve.n
    d_recovered = (numerator_d * mod_inverse(r1, curve.n)) % curve.n

    return d_recovered


# ==============================================================================
# PHẦN 6: KIỂM THỬ TÍNH TOÁN TAY VỚI THAM SỐ ĐƯỜNG CONG SỐ NHỎ (TOY CURVE F_17)
# ==============================================================================

def verify_toy_curve_calculation():
    """
    Thực hiện tính toán từng bước chi tiết trên đường cong số nhỏ TOY_CURVE_F17:
        y^2 = x^3 + 2x + 2 (mod 17)
        Bậc nhóm n = 19 (nguyên tố), Điểm sinh G = (5, 1).
    Phục vụ đối chiếu trực tiếp với Mục 6 trong báo cáo.
    """
    print("\n" + "=" * 80)
    print("VÍ DỤ TÍNH TAY VỚI THAM SỐ ĐƯỜNG CONG SỐ NHỎ (TOY CURVE TRÊN F_17)")
    print("=" * 80)
    curve = TOY_CURVE_F17
    print(f"[*] Phương trình: y^2 = x^3 + {curve.a}x + {curve.b} (mod {curve.p})")
    print(f"[*] Điểm sinh G = ({curve.G.x}, {curve.G.y}), Bậc nhóm n = {curve.n}")

    # 1. Sinh khóa
    d = 7  # Chọn khóa riêng d = 7
    Q = curve.scalar_mult(d, curve.G)
    print(f"\n[Bước 1: Sinh khóa]")
    print(f" - Khóa riêng bí mật d = {d}")
    print(f" - Khóa công khai Q = d * G = 7 * (5, 1) = ({Q.x}, {Q.y})")
    assert Q == Point(0, 6), f"Lỗi tính Q: mong đợi (0, 6) nhưng nhận {Q}"

    # 2. Ký thông điệp (chọn z = 10 đại diện cho mã băm, nonce k = 13)
    z = 10
    k = 13
    print(f"\n[Bước 2: Tạo chữ ký số]")
    print(f" - Giá trị băm thông điệp z = {z}")
    print(f" - Số ngẫu nhiên nonce k = {k}")

    # R = k * G
    R = curve.scalar_mult(k, curve.G)
    print(f" - Điểm tạm R = k * G = 13 * (5, 1) = ({R.x}, {R.y})")
    assert R == Point(16, 4), f"Lỗi tính R: mong đợi (16, 4) nhưng nhận {R}"

    r = R.x % curve.n
    k_inv = mod_inverse(k, curve.n)  # 13^(-1) mod 19 = 3 (13 * 3 = 39 = 2*19 + 1)
    s = (k_inv * (z + r * d)) % curve.n
    print(f" - Thành phần r = R.x mod n = {R.x} mod 19 = {r}")
    print(f" - Nghịch đảo k^(-1) mod n = 13^(-1) mod 19 = {k_inv}")
    print(f" - Thành phần s = k^(-1) * (z + r*d) mod n = {k_inv} * ({z} + {r}*{d}) mod 19 = {s}")
    assert (r, s) == (16, 5), f"Lỗi chữ ký: mong đợi (16, 5) nhưng nhận ({r}, {s})"
    print(f" => CẶP CHỮ KÝ SỐ HOÀN CHỈNH: (r={r}, s={s})")

    # 3. Xác minh chữ ký
    print(f"\n[Bước 3: Xác minh chữ ký số]")
    w = mod_inverse(s, curve.n)  # 5^(-1) mod 19 = 4 (5 * 4 = 20 = 1*19 + 1)
    u1 = (z * w) % curve.n        # (10 * 4) mod 19 = 40 mod 19 = 2
    u2 = (r * w) % curve.n        # (16 * 4) mod 19 = 64 mod 19 = 7
    print(f" - Tính w = s^(-1) mod n = {s}^(-1) mod 19 = {w}")
    print(f" - Tính u1 = z * w mod n = ({z} * {w}) mod 19 = {u1}")
    print(f" - Tính u2 = r * w mod n = ({r} * {w}) mod 19 = {u2}")

    P1 = curve.scalar_mult(u1, curve.G)
    P2 = curve.scalar_mult(u2, Q)
    P_check = curve.point_add(P1, P2)
    print(f" - Điểm u1 * G = 2 * (5, 1) = ({P1.x}, {P1.y})")
    print(f" - Điểm u2 * Q = 7 * (0, 6) = ({P2.x}, {P2.y})")
    print(f" - Điểm P = u1*G + u2*Q = ({P1.x}, {P1.y}) + ({P2.x}, {P2.y}) = ({P_check.x}, {P_check.y})")
    print(f" - Kiểm tra: P.x mod n = {P_check.x} mod 19 = {P_check.x % curve.n} | r = {r}")
    is_valid = (P_check.x % curve.n) == r
    print(f" => KẾT QUẢ XÁC MINH: {'HỢP LỆ (TRUE - 100% KHỚP NHAU)' if is_valid else 'THẤT BẠI (FALSE)'}")
    assert is_valid


# ==============================================================================
# PHẦN 7: BỘ KIỂM THỬ THỰC NGHIỆM ĐẦY ĐỦ VÀ ĐO ĐẠC HIỆU NĂNG
# ==============================================================================

def run_comprehensive_tests():
    """Bộ kiểm thử tính đúng đắn toàn diện cho hệ thống ECDSA secp256k1."""
    print("\n" + "=" * 80)
    print("CHẠY BỘ KIỂM THỬ TÍNH ĐÚNG ĐẮN VÀ BẢO MẬT (SECP256K1 + SHA-256)")
    print("=" * 80)

    # 1. Sinh khóa chuẩn
    d, Q = generate_keypair(SECP256K1)
    msg_goc = "Đồ án An toàn thông tin - Chữ ký số ECDSA secp256k1 - Sinh viên Trần Gia Thuận"
    print(f"[*] Thông điệp kiểm thử: \"{msg_goc}\"")
    print(f"[*] Khóa riêng d (256-bit): {hex(d)}")
    print(f"[*] Khóa công khai Q: {Q.to_short_str()}")

    # 2. Test Case 1: Chữ ký hợp lệ
    sig = sign_message(msg_goc, d, SECP256K1)
    r, s = sig
    print(f"\n[Test Case 1] Kiểm tra chữ ký hợp lệ:")
    print(f" - Chữ ký (r, s): r={hex(r)[:20]}..., s={hex(s)[:20]}...")
    valid = verify_signature(msg_goc, sig, Q, SECP256K1)
    print(f" - Kết quả kiểm tra: {'ĐẠT (PASS - Chữ ký chuẩn xác)' if valid else 'LỖI (FAIL)'}")
    assert valid, "Lỗi: Chữ ký hợp lệ bị từ chối!"

    # 3. Test Case 2: Thông điệp bị thay đổi 1 ký tự (Tampered Message)
    msg_gia_mao = msg_goc + "."
    tamper_msg_valid = verify_signature(msg_gia_mao, sig, Q, SECP256K1)
    print(f"\n[Test Case 2] Kiểm tra khi thông điệp bị kẻ xấu sửa đổi:")
    print(f" - Thông điệp giả mạo: \"{msg_gia_mao}\"")
    print(f" - Kết quả kiểm tra: {'ĐẠT (PASS - Đã phát hiện và bác bỏ thành công)' if not tamper_msg_valid else 'LỖI (FAIL - Chấp nhận giả mạo)'}")
    assert not tamper_msg_valid, "Lỗi: Thông điệp bị sửa đổi nhưng chữ ký vẫn được chấp nhận!"

    # 4. Test Case 3: Chữ ký bị can thiệp biến đổi r hoặc s (Tampered Signature)
    sig_gia_mao = (r + 1, s)
    tamper_sig_valid = verify_signature(msg_goc, sig_gia_mao, Q, SECP256K1)
    print(f"\n[Test Case 3] Kiểm tra khi chữ ký r bị kẻ xấu sửa thành r + 1:")
    print(f" - Kết quả kiểm tra: {'ĐẠT (PASS - Đã phát hiện can thiệp chữ ký)' if not tamper_sig_valid else 'LỖI (FAIL)'}")
    assert not tamper_sig_valid, "Lỗi: Chữ ký bị can thiệp nhưng vẫn được chấp nhận!"

    # 5. Test Case 4: Khóa công khai của người khác (Wrong Public Key)
    _, Q_khac = generate_keypair(SECP256K1)
    wrong_pk_valid = verify_signature(msg_goc, sig, Q_khac, SECP256K1)
    print(f"\n[Test Case 4] Kiểm tra khi người khác cố tình nhận vơ chữ ký (Khóa công khai sai):")
    print(f" - Kết quả kiểm tra: {'ĐẠT (PASS - Bác bỏ khóa công khai không khớp)' if not wrong_pk_valid else 'LỖI (FAIL)'}")
    assert not wrong_pk_valid, "Lỗi: Khóa công khai sai nhưng vẫn xác minh thành công!"

    # 6. Test Case 5: Tấn công tái sử dụng Nonce (Nonce Reuse Attack Demo)
    print(f"\n[Test Case 5] Mô phỏng tấn công đánh cắp khóa riêng do tái sử dụng nonce k:")
    m1 = "Lệnh chuyển tiền #01: Chuyển 10 BTC cho Alice"
    m2 = "Lệnh chuyển tiền #02: Chuyển 50 BTC cho Bob"
    k_chung = secrets.randbelow(SECP256K1.n - 1) + 1

    sig1 = sign_message(m1, d, SECP256K1, k_custom=k_chung)
    sig2 = sign_message(m2, d, SECP256K1, k_custom=k_chung)
    print(f" - Ký m1 với k cố định: r={hex(sig1[0])[:16]}...")
    print(f" - Ký m2 với k cố định: r={hex(sig2[0])[:16]}... (r hoàn toàn trùng khớp!)")

    d_danh_cap = attack_nonce_reuse(m1, sig1, m2, sig2, SECP256K1)
    print(f" - Khóa riêng gốc d     : {hex(d)}")
    print(f" - Khóa riêng khôi phục : {hex(d_danh_cap)}")
    assert d == d_danh_cap, "Lỗi: Khôi phục khóa riêng thất bại!"
    print(f" - Kết quả tấn công: ĐẠT (PASS - Khôi phục 100% khóa bí mật chỉ từ 2 chữ ký lặp nonce!)")


def benchmark_ecdsa_performance(iterations: int = 50):
    """
    Đo lường thời gian thực thi của các thao tác cốt lõi trên secp256k1:
    - Sinh khóa (Key Generation)
    - Ký số thông điệp (Signing)
    - Xác minh chữ ký (Verification)
    """
    print("\n" + "=" * 80)
    print(f"ĐO LƯỜNG HIỆU NĂNG THỰC TẾ (BENCHMARK {iterations} LẦN CHẠY - SECP256K1 PYTHON THUẦN)")
    print("=" * 80)

    keygen_times = []
    sign_times = []
    verify_times = []

    test_message = "Đồ án môn An toàn thông tin - Kiểm thử hiệu năng chữ ký số ECDSA secp256k1."

    # Chạy đo lường
    for _ in range(iterations):
        # 1. Đo sinh khóa
        t0 = time.perf_counter()
        d, Q = generate_keypair(SECP256K1)
        t1 = time.perf_counter()
        keygen_times.append((t1 - t0) * 1000.0)

        # 2. Đo ký số
        t0 = time.perf_counter()
        sig = sign_message(test_message, d, SECP256K1)
        t1 = time.perf_counter()
        sign_times.append((t1 - t0) * 1000.0)

        # 3. Đo xác minh
        t0 = time.perf_counter()
        is_ok = verify_signature(test_message, sig, Q, SECP256K1)
        t1 = time.perf_counter()
        verify_times.append((t1 - t0) * 1000.0)
        assert is_ok

    avg_keygen = sum(keygen_times) / iterations
    avg_sign = sum(sign_times) / iterations
    avg_verify = sum(verify_times) / iterations

    min_keygen, max_keygen = min(keygen_times), max(keygen_times)
    min_sign, max_sign = min(sign_times), max(sign_times)
    min_verify, max_verify = min(verify_times), max(verify_times)

    print(f"{'Thao tác':<22} | {'Trung bình (ms)':>16} | {'Nhanh nhất (ms)':>16} | {'Chậm nhất (ms)':>16} | {'Tốc độ (ops/s)':>15}")
    print("-" * 95)
    print(f"{'Sinh cặp khóa (KeyGen)':<22} | {avg_keygen:>16.3f} | {min_keygen:>16.3f} | {max_keygen:>16.3f} | {1000.0 / avg_keygen:>15.1f}")
    print(f"{'Tạo chữ ký (Sign)':<22} | {avg_sign:>16.3f} | {min_sign:>16.3f} | {max_sign:>16.3f} | {1000.0 / avg_sign:>15.1f}")
    print(f"{'Xác minh (Verify)':<22} | {avg_verify:>16.3f} | {min_verify:>16.3f} | {max_verify:>16.3f} | {1000.0 / avg_verify:>15.1f}")
    print("=" * 95)
    print(f"Nhận xét thực nghiệm:")
    print(f"- Thời gian Xác minh chữ ký (Verify ~ {avg_verify:.2f} ms) gấp xấp xỉ 2 lần thời gian Ký (Sign ~ {avg_sign:.2f} ms)")
    print(f"  bởi vì hàm Verify thực hiện tới 2 phép nhân vô hướng (u1*G + u2*Q) thay vì 1 phép nhân (k*G) như lúc Ký.")
    print(f"- Toàn bộ thuật toán chạy trên Python thuần 100% không dùng thư viện C tăng tốc mà vẫn đạt hơn {1000.0 / avg_sign:.0f} lượt ký/giây.")


def interactive_demo():
    """Giao diện dòng lệnh CLI tương tác trực quan cho sinh viên và giảng viên kiểm thử."""
    print("\n" + "=" * 80)
    print("    CHƯƠNG TRÌNH DEMO CHỮ KÝ SỐ ECDSA SECP256K1 - PYTHON THUẦN")
    print("    Sinh viên thực hiện: Trần Gia Thuận (Chữ số cuối SID: 3)")
    print("=" * 80)

    # 1. Sinh khóa
    print("\n[+] Đang sinh cặp khóa ngẫu nhiên trên đường cong secp256k1...")
    t0 = time.perf_counter()
    d, Q = generate_keypair(SECP256K1)
    t_gen = (time.perf_counter() - t0) * 1000.0
    print(f"[✓] Đã sinh cặp khóa thành công trong {t_gen:.2f} ms:")
    print(f"    - Khóa riêng bí mật d (256-bit): {hex(d)}")
    print(f"    - Khóa công khai Q(x, y):")
    print(f"      + x = {hex(Q.x)}")
    print(f"      + y = {hex(Q.y)}")

    # 2. Thông điệp ký thử
    sample_text = "Tôi là Trần Gia Thuận, cam kết báo cáo đồ án An toàn thông tin này hoàn toàn trung thực."
    print(f"\n[+] Thông điệp ký số thử nghiệm (Tiếng Việt Unicode UTF-8):")
    print(f"    \"{sample_text}\"")

    # 3. Ký số
    t0 = time.perf_counter()
    sig = sign_message(sample_text, d, SECP256K1)
    t_sign = (time.perf_counter() - t0) * 1000.0
    r, s = sig
    print(f"\n[✓] Tạo chữ ký số thành công trong {t_sign:.2f} ms:")
    print(f"    - Thành phần r ({r.bit_length()} bits): {hex(r)}")
    print(f"    - Thành phần s ({s.bit_length()} bits): {hex(s)}")

    # 4. Xác minh chữ ký với bản gốc
    t0 = time.perf_counter()
    is_valid = verify_signature(sample_text, sig, Q, SECP256K1)
    t_ver = (time.perf_counter() - t0) * 1000.0
    print(f"\n[✓] Xác minh chữ ký với thông điệp gốc trong {t_ver:.2f} ms:")
    print(f"    - Trạng thái chữ ký: {'HỢP LỆ (VALID) [✓]' if is_valid else 'BỊ LỖI (INVALID) [X]'}")

    # 5. Xác minh khi kẻ thù chỉnh sửa nội dung
    tampered_text = sample_text + " [Kẻ gian đã sửa đổi]"
    tampered_result = verify_signature(tampered_text, sig, Q, SECP256K1)
    print(f"\n[!] Thử xác minh khi thông điệp bị can thiệp trái phép:")
    print(f"    \"{tampered_text}\"")
    print(f"    - Trạng thái chữ ký: {'BỊ GIẢ MẠO - ĐÃ PHÁT HIỆN VÀ TỪ CHỐI [✓]' if not tampered_result else 'NGUY HIỂM: Chấp nhận thông điệp giả [X]'}")


# ==============================================================================
# HÀM CHÍNH (MAIN ENTRY POINT)
# ==============================================================================

if __name__ == "__main__":
    # 1. Chạy xác thực ví dụ tính tay nhỏ F_17 (đối chiếu Mục 6 Báo cáo)
    verify_toy_curve_calculation()

    # 2. Chạy Demo tương tác trực quan
    interactive_demo()

    # 3. Chạy bộ kiểm thử toàn diện các kịch bản tấn công
    run_comprehensive_tests()

    # 4. Đo lường và in bảng hiệu năng thực nghiệm
    benchmark_ecdsa_performance(iterations=30)
