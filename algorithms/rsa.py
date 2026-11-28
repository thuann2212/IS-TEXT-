# -*- coding: utf-8 -*-
"""
================================================================================
HỆ THỐNG MẬT MÃ BẤT ĐỐI XỨNG RSA (RIVEST - SHAMIR - ADLEMAN)
Môn học: An toàn thông tin (Information Security)
Sinh viên thực hiện: Trần Gia Thuận
Chữ số cuối SID: 3 (3 mod 3 = 0 -> Đề tài: Mật mã bất đối xứng RSA)
Ngôn ngữ: Python thuần 3.12 (Không sử dụng thư viện mật mã có sẵn)
================================================================================
"""

import sys
import math
import time
import secrets
from typing import Tuple, List, Dict, Any


# ==============================================================================
# PHẦN 1: CÁC HÀM TOÁN HỌC NỀN TẢNG (MATHEMATICAL PRIMITIVES)
# ==============================================================================

def pow_mod(base: int, exp: int, mod: int) -> int:
    """
    Thuật toán Lũy thừa nhanh theo modulo (Square-and-Multiply / Binary Exponentiation).
    Tính toán (base^exp) mod mod với độ phức tạp thời gian O(log exp).
    
    Nguyên lý:
    - Biểu diễn số mũ exp dưới dạng nhị phân.
    - Lặp từ bit thấp nhất đến bit cao nhất:
      + Nếu bit hiện tại là 1 (exp lẻ), nhân kết quả với base (mod mod).
      + Trong mỗi bước lặp, bình phương base (mod mod) và dịch phải exp (exp >>= 1).
    """
    if mod <= 0:
        raise ValueError("Modulo phải là số nguyên dương lớn hơn 0.")
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError("Hàm pow_mod chỉ hỗ trợ số mũ không âm.")

    res = 1
    base = base % mod
    while exp > 0:
        if exp & 1:  # Bit cuối cùng là 1 (exp lẻ)
            res = (res * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return res


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Thuật toán Euclid mở rộng (Extended Euclidean Algorithm).
    Tìm ước số chung lớn nhất gcd(a, b) và các hệ số Bezout (x, y) thỏa mãn:
        a * x + b * y = gcd(a, b)
    
    Trả về:
        (gcd_val, x, y)
    """
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
        
    return a, x0, y0


def mod_inverse(e: int, phi: int) -> int:
    """
    Tìm nghịch đảo modulo của e theo phi: e^(-1) mod phi.
    Tức là tìm d sao cho: (e * d) mod phi = 1.
    Sử dụng nghiệm x từ phương trình Bezout của thuật toán Euclid mở rộng.
    """
    if phi <= 1:
        raise ValueError(f"Modulo phi phải lớn hơn 1 (phi={phi}).")
    gcd_val, x, _ = extended_gcd(e % phi, phi)
    if gcd_val != 1:
        raise ValueError(f"Không tồn tại nghịch đảo modulo: gcd({e}, {phi}) = {gcd_val} != 1.")
    return x % phi


# Bảng sàng số nguyên tố nhỏ (primes < 1000) nhằm loại bỏ nhanh 85% hợp số ngẫu nhiên
# trước khi thực hiện phép kiểm tra Miller-Rabin tốn kém tính toán.
SMALL_PRIMES = [
      3,   5,   7,  11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,  53,  59,
     61,  67,  71,  73,  79,  83,  89,  97, 101, 103, 107, 109, 113, 127, 131, 137,
    139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
    229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
    521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
    619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727,
    733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
    839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
    953, 967, 971, 977, 983, 991, 997
]


def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """
    Kiểm tra số nguyên tố xác suất Miller-Rabin (Miller-Rabin Primality Test).
    Tham số k: số vòng lặp kiểm tra độc lập (mặc định k = 40 cho xác suất sai số <= 4^(-40) < 10^(-24)).
    
    Thuật toán:
    1. Kiểm tra các trường hợp cơ sở: n < 2, n == 2, n == 3, n chẵn.
    2. Sàng nhanh bằng cách chia thử với bảng các số nguyên tố nhỏ.
    3. Phân tích n - 1 = 2^s * d (với d lẻ).
    4. Lặp k vòng:
       - Chọn ngẫu nhiên cơ số an toàn a trong đoạn [2, n - 2] bằng secrets.randbelow.
       - Tính x = a^d mod n.
       - Nếu x == 1 hoặc x == n - 1, vượt qua vòng này.
       - Lặp s - 1 lần: x = x^2 mod n. Nếu x == n - 1, tiếp tục vòng mới.
       - Nếu không đạt được n - 1, n chắc chắn là hợp số (Composite).
    5. Nếu vượt qua k vòng, n là số nguyên tố với độ tin cậy cực cao.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
        
    # Bước sàng nhanh với các số nguyên tố nhỏ
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
            
    # Phân tích n - 1 thành dạng 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
        
    # Lặp kiểm thử Miller-Rabin qua k vòng
    for _ in range(k):
        # Chọn ngẫu nhiên cơ số a trong [2, n - 2]
        a = secrets.randbelow(n - 3) + 2
        x = pow_mod(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
            
        is_composite = True
        for _ in range(s - 1):
            x = pow_mod(x, 2, n)
            if x == n - 1:
                is_composite = False
                break
                
        if is_composite:
            return False
            
    return True


def generate_prime(bits: int) -> int:
    """
    Sinh ngẫu nhiên một số nguyên tố lớn có đúng số lượng `bits` bit.
    Đảm bảo:
    - Bit cao nhất bằng 1 (để giữ đúng kích thước bit).
    - Bit thấp nhất bằng 1 (để số luôn là số lẻ).
    - Sử dụng bộ sinh số ngẫu nhiên an toàn mật mã `secrets`.
    """
    if bits < 8:
        raise ValueError("Độ dài bit tối thiểu của số nguyên tố phải là 8 bit.")
        
    while True:
        # Sinh số ngẫu nhiên có đúng `bits` bit
        candidate = secrets.randbits(bits)
        # Bật bit MSB (để đảm bảo đủ bit) và LSB (để là số lẻ)
        candidate |= (1 << (bits - 1)) | 1
        
        if is_prime_miller_rabin(candidate, k=40):
            return candidate


# ==============================================================================
# PHẦN 2: THUẬT TOÁN SINH CẶP KHÓA RSA (KEY GENERATION)
# ==============================================================================

def generate_keypair(key_size: int = 1024, e: int = 65537) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Quy trình sinh cặp khóa RSA chuẩn:
    1. Sinh 2 số nguyên tố lớn độc lập p và q có độ dài bit xấp xỉ key_size // 2.
    2. Đảm bảo p != q và |p - q| đủ lớn (tránh tấn công phân tích Fermat).
    3. Tính modulo công khai: n = p * q.
    4. Tính hàm số Euler phi(n) = (p - 1) * (q - 1).
    5. Kiểm tra gcd(e, phi(n)) == 1. Thường chọn e = 65537 (số Fermat F4 = 2^16 + 1).
    6. Tính khóa riêng d = e^(-1) mod phi(n) bằng thuật toán Euclid mở rộng.
    7. Tính các tham số tối ưu hóa tăng tốc giải mã bằng Định lý Thặng dư Trung Hoa (RSA-CRT):
       - dp = d mod (p - 1)
       - dq = d mod (q - 1)
       - qinv = q^(-1) mod p
       
    Trả về:
        (public_key, private_key)
    """
    if key_size < 16:
        raise ValueError("Kích thước khóa RSA tối thiểu phải là 16 bit.")
    if e < 3 or (e % 2 == 0):
        raise ValueError("Số mũ công khai e phải là số nguyên lẻ >= 3 (để nguyên tố cùng nhau với phi(n) chẵn).")
    if e >= (1 << (key_size - 2)):
        raise ValueError(f"Số mũ công khai e={e} quá lớn so với kích thước khóa {key_size}-bit (cần 1 < e < phi(n)).")

    half_bits = key_size // 2
    other_bits = key_size - half_bits

    while True:
        p = generate_prime(half_bits)
        q = generate_prime(other_bits)

        # Đảm bảo p != q, n có đúng key_size bit và chênh lệch |p - q| đủ lớn chống phân tích Fermat
        diff = abs(p - q)
        if p != q and diff > (1 << (half_bits - 100 if half_bits > 100 else half_bits // 2)):
            n = p * q
            if n.bit_length() != key_size:
                continue
            phi = (p - 1) * (q - 1)
            if not (1 < e < phi):
                continue

            # Kiểm tra e và phi(n) có nguyên tố cùng nhau hay không
            gcd_val, _, _ = extended_gcd(e, phi)
            if gcd_val != 1:
                continue

            # Tính khóa bí mật d và kiểm tra ngưỡng an toàn chống tấn công Wiener (d > n^(1/4) / 3)
            d = mod_inverse(e, phi)
            if key_size >= 64 and (3 * d <= math.isqrt(math.isqrt(n))):
                continue
            break
    
    # Tính các tham số tối ưu hóa Định lý Thặng dư Trung Hoa (CRT)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = mod_inverse(q, p)
    
    public_key = {
        "e": e,
        "n": n,
        "bits": key_size
    }
    
    private_key = {
        "d": d,
        "n": n,
        "p": p,
        "q": q,
        "dp": dp,
        "dq": dq,
        "qinv": qinv,
        "phi": phi,
        "bits": key_size
    }
    
    return public_key, private_key


# ==============================================================================
# PHẦN 3: CÁC THUẬT TOÁN MÃ HÓA & GIẢI MÃ NGUYÊN BẢN (CORE RSA ARITHMETIC)
# ==============================================================================

def rsa_encrypt_int(m: int, pubkey: Dict[str, Any]) -> int:
    """
    Mã hóa số nguyên m thành bản mã c:
        c = (m^e) mod n
    Yêu cầu: 0 <= m < n.
    """
    n = pubkey["n"]
    e = pubkey["e"]
    if m < 0 or m >= n:
        raise ValueError(f"Thông điệp nguyên m phải thỏa mãn 0 <= m < n (m={m.bit_length()} bits, n={n.bit_length()} bits).")
    return pow_mod(m, e, n)


def rsa_decrypt_int(c: int, privkey: Dict[str, Any], use_crt: bool = True) -> int:
    """
    Giải mã bản mã c thành thông điệp số nguyên m:
    - Nếu use_crt == False: Giải mã tiêu chuẩn m = (c^d) mod n.
    - Nếu use_crt == True: Giải mã tăng tốc bằng Định lý Thặng dư Trung Hoa (RSA-CRT):
        m1 = c^dp mod p
        m2 = c^dq mod q
        h = (qinv * (m1 - m2)) mod p
        m = m2 + h * q
      (Tốc độ nhanh gấp khoảng 4 lần giải mã tiêu chuẩn).
    """
    n = privkey["n"]
    if c < 0 or c >= n:
        raise ValueError("Bản mã c không hợp lệ trong vành Z_n (cần 0 <= c < n).")
        
    if not use_crt or "p" not in privkey:
        d = privkey["d"]
        return pow_mod(c, d, n)
    else:
        # Tăng tốc RSA-CRT (Garner's Formula)
        p = privkey["p"]
        q = privkey["q"]
        dp = privkey["dp"]
        dq = privkey["dq"]
        qinv = privkey["qinv"]
        
        m1 = pow_mod(c % p, dp, p)
        m2 = pow_mod(c % q, dq, q)
        h = (qinv * ((m1 - m2) % p)) % p
        m = m2 + h * q
        return m


# ==============================================================================
# PHẦN 4: CƠ CHẾ ĐỆM PKCS#1 v1.5 & CHIA KHỐI THÔNG ĐIỆP VĂN BẢN
# ==============================================================================

def pkcs1_pad(data: bytes, target_len: int) -> bytes:
    """
    Cơ chế đệm chuẩn PKCS#1 v1.5 (Encryption Block Type 2):
    Định dạng khối đệm:
        EB = 0x00 || 0x02 || PS || 0x00 || Data
    Trong đó:
    - 0x00, 0x02: Các byte tiền tố bắt buộc nhận diện khối mã hóa công khai.
    - PS (Padding String): Chuỗi các byte ngẫu nhiên KHÁC 0 (PS[i] != 0x00),
      có độ dài tối thiểu là 8 byte (đảm bảo tính ngẫu nhiên, chống tấn công vét cạn và tấn công đồng cấu).
    - 0x00: Byte phân cách giữa phần đệm và dữ liệu gốc.
    - target_len: Kích thước khối theo byte, bằng ceil(key_size_in_bits / 8).
    """
    if target_len < 11:
        raise ValueError("Kích thước khối đích target_len phải tối thiểu 11 byte theo chuẩn PKCS#1 v1.5.")
    data_len = len(data)
    # Cần tối thiểu 11 byte overhead: 1 (0x00) + 1 (0x02) + >=8 (PS) + 1 (0x00)
    if data_len > target_len - 11:
        raise ValueError(f"Độ dài dữ liệu ({data_len} bytes) vượt quá giới hạn khối ({target_len - 11} bytes).")

    ps_len = target_len - data_len - 3
    # Sinh chuỗi PS ngẫu nhiên không chứa byte 0x00
    ps = bytearray()
    while len(ps) < ps_len:
        rand_byte = secrets.randbelow(256)
        if rand_byte != 0:
            ps.append(rand_byte)

    return b'\x00\x02' + bytes(ps) + b'\x00' + data


def pkcs1_unpad(padded: bytes, target_len: int) -> bytes:
    """
    Giải đệm chuẩn PKCS#1 v1.5 (RFC 8017 Section 7.2.2):
    Kiểm tra cấu trúc 0x00 || 0x02 || PS (>= 8 bytes != 0x00) || 0x00 || Data.
    Quét toàn bộ khối không thoát sớm và chỉ ném một thông báo lỗi thống nhất
    nhằm phòng chống tấn công Bleichenbacher Padding Oracle.
    """
    if target_len < 11:
        raise ValueError("Kích thước khối đích target_len phải tối thiểu 11 byte.")
    if len(padded) == target_len - 1 and padded[0] == 0x02:
        padded = b'\x00' + padded
    if len(padded) != target_len:
        raise ValueError("Giải đệm PKCS#1 v1.5 không hợp lệ.")

    bad = (padded[0] ^ 0x00) | (padded[1] ^ 0x02)
    sep_idx = -1
    found_sep = 0
    for i in range(2, target_len):
        is_zero = 1 if padded[i] == 0x00 else 0
        if is_zero and not found_sep:
            sep_idx = i
            found_sep = 1

    if not found_sep or (sep_idx - 2 < 8):
        bad |= 1

    if bad != 0:
        raise ValueError("Giải đệm PKCS#1 v1.5 không hợp lệ.")

    return padded[sep_idx + 1:]


def encrypt_text(plaintext: str, pubkey: Dict[str, Any], use_padding: bool = True) -> List[int]:
    """
    Mã hóa chuỗi ký tự bất kỳ (hỗ trợ đầy đủ Unicode / UTF-8 tiếng Việt, kể cả chuỗi rỗng):
    1. Mã hóa văn bản sang mảng byte UTF-8.
    2. Xác định kích thước khối k = (n.bit_length() + 7) // 8.
    3. Chia nhỏ dữ liệu thành các khối thích hợp:
       - Nếu use_padding == True: Mỗi khối có kích thước tối đa k - 11 bytes, được đệm PKCS#1 v1.5.
       - Nếu use_padding == False (Raw chunking): Mỗi khối tối đa k - 3 bytes theo cấu trúc
         0x00 || chunk_len (2B) || chunk || 0x00... (cố định k byte để đảm bảo m < n và bảo toàn byte 0x00 đầu).
    4. Chuyển mỗi khối byte thành số nguyên m < n theo thứ tự big-endian.
    5. Mã hóa từng khối c = (m^e) mod n.

    Trả về:
        Danh sách các số nguyên bản mã [c_0, c_1, ...]
    """
    raw_bytes = plaintext.encode("utf-8")
    mod_len = (pubkey["n"].bit_length() + 7) // 8

    if use_padding:
        max_chunk = mod_len - 11
        if max_chunk <= 0:
            raise ValueError("Kích thước modulo quá nhỏ để áp dụng chuẩn đệm PKCS#1 v1.5.")
    else:
        max_chunk = mod_len - 3  # 1 byte 0x00 (đảm bảo m < n) + 2 byte ghi độ dài chunk
        if max_chunk <= 0 or max_chunk > 65535:
            raise ValueError("Kích thước modulo không hợp lệ cho chế độ chia khối thô (raw chunking).")

    # Đảm bảo chuỗi rỗng "" vẫn được đóng gói và mã hóa thành 1 khối hợp lệ thay vì danh sách rỗng
    chunks = [b""] if len(raw_bytes) == 0 else [raw_bytes[i:i + max_chunk] for i in range(0, len(raw_bytes), max_chunk)]

    cipher_chunks = []
    for chunk in chunks:
        if use_padding:
            padded_block = pkcs1_pad(chunk, mod_len)
        else:
            chunk_len = len(chunk)
            padded_block = b'\x00' + chunk_len.to_bytes(2, byteorder="big") + chunk + bytes(max_chunk - chunk_len)

        m = int.from_bytes(padded_block, byteorder="big")
        c = rsa_encrypt_int(m, pubkey)
        cipher_chunks.append(c)

    return cipher_chunks


def decrypt_text(cipher_chunks: List[int], privkey: Dict[str, Any], use_padding: bool = True, use_crt: bool = True) -> str:
    """
    Giải mã danh sách các khối số nguyên bản mã trở lại văn bản UTF-8 gốc:
    1. Giải mã từng số nguyên c: m = (c^d) mod n (dùng CRT để tăng tốc).
    2. Chuyển số nguyên m thành mảng byte có độ dài mod_len.
    3. Gỡ bỏ đệm PKCS#1 v1.5 (hoặc kiểm tra khung và bóc tách độ dài đối với raw chunking).
    4. Ghép nối các khối byte và giải mã UTF-8 trở lại chuỗi văn bản.
    """
    if not cipher_chunks:
        raise ValueError("Danh sách khối bản mã không được rỗng.")
    mod_len = (privkey["n"].bit_length() + 7) // 8
    max_raw_chunk = mod_len - 3
    recovered_bytes = bytearray()

    for c in cipher_chunks:
        m = rsa_decrypt_int(c, privkey, use_crt=use_crt)
        m_bytes = m.to_bytes(mod_len, byteorder="big")

        if use_padding:
            chunk = pkcs1_unpad(m_bytes, mod_len)
        else:
            if max_raw_chunk <= 0 or m_bytes[0] != 0x00:
                raise ValueError("Khối giải mã thô (raw chunk) bị hỏng hoặc sai khóa.")
            chunk_len = int.from_bytes(m_bytes[1:3], byteorder="big")
            if chunk_len > max_raw_chunk or any(b != 0 for b in m_bytes[3 + chunk_len:]):
                raise ValueError("Độ dài hoặc phần đệm 0x00 của khối giải mã thô không hợp lệ.")
            chunk = m_bytes[3:3 + chunk_len]

        recovered_bytes.extend(chunk)

    return recovered_bytes.decode("utf-8")


# ==============================================================================
# PHẦN 5: ĐÁNH GIÁ THỰC NGHIỆM & KIỂM CHỨNG TÍNH ĐÚNG ĐẮN
# ==============================================================================

def verify_hand_calculation_example():
    """
    Kiểm chứng thực nghiệm ví dụ tính tay nhỏ (p = 61, q = 53)
    để đối chiếu tuyệt đối với lý thuyết trong Mục 6 của Báo cáo.
    """
    print("\n" + "="*70)
    print("KIỂM CHỨNG VÍ DỤ TÍNH TAY VỚI THAM SỐ NHỎ (p = 61, q = 53)")
    print("="*70)
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    
    # 1. Tính nghịch đảo
    d = mod_inverse(e, phi)
    print("1. Tham số hệ thống:")
    print(f"   p = {p}, q = {q}")
    print(f"   n = p * q = {n}")
    print(f"   phi(n) = (p - 1)*(q - 1) = {phi}")
    print(f"   Khóa công khai (e, n): ({e}, {n})")
    print(f"   Khóa bí mật    (d, n): ({d}, {n})")
    print(f"   Kiểm tra e*d mod phi(n): ({e} * {d}) mod {phi} = {(e * d) % phi}")

    # 2. Mã hóa ký tự 'A' (ASCII = 65)
    m = 65
    c = pow_mod(m, e, n)
    print(f"\n2. Mã hóa thông điệp số m = {m} (ASCII 'A'):")
    print(f"   c = m^e mod n = {m}^{e} mod {n} = {c}")

    # 3. Giải mã
    m_dec = pow_mod(c, d, n)
    print(f"\n3. Giải mã bản mã c = {c}:")
    print(f"   m = c^d mod n = {c}^{d} mod {n} = {m_dec}")
    assert m == m_dec, "Lỗi giải mã ví dụ tính tay!"
    print("   -> KẾT QUẢ: GIẢI MÃ CHÍNH XÁC 100%!")


def benchmark_rsa_performance():
    """
    Đánh giá thực nghiệm hiệu năng tính toán của thuật toán RSA:
    - Đo thời gian sinh khóa, mã hóa, giải mã tiêu chuẩn và giải mã CRT
      trên các kích thước khóa phổ biến: 512-bit, 1024-bit và 2048-bit.
    """
    test_message = (
        "Khoa Công nghệ Thông tin - Đồ án An toàn thông tin RSA. "
        "Sinh viên: Trần Gia Thuận. Mã hóa chuỗi ký tự tiếng Việt: "
        "Bảo mật thông tin là nền tảng của chuyển đổi số quốc gia!"
    )

    key_sizes = [512, 1024, 2048]
    results = []

    print("\n" + "="*85)
    print("ĐÁNH GIÁ THỰC NGHIỆM HIỆU NĂNG TÍNH TOÁN RSA TRÊN CÁC KÍCH THƯỚC KHÓA")
    print(f"Thông điệp thử nghiệm ({len(test_message)} ký tự, {len(test_message.encode('utf-8'))} bytes UTF-8): \"{test_message[:45]}...\"")
    print("="*85)

    for bits in key_sizes:
        print(f"\n[*] Đang đánh giá khóa {bits}-bit...")

        # 1. Đo thời gian sinh khóa
        t0 = time.perf_counter()
        pub, priv = generate_keypair(key_size=bits, e=65537)
        t_keygen = (time.perf_counter() - t0) * 1000.0  # ms

        # 2. Đo thời gian mã hóa (có đệm PKCS#1 v1.5)
        t0 = time.perf_counter()
        cipher_blocks = encrypt_text(test_message, pub, use_padding=True)
        t_enc = (time.perf_counter() - t0) * 1000.0  # ms

        # 3. Đo thời gian giải mã chuẩn (không dùng CRT)
        t0 = time.perf_counter()
        dec_std = decrypt_text(cipher_blocks, priv, use_padding=True, use_crt=False)
        t_dec_std = (time.perf_counter() - t0) * 1000.0  # ms

        # 4. Đo thời gian giải mã tăng tốc CRT
        t0 = time.perf_counter()
        dec_crt = decrypt_text(cipher_blocks, priv, use_padding=True, use_crt=True)
        t_dec_crt = (time.perf_counter() - t0) * 1000.0  # ms

        # Kiểm tra tính toàn vẹn
        assert test_message == dec_std == dec_crt, f"Lỗi tính toàn vẹn ở mức khóa {bits}-bit!"

        speedup = t_dec_std / t_dec_crt if t_dec_crt > 0 else 1.0

        results.append({
            "bits": bits,
            "keygen_ms": t_keygen,
            "enc_ms": t_enc,
            "dec_std_ms": t_dec_std,
            "dec_crt_ms": t_dec_crt,
            "speedup": speedup,
            "blocks": len(cipher_blocks)
        })

    print("\n" + "="*85)
    print(f"{'Kích thước':<12} | {'Sinh khóa':<12} | {'Mã hóa':<12} | {'Giải mã chuẩn':<14} | {'Giải mã CRT':<13} | {'Gia tốc CRT':<10}")
    print("-"*85)
    for r in results:
        print(f"{r['bits']}-bit{'':<6} | {r['keygen_ms']:>8.2f} ms | {r['enc_ms']:>8.2f} ms | {r['dec_std_ms']:>10.2f} ms | {r['dec_crt_ms']:>9.2f} ms | {r['speedup']:>8.2f}x")
    print("="*85)
    print("Ghi chú: Tốc độ giải mã với CRT tăng gấp ~3.0x - 4.0x so với giải mã chuẩn.")
    return results


def interactive_demo():
    """
    Giao diện dòng lệnh (CLI) tương tác trực quan cho sinh viên và giảng viên kiểm thử.
    """
    print("\n" + "="*70)
    print("    CHƯƠNG TRÌNH DEMO MẬT MÃ BẤT ĐỐI XỨNG RSA - PYTHON THUẦN")
    print("    Sinh viên: Trần Gia Thuận (Chữ số cuối SID: 3)")
    print("="*70)
    
    print("\n[+] Đang sinh cặp khóa RSA 1024-bit ngẫu nhiên...")
    t0 = time.perf_counter()
    pub, priv = generate_keypair(key_size=1024, e=65537)
    t_gen = (time.perf_counter() - t0) * 1000.0
    print(f"[✓] Đã sinh cặp khóa thành công trong {t_gen:.2f} ms!")
    print(f"    - Modulo n ({pub['n'].bit_length()} bits): {str(pub['n'])[:40]}...{str(pub['n'])[-20:]}")
    print(f"    - Số mũ công khai e: {pub['e']}")
    print(f"    - Khóa riêng d ({priv['d'].bit_length()} bits): {str(priv['d'])[:40]}...{str(priv['d'])[-20:]}")
    
    sample_text = "Mật mã RSA được phát minh năm 1977 bởi Ron Rivest, Adi Shamir và Leonard Adleman tại MIT."
    print(f"\n[+] Thông điệp thử nghiệm tiếng Việt:\n    \"{sample_text}\"")
    
    # Mã hóa
    t0 = time.perf_counter()
    ciphertext = encrypt_text(sample_text, pub, use_padding=True)
    t_enc = (time.perf_counter() - t0) * 1000.0
    print(f"\n[✓] Mã hóa thành công ({len(ciphertext)} khối bản mã) trong {t_enc:.2f} ms:")
    for idx, c in enumerate(ciphertext):
        print(f"    Khối #{idx}: {hex(c)[:35]}...{hex(c)[-20:]}")
        
    # Giải mã
    t0 = time.perf_counter()
    decrypted_text = decrypt_text(ciphertext, priv, use_padding=True, use_crt=True)
    t_dec = (time.perf_counter() - t0) * 1000.0
    print(f"\n[✓] Giải mã thành công (RSA-CRT) trong {t_dec:.2f} ms:")
    print(f"    \"{decrypted_text}\"")
    
    if sample_text == decrypted_text:
        print("\n[==>] XÁC THỰC HOÀN TOÀN TRÙNG KHỚP 100%! BẢN RÕ TOÀN VẸN TUYỆT ĐỐI.")
    else:
        print("\n[!] CẢNH BÁO: Dữ liệu giải mã không khớp!")


if __name__ == "__main__":
    # 1. Chạy xác thực ví dụ tính tay nhỏ (p = 61, q = 53)
    verify_hand_calculation_example()
    
    # 2. Chạy Demo tương tác sinh khóa và mã hóa/giải mã tiếng Việt
    interactive_demo()
    
    # 3. Đo đạc và in bảng hiệu năng thực nghiệm
    benchmark_rsa_performance()
