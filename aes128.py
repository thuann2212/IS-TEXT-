# -*- coding: utf-8 -*-
"""
Đồ án An toàn thông tin (Information Security)
Chủ đề: Cài đặt thuật toán Mật mã khóa đối xứng AES-128 từ nguyên lý gốc (From First Principles)
Sinh viên thực hiện: Trần Gia Thuận
Chữ số cuối SID: 3
Kết nối trực tiếp với mô-đun sha256.py để trích xuất khóa 128-bit từ SHA-256("Trần Gia Thuận").
"""

import time
from sha256 import bam_sha256_bytes

# Đa thức tối giản (Irreducible Polynomial) của AES trên trường GF(2^8):
# m(x) = x^8 + x^4 + x^3 + x + 1 -> Biểu diễn nhị phân: 0b100011011 = 0x11B
DA_THUC_TOI_GIAN = 0x11B


# ==============================================================================
# 1. SỐ HỌC TRÊN TRƯỜNG HỮU HẠN GF(2^8) VÀ SINH BẢNG S-BOX TỪ NGUYÊN LÝ GỐC
# ==============================================================================

def xtime(a: int) -> int:
    """
    Nhân một phần tử a trong GF(2^8) với đa thức x (tức nhân với {02}):
    - Dịch trái 1 bit (a << 1).
    - Nếu bit cao nhất (bit thứ 7 của a trước khi dịch, tức bit 8 sau khi dịch) bằng 1,
      thực hiện phép cộng (XOR) với byte thấp của đa thức tối giản 0x1B (00011011_2).
    """
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def nhan_gf256(a: int, b: int) -> int:
    """
    Nhân hai phần tử a và b trên trường hữu hạn GF(2^8) theo đa thức tối giản
    m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B) bằng thuật toán nhân nông dân Nga (Peasant's Algorithm).
    """
    ket_qua = 0
    a &= 0xFF
    b &= 0xFF
    for _ in range(8):
        if b & 1:
            ket_qua ^= a
        a = xtime(a)
        b >>= 1
    return ket_qua & 0xFF


def nghich_dao_gf256(a: int) -> int:
    """
    Tìm phần tử nghịch đảo nhân a^(-1) trong GF(2^8) sao cho a * a^(-1) = 1 (mod m(x)).
    Theo định lý Fermat nhỏ trên trường hữu hạn GF(2^8): a^(255) = 1 => a^(-1) = a^(254).
    Quy ước của AES: phần tử 0x00 được ánh xạ nghịch đảo về chính 0x00.
    """
    if a == 0:
        return 0
    # Tính a^254 trong GF(2^8) bằng bình phương và nhân liên tiếp
    ket_qua = 1
    co_so = a & 0xFF
    so_mu = 254
    while so_mu > 0:
        if so_mu & 1:
            ket_qua = nhan_gf256(ket_qua, co_so)
        co_so = nhan_gf256(co_so, co_so)
        so_mu >>= 1
    return ket_qua


def bien_doi_affine_sbox(b: int) -> int:
    """
    Phép biến đổi Affine trên GF(2)^8 để tạo S-Box theo chuẩn FIPS 197:
    b'_i = b_i XOR b_{(i+4) mod 8} XOR b_{(i+5) mod 8} XOR b_{(i+6) mod 8} XOR b_{(i+7) mod 8} XOR c_i
    với hằng số c = 0x63 (01100011_2).
    """
    c = 0x63
    ket_qua = 0
    for i in range(8):
        bit_i = (
            ((b >> i) & 1)
            ^ ((b >> ((i + 4) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 6) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1)
            ^ ((c >> i) & 1)
        )
        ket_qua |= (bit_i << i)
    return ket_qua


# Bảng S-Box 256 phần tử chuẩn FIPS 197 (khai báo tường minh để tra cứu nhanh O(1)
# và được kiểm chứng tự động bằng hàm nghich_dao_gf256 + bien_doi_affine_sbox)
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Bảng Inv S-Box 256 phần tử chuẩn FIPS 197 dùng cho quá trình giải mã
INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# Hằng số vòng Rcon[1..10] trong GF(2^8): Rcon[i] = x^(i-1) mod (x^8 + x^4 + x^3 + x + 1)
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def kiem_chung_sbox_tu_nguyen_ly_goc() -> bool:
    """
    Kiểm chứng toàn bộ 256 phần tử của S_BOX và INV_S_BOX khớp 100% với công thức
    nghịch đảo nhân trên GF(2^8) + biến đổi Affine.
    """
    for x in range(256):
        s_x = bien_doi_affine_sbox(nghich_dao_gf256(x))
        if s_x != S_BOX[x] or INV_S_BOX[s_x] != x:
            return False
    return True


# ==============================================================================
# 2. BIỂU DIỄN MA TRẬN TRẠNG THÁI (STATE MATRIX 4x4 THEO CỘT - COLUMN-MAJOR)
# ==============================================================================
# Theo chuẩn FIPS 197, một khối 16 byte b_0, b_1, ..., b_15 được xếp vào ma trận
# trạng thái S kích thước 4 dòng x 4 cột theo thứ tự từng cột (column-major):
#   S[r][c] = byte_input[r + 4 * c]   với r in {0..3} (dòng), c in {0..3} (cột)


def bytes_sang_state(khoi_16_byte: bytes) -> list:
    """Chuyển chuỗi 16 byte thành ma trận trạng thái 4x4 (S[dòng][cột]) theo chuẩn cột."""
    return [[khoi_16_byte[r + 4 * c] for c in range(4)] for r in range(4)]


def state_sang_bytes(state: list) -> bytes:
    """Chuyển ma trận trạng thái 4x4 (S[dòng][cột]) ngược lại thành chuỗi 16 byte."""
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ==============================================================================
# 3. BỐN PHÉP BIẾN ĐỔI VÒNG CỦA AES (VÀ CÁC PHÉP BIẾN ĐỔI NGƯỢC)
# ==============================================================================

def sub_bytes(state: list) -> list:
    """
    1. Phép thế byte phi tuyến (SubBytes):
    Thay thế độc lập từng byte trong ma trận trạng thái S bằng giá trị tra bảng S-Box:
    S'[r][c] = S_BOX[S[r][c]]
    """
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state: list) -> list:
    """Phép thế byte ngược (InvSubBytes) dùng trong giải mã: S'[r][c] = INV_S_BOX[S[r][c]]."""
    return [[INV_S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: list) -> list:
    """
    2. Phép dịch dòng tuần hoàn sang trái (ShiftRows):
    - Dòng 0: giữ nguyên (dịch 0 vị trí)
    - Dòng 1: dịch vòng trái 1 byte
    - Dòng 2: dịch vòng trái 2 byte
    - Dòng 3: dịch vòng trái 3 byte
    Công thức: S'[r][c] = S[r][(c + r) mod 4]
    """
    return [[state[r][(c + r) % 4] for c in range(4)] for r in range(4)]


def inv_shift_rows(state: list) -> list:
    """
    Phép dịch dòng ngược sang phải (InvShiftRows) dùng trong giải mã:
    - Dòng r được dịch vòng sang phải r vị trí: S'[r][c] = S[r][(c - r) mod 4]
    """
    return [[state[r][(c - r) % 4] for c in range(4)] for r in range(4)]


def mix_columns(state: list) -> list:
    """
    3. Phép trộn cột tuyến tính trên GF(2^8) (MixColumns):
    Mỗi cột c (gồm 4 byte s0, s1, s2, s3) được nhân với ma trận MDS cố định trong GF(2^8):
    [s'0]   [02 03 01 01] [s0]
    [s'1] = [01 02 03 01] [s1]
    [s'2]   [01 01 02 03] [s2]
    [s'3]   [03 01 01 02] [s3]
    """
    ket_qua = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        ket_qua[0][c] = nhan_gf256(0x02, s0) ^ nhan_gf256(0x03, s1) ^ s2 ^ s3
        ket_qua[1][c] = s0 ^ nhan_gf256(0x02, s1) ^ nhan_gf256(0x03, s2) ^ s3
        ket_qua[2][c] = s0 ^ s1 ^ nhan_gf256(0x02, s2) ^ nhan_gf256(0x03, s3)
        ket_qua[3][c] = nhan_gf256(0x03, s0) ^ s1 ^ s2 ^ nhan_gf256(0x02, s3)
    return ket_qua


def inv_mix_columns(state: list) -> list:
    """
    Phép trộn cột ngược (InvMixColumns) dùng trong giải mã:
    Nhân mỗi cột với ma trận nghịch đảo trên GF(2^8):
    [s'0]   [0e 0b 0d 09] [s0]
    [s'1] = [09 0e 0b 0d] [s1]
    [s'2]   [0d 09 0e 0b] [s2]
    [s'3]   [0b 0d 09 0e] [s3]
    """
    ket_qua = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        ket_qua[0][c] = (
            nhan_gf256(0x0E, s0)
            ^ nhan_gf256(0x0B, s1)
            ^ nhan_gf256(0x0D, s2)
            ^ nhan_gf256(0x09, s3)
        )
        ket_qua[1][c] = (
            nhan_gf256(0x09, s0)
            ^ nhan_gf256(0x0E, s1)
            ^ nhan_gf256(0x0B, s2)
            ^ nhan_gf256(0x0D, s3)
        )
        ket_qua[2][c] = (
            nhan_gf256(0x0D, s0)
            ^ nhan_gf256(0x09, s1)
            ^ nhan_gf256(0x0E, s2)
            ^ nhan_gf256(0x0B, s3)
        )
        ket_qua[3][c] = (
            nhan_gf256(0x0B, s0)
            ^ nhan_gf256(0x0D, s1)
            ^ nhan_gf256(0x09, s2)
            ^ nhan_gf256(0x0E, s3)
        )
    return ket_qua


def add_round_key(state: list, khoa_vong_state: list) -> list:
    """
    4. Phép cộng khóa vòng (AddRoundKey):
    Kết hợp từng byte của ma trận trạng thái với ma trận khóa vòng 4x4 bằng phép XOR:
    S'[r][c] = S[r][c] XOR RoundKey[r][c]
    (Phép biến đổi ngược của AddRoundKey là chính nó vì A XOR B XOR B = A).
    """
    return [[state[r][c] ^ khoa_vong_state[r][c] for c in range(4)] for r in range(4)]


# ==============================================================================
# 4. QUY TRÌNH MỞ RỘNG KHÓA (KEY EXPANSION) CHO AES-128 (10 VÒNG -> 44 TỪ 32-BIT)
# ==============================================================================

def rot_word(word_4_byte: list) -> list:
    """Dịch vòng trái 1 byte trên từ 4 byte: [a0, a1, a2, a3] -> [a1, a2, a3, a0]."""
    return word_4_byte[1:] + word_4_byte[:1]


def sub_word(word_4_byte: list) -> list:
    """Áp dụng S-Box lên từng byte của từ 4 byte."""
    return [S_BOX[b] for b in word_4_byte]


def mo_rong_khoa_aes128(khoa_16_byte: bytes) -> list:
    """
    Mở rộng khóa gốc 128-bit (16 byte) thành 11 khóa vòng (Round Keys 0..10),
    tổng cộng 44 từ 32-bit (W[0..43]), mỗi từ là danh sách 4 byte.
    Trả về danh sách 11 ma trận khóa vòng 4x4 (theo thứ tự cột chuẩn của AES).
    """
    if len(khoa_16_byte) != 16:
        raise ValueError("Khóa AES-128 bắt buộc phải có độ dài đúng 16 byte (128 bit).")

    # Bước 1: 4 từ đầu tiên W[0..3] được tách trực tiếp từ khóa gốc 16 byte
    w = [list(khoa_16_byte[4 * i : 4 * (i + 1)]) for i in range(4)]

    # Bước 2: Sinh các từ W[4..43]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            # Nếu chỉ số từ là bội của 4: temp = SubWord(RotWord(temp)) XOR [Rcon[i/4], 0, 0, 0]
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]
        # W[i] = W[i - 4] XOR temp
        w_i = [w[i - 4][j] ^ temp[j] for j in range(4)]
        w.append(w_i)

    # Bước 3: Gom mỗi 4 từ liên tiếp (W[4*vong .. 4*vong+3]) thành ma trận khóa vòng 4x4
    ds_khoa_vong = []
    for vong in range(11):
        bon_tu = w[4 * vong : 4 * (vong + 1)]
        # Cột c của ma trận khóa vòng chính là từ thứ c (W[4*vong + c])
        ma_tran_khoa = [[bon_tu[c][r] for c in range(4)] for r in range(4)]
        ds_khoa_vong.append(ma_tran_khoa)

    return ds_khoa_vong


# ==============================================================================
# 5. MÃ HÓA VÀ GIẢI MÃ MỘT KHỐI ĐƠN 128-BIT (16 BYTE)
# ==============================================================================

def ma_hoa_khoi_16byte(khoi_ro_16_byte: bytes, ds_khoa_vong: list) -> bytes:
    """
    Mã hóa một khối 16 byte theo chuẩn AES-128 (10 vòng):
    - Vòng 0 (Khởi tạo): AddRoundKey(State, RoundKey[0])
    - Vòng 1 đến 9: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey(RoundKey[r])
    - Vòng 10 (Cuối): SubBytes -> ShiftRows -> AddRoundKey(RoundKey[10]) (Không có MixColumns)
    """
    state = bytes_sang_state(khoi_ro_16_byte)

    # Vòng 0: AddRoundKey ban đầu
    state = add_round_key(state, ds_khoa_vong[0])

    # Vòng 1 đến Vòng 9: Đầy đủ 4 phép biến đổi
    for vong in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, ds_khoa_vong[vong])

    # Vòng 10: Bỏ qua MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, ds_khoa_vong[10])

    return state_sang_bytes(state)


def giai_ma_khoi_16byte(khoi_ma_16_byte: bytes, ds_khoa_vong: list) -> bytes:
    """
    Giải mã một khối 16 byte theo quy trình nghịch đảo chuẩn AES-128:
    - Khởi tạo: AddRoundKey(State, RoundKey[10])
    - Vòng 9 xuống 1: InvShiftRows -> InvSubBytes -> AddRoundKey(RoundKey[r]) -> InvMixColumns
    - Vòng 0 (Cuối): InvShiftRows -> InvSubBytes -> AddRoundKey(RoundKey[0])
    """
    state = bytes_sang_state(khoi_ma_16_byte)

    # Bước đảo vòng 10
    state = add_round_key(state, ds_khoa_vong[10])

    # Vòng 9 ngược về Vòng 1
    for vong in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, ds_khoa_vong[vong])
        state = inv_mix_columns(state)

    # Bước đảo vòng 0 cuối cùng
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, ds_khoa_vong[0])

    return state_sang_bytes(state)


# ==============================================================================
# 6. ĐỆM DỮ LIỆU PKCS#7 VÀ CÁC CHẾ ĐỘ VẬN HÀNH KHỐI (CBC & ECB)
# ==============================================================================

def dem_pkcs7(du_lieu: bytes, kich_thuoc_khoi: int = 16) -> bytes:
    """
    Đệm dữ liệu theo chuẩn PKCS#7 (RFC 5652):
    - Tính số byte cần đệm: pad_len = 16 - (len(du_lieu) % 16).
    - Nếu độ dài dữ liệu đã chia hết cho 16, vẫn đệm thêm nguyên 1 khối 16 byte có giá trị 0x10.
    - Mỗi byte đệm đều mang giá trị bằng chính pad_len (1 <= pad_len <= 16).
    """
    so_byte_dem = kich_thuoc_khoi - (len(du_lieu) % kich_thuoc_khoi)
    return du_lieu + bytes([so_byte_dem] * so_byte_dem)


def bo_dem_pkcs7(du_lieu_da_dem: bytes, kich_thuoc_khoi: int = 16) -> bytes:
    """
    Kiểm tra tính hợp lệ và gỡ bỏ phần đệm PKCS#7 sau khi giải mã.
    """
    if not du_lieu_da_dem or (len(du_lieu_da_dem) % kich_thuoc_khoi != 0):
        raise ValueError("Dữ liệu giải mã có độ dài không hợp lệ (không phải bội của 16 byte).")
    so_byte_dem = du_lieu_da_dem[-1]
    if so_byte_dem < 1 or so_byte_dem > kich_thuoc_khoi:
        raise ValueError(f"Giá trị byte đệm PKCS#7 không hợp lệ: {so_byte_dem}.")
    if du_lieu_da_dem[-so_byte_dem:] != bytes([so_byte_dem] * so_byte_dem):
        raise ValueError("Các byte đệm PKCS#7 bị lỗi hoặc sai khóa giải mã.")
    return du_lieu_da_dem[:-so_byte_dem]


def ma_hoa_aes128_cbc(ban_ro: bytes, khoa_16_byte: bytes, iv_16_byte: bytes) -> bytes:
    """
    Mã hóa dữ liệu độ dài bất kỳ bằng chế độ AES-128-CBC kèm đệm PKCS#7:
    C_i = E_K(P_i XOR C_{i-1}), với C_0 = IV.
    """
    if len(iv_16_byte) != 16:
        raise ValueError("Vector khởi tạo IV phải đúng 16 byte.")
    ds_khoa_vong = mo_rong_khoa_aes128(khoa_16_byte)
    du_lieu_dem = dem_pkcs7(ban_ro, 16)

    ban_ma = bytearray()
    khoi_truoc = iv_16_byte
    for i in range(0, len(du_lieu_dem), 16):
        khoi_hien_tai = du_lieu_dem[i : i + 16]
        khoi_xor = bytes(a ^ b for a, b in zip(khoi_hien_tai, khoi_truoc))
        khoi_ma = ma_hoa_khoi_16byte(khoi_xor, ds_khoa_vong)
        ban_ma.extend(khoi_ma)
        khoi_truoc = khoi_ma

    return bytes(ban_ma)


def giai_ma_aes128_cbc(ban_ma: bytes, khoa_16_byte: bytes, iv_16_byte: bytes) -> bytes:
    """
    Giải mã dữ liệu chế độ AES-128-CBC và gỡ đệm PKCS#7:
    P_i = D_K(C_i) XOR C_{i-1}, với C_0 = IV.
    """
    if len(iv_16_byte) != 16:
        raise ValueError("Vector khởi tạo IV phải đúng 16 byte.")
    if len(ban_ma) == 0 or (len(ban_ma) % 16 != 0):
        raise ValueError("Bản mã CBC phải có độ dài là bội số dương của 16 byte.")
    ds_khoa_vong = mo_rong_khoa_aes128(khoa_16_byte)

    ban_ro_da_dem = bytearray()
    khoi_truoc = iv_16_byte
    for i in range(0, len(ban_ma), 16):
        khoi_ma = ban_ma[i : i + 16]
        khoi_giai_ma = giai_ma_khoi_16byte(khoi_ma, ds_khoa_vong)
        khoi_ro = bytes(a ^ b for a, b in zip(khoi_giai_ma, khoi_truoc))
        ban_ro_da_dem.extend(khoi_ro)
        khoi_truoc = khoi_ma

    return bo_dem_pkcs7(bytes(ban_ro_da_dem), 16)


def ma_hoa_aes128_ecb(ban_ro: bytes, khoa_16_byte: bytes) -> bytes:
    """Mã hóa dữ liệu độ dài bất kỳ bằng chế độ AES-128-ECB kèm đệm PKCS#7."""
    ds_khoa_vong = mo_rong_khoa_aes128(khoa_16_byte)
    du_lieu_dem = dem_pkcs7(ban_ro, 16)
    ban_ma = bytearray()
    for i in range(0, len(du_lieu_dem), 16):
        ban_ma.extend(ma_hoa_khoi_16byte(du_lieu_dem[i : i + 16], ds_khoa_vong))
    return bytes(ban_ma)


def giai_ma_aes128_ecb(ban_ma: bytes, khoa_16_byte: bytes) -> bytes:
    """Giải mã dữ liệu chế độ AES-128-ECB và gỡ đệm PKCS#7."""
    ds_khoa_vong = mo_rong_khoa_aes128(khoa_16_byte)
    ban_ro_da_dem = bytearray()
    for i in range(0, len(ban_ma), 16):
        ban_ro_da_dem.extend(giai_ma_khoi_16byte(ban_ma[i : i + 16], ds_khoa_vong))
    return bo_dem_pkcs7(bytes(ban_ro_da_dem), 16)


# ==============================================================================
# 7. TRÍCH XUẤT KHÓA TỪ SHA-256("Trần Gia Thuận"), TRUY VẾT VÒNG 0-1 & BENCHMARK
# ==============================================================================

def lay_khoa_va_iv_sinh_vien(ho_ten: str = "Trần Gia Thuận") -> tuple:
    """
    Kết nối trực tiếp với hàm bam_sha256_bytes trong sha256.py:
    - Tính SHA-256(UTF-8("Trần Gia Thuận")) -> 32 byte (256 bit).
    - Lấy 16 byte đầu tiên (128 bit đầu) làm khóa bí mật AES-128 theo đúng yêu cầu đề bài.
    - Lấy 16 byte tiếp theo (128 bit sau) làm Vector khởi tạo IV xác định cho chế độ CBC.
    """
    ma_bam_32_byte = bam_sha256_bytes(ho_ten.encode("utf-8"))
    khoa_128_bit = ma_bam_32_byte[:16]
    iv_128_bit = ma_bam_32_byte[16:32]
    return khoa_128_bit, iv_128_bit, ma_bam_32_byte


def in_ma_tran_state_dong(state: list) -> str:
    """Định dạng ma trận 4x4 dưới dạng chuỗi các cột và chuỗi 16 byte hex."""
    chuoi_byte = " ".join(f"{b:02x}" for b in state_sang_bytes(state))
    cac_dong = ["[" + " ".join(f"{state[r][c]:02x}" for c in range(4)) + "]" for r in range(4)]
    return f"{chuoi_byte}  |  Hàng: {' '.join(cac_dong)}"


def minh_hoa_tinh_tay_vong0_vong1(khoi_16_byte: bytes, khoa_16_byte: bytes):
    """
    In chi tiết từng bước của Vòng 0 và Vòng 1 (SubBytes, ShiftRows, MixColumns, AddRoundKey)
    trên khối 16 byte để đối chiếu với Mục 6 của báo cáo.
    """
    ds_khoa_vong = mo_rong_khoa_aes128(khoa_16_byte)
    state = bytes_sang_state(khoi_16_byte)

    print(f" - Khối đầu vào (16B)       : {in_ma_tran_state_dong(state)}")
    print(f" - Khóa vòng 0 (RoundKey 0) : {in_ma_tran_state_dong(ds_khoa_vong[0])}")

    # Vòng 0: AddRoundKey
    state_v0 = add_round_key(state, ds_khoa_vong[0])
    print(f" - Sau Vòng 0 (AddRoundKey) : {in_ma_tran_state_dong(state_v0)}")

    # Vòng 1: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    s_sub = sub_bytes(state_v0)
    print(f" - Vòng 1 - Sau SubBytes    : {in_ma_tran_state_dong(s_sub)}")

    s_shift = shift_rows(s_sub)
    print(f" - Vòng 1 - Sau ShiftRows   : {in_ma_tran_state_dong(s_shift)}")

    s_mix = mix_columns(s_shift)
    print(f" - Vòng 1 - Sau MixColumns  : {in_ma_tran_state_dong(s_mix)}")

    print(f" - Khóa vòng 1 (RoundKey 1) : {in_ma_tran_state_dong(ds_khoa_vong[1])}")
    s_rk1 = add_round_key(s_mix, ds_khoa_vong[1])
    print(f" - Vòng 1 - Sau AddRoundKey : {in_ma_tran_state_dong(s_rk1)}")


def chay_benchmark(khoa_16_byte: bytes, iv_16_byte: bytes) -> list:
    """
    Đo hiệu năng mã hóa và giải mã AES-128-CBC trên các kích thước 100B, 1KB, 10KB.
    """
    kich_thuoc_mau = [
        ("100 Bytes", 100),
        ("1 KB (1024 B)", 1024),
        ("10 KB (10240 B)", 10240),
    ]
    so_lan_lap = 20
    ket_qua = []

    for nhan, so_byte in kich_thuoc_mau:
        mau = (b"TranGiaThuan_SID3_AES128_" * ((so_byte // 25) + 1))[:so_byte]
        so_khoi = len(dem_pkcs7(mau, 16)) // 16

        # Đo thời gian mã hóa
        t0 = time.perf_counter()
        ban_ma = b""
        for _ in range(so_lan_lap):
            ban_ma = ma_hoa_aes128_cbc(mau, khoa_16_byte, iv_16_byte)
        t1 = time.perf_counter()

        # Đo thời gian giải mã
        t2 = time.perf_counter()
        ban_giai_ma = b""
        for _ in range(so_lan_lap):
            ban_giai_ma = giai_ma_aes128_cbc(ban_ma, khoa_16_byte, iv_16_byte)
        t3 = time.perf_counter()

        assert ban_giai_ma == mau, "Lỗi: Bản giải mã không khớp với bản rõ!"
        enc_ms = ((t1 - t0) / so_lan_lap) * 1000.0
        dec_ms = ((t3 - t2) / so_lan_lap) * 1000.0
        tong_ms = enc_ms + dec_ms
        toc_do_enc_kbs = (so_byte / 1024.0) / (enc_ms / 1000.0) if enc_ms > 0 else 0.0
        ket_qua.append((nhan, so_byte, so_khoi, enc_ms, dec_ms, tong_ms, toc_do_enc_kbs))

    return ket_qua


def main():
    print("=" * 84)
    print("ĐỒ ÁN AN TOÀN THÔNG TIN - CÀI ĐẶT MẬT MÃ KHỐI AES-128 TỪ NGUYÊN LÝ GỐC")
    print("Sinh viên: Trần Gia Thuận | Chữ số cuối SID: 3")
    print("=" * 84)

    # 1. Kiểm chứng toán học S-Box trên GF(2^8) và vector chuẩn FIPS 197
    sbox_hop_le = kiem_chung_sbox_tu_nguyen_ly_goc()
    print("\n[1] KIỂM CHỨNG TOÁN HỌC GF(2^8) & VECTOR TIÊU CHUẨN NIST FIPS 197:")
    print(f" - Kiểm chứng 256 phần tử S-Box & InvS-Box từ nghịch đảo GF(2^8): {'ĐẠT (PASS)' if sbox_hop_le else 'LỖI'}")

    # Vector chuẩn FIPS 197 Appendix C.1
    pt_nist = bytes.fromhex("00112233445566778899aabbccddeeff")
    key_nist = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ct_ky_vong = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    rk_nist = mo_rong_khoa_aes128(key_nist)
    ct_thuc_te = ma_hoa_khoi_16byte(pt_nist, rk_nist)
    pt_khoi_phuc = giai_ma_khoi_16byte(ct_thuc_te, rk_nist)
    print(f" - Vector FIPS 197 (Appendix C.1):")
    print(f"   + Bản rõ (Plaintext)  : {pt_nist.hex()}")
    print(f"   + Khóa (Key 128-bit)  : {key_nist.hex()}")
    print(f"   + Bản mã (Ciphertext) : {ct_thuc_te.hex()} (Kỳ vọng: {ct_ky_vong.hex()})")
    print(f"   + Giải mã ngược       : {pt_khoi_phuc.hex()}")
    print(f"   + Đánh giá            : {'ĐẠT (PASS)' if (ct_thuc_te == ct_ky_vong and pt_khoi_phuc == pt_nist) else 'LỖI'}")

    # 2. Kết nối với sha256.py để lấy khóa AES-128 từ họ tên "Trần Gia Thuận"
    ho_ten = "Trần Gia Thuận"
    khoa_sv, iv_sv, bam_day_du = lay_khoa_va_iv_sinh_vien(ho_ten)
    print("\n[2] TRÍCH XUẤT KHÓA BÍ MẬT TỪ FILE sha256.py (HỌ TÊN SINH VIÊN):")
    print(f" - Họ tên sinh viên          : {ho_ten} (Chữ số cuối SID: 3)")
    print(f" - SHA-256 đầy đủ (256-bit)  : {bam_day_du.hex()}")
    print(f" - Khóa AES-128 (16B đầu)    : {khoa_sv.hex()}")
    print(f" - Vector IV CBC (16B sau)   : {iv_sv.hex()}")

    # In lịch trình 11 khóa vòng mở rộng của sinh viên
    ds_rk_sv = mo_rong_khoa_aes128(khoa_sv)
    print("\n[3] LỊCH TRÌNH 11 KHÓA VÒNG (KEY EXPANSION) CỦA SINH VIÊN:")
    for idx, rk in enumerate(ds_rk_sv):
        print(f" - RoundKey[{idx:2d}] : {state_sang_bytes(rk).hex()}")

    # 3. Dữ liệu đối chiếu ví dụ tính tay Vòng 0 và Vòng 1 (Khối 16 byte đầu của thông điệp)
    khoi_mau_16b = b"Tran Gia Thuan 3"  # Đúng 16 byte ASCII (54 72 61 6e 20 47 69 61 20 54 68 75 61 6e 20 33)
    print("\n[4] TRUY VẾT CHI TIẾT VÒNG 0 & VÒNG 1 CHO VÍ DỤ TÍNH TAY (Khối 'Tran Gia Thuan 3'):")
    minh_hoa_tinh_tay_vong0_vong1(khoi_mau_16b, khoa_sv)
    ct_khoi_mau = ma_hoa_khoi_16byte(khoi_mau_16b, ds_rk_sv)
    pt_khoi_mau = giai_ma_khoi_16byte(ct_khoi_mau, ds_rk_sv)
    print(f" - Bản mã sau 10 vòng (Hex)  : {ct_khoi_mau.hex()}")
    print(f" - Giải mã kiểm chứng        : {pt_khoi_mau.decode('utf-8')!r} (Khớp: {pt_khoi_mau == khoi_mau_16b})")

    # 4. Mã hóa và giải mã chuỗi văn bản tiếng Việt dài bất kỳ (Chế độ CBC & ECB + PKCS#7)
    van_ban_tieng_viet = (
        "Đồ án môn An toàn thông tin - Phần Mật mã khóa đối xứng AES-128. "
        "Sinh viên thực hiện: Trần Gia Thuận (Chữ số cuối SID: 3). "
        "Kiểm chứng mã hóa khối chế độ CBC và ECB kết hợp đệm dữ liệu PKCS#7 cho tiếng Việt UTF-8!"
    )
    du_lieu_ro_utf8 = van_ban_tieng_viet.encode("utf-8")
    du_lieu_da_dem = dem_pkcs7(du_lieu_ro_utf8, 16)

    ban_ma_cbc = ma_hoa_aes128_cbc(du_lieu_ro_utf8, khoa_sv, iv_sv)
    ban_ro_cbc = giai_ma_aes128_cbc(ban_ma_cbc, khoa_sv, iv_sv)

    ban_ma_ecb = ma_hoa_aes128_ecb(du_lieu_ro_utf8, khoa_sv)
    ban_ro_ecb = giai_ma_aes128_ecb(ban_ma_ecb, khoa_sv)

    print("\n[5] KIỂM THỬ MÃ HÓA & GIẢI MÃ VĂN BẢN TIẾNG VIỆT DÀI (UTF-8 + PKCS#7):")
    print(f" - Văn bản gốc               : {van_ban_tieng_viet}")
    print(f" - Độ dài UTF-8 gốc          : {len(du_lieu_ro_utf8)} bytes")
    print(f" - Độ dài sau đệm PKCS#7     : {len(du_lieu_da_dem)} bytes ({len(du_lieu_da_dem)//16} khối 16-byte, đệm {du_lieu_da_dem[-1]} byte 0x{du_lieu_da_dem[-1]:02x})")
    print(f" - Bản mã AES-128-CBC (Hex)  : {ban_ma_cbc.hex()[:96]}... (Tổng {len(ban_ma_cbc)} bytes)")
    print(f" - Bản mã AES-128-ECB (Hex)  : {ban_ma_ecb.hex()[:96]}... (Tổng {len(ban_ma_ecb)} bytes)")
    print(f" - Giải mã CBC khôi phục     : {ban_ro_cbc.decode('utf-8')}")
    print(f" - So sánh toàn vẹn (CBC/ECB): CBC={'KHỚP 100%' if ban_ro_cbc == du_lieu_ro_utf8 else 'LỖI'} | ECB={'KHỚP 100%' if ban_ro_ecb == du_lieu_ro_utf8 else 'LỖI'}")

    # 5. Đo thời gian chạy (Benchmark 100B, 1KB, 10KB)
    print("\n[6] KẾT QUẢ ĐO HIỆU NĂNG AES-128-CBC (TRUNG BÌNH 20 LẦN CHẠY):")
    print(f"{'Kích thước':<16} | {'Số byte':>7} | {'Số khối 128b':>12} | {'Mã hóa (ms)':>12} | {'Giải mã (ms)':>12} | {'Thông lượng Mã hóa':>18}")
    print("-" * 88)
    for nhan, so_byte, so_khoi, enc_ms, dec_ms, tong_ms, toc_do in chay_benchmark(khoa_sv, iv_sv):
        print(f"{nhan:<16} | {so_byte:>7} | {so_khoi:>12} | {enc_ms:>12.4f} | {dec_ms:>12.4f} | {toc_do:>13.2f} KB/s")
    print("=" * 84)


if __name__ == "__main__":
    main()
