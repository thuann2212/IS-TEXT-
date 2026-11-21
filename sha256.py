# -*- coding: utf-8 -*-
"""
Đồ án An toàn thông tin (Information Security)
Chủ đề: Cài đặt thuật toán băm mật mã SHA-256 từ nguyên lý gốc (From First Principles)
Sinh viên thực hiện: Trần Gia Thuận
Chữ số cuối SID: 3
"""

import struct
import time

# Mask 32-bit để đảm bảo các phép toán số học trên Python (vốn có độ dài bit tùy ý)
# luôn nằm trong không gian modulo 2^32.
MASK_32 = 0xFFFFFFFF


def lay_n_so_nguyen_to_dau_tien(so_luong: int) -> list:
    """Tìm danh sách n số nguyên tố đầu tiên để sinh hằng số cho SHA-256."""
    ds_nguyen_to = []
    ung_vien = 2
    while len(ds_nguyen_to) < so_luong:
        la_nt = True
        for p in ds_nguyen_to:
            if p * p > ung_vien:
                break
            if ung_vien % p == 0:
                la_nt = False
                break
        if la_nt:
            ds_nguyen_to.append(ung_vien)
        ung_vien += 1
    return ds_nguyen_to


def trich_phan_thap_phan_32bit(so_nguyen_to: int, bac_can: int) -> int:
    """
    Trích 32 bit đầu tiên của phần thập phân của căn bậc `bac_can` (2 hoặc 3)
    của một số nguyên tố theo đặc tả FIPS 180-4:
    Giá trị = floor(frac(p^(1/bac_can)) * 2^32)
    Sử dụng phép tìm kiếm nhị phân số nguyên lớn để tránh sai số dấu phẩy động.
    """
    # Ta cần tìm x = floor(p^(1/bac_can) * 2^32)
    # Tương đương tìm x lớn nhất sao cho x^bac_can <= p * (2^(32 * bac_can))
    muc_tieu = so_nguyen_to << (32 * bac_can)
    thap = 1 << 32
    cao = (so_nguyen_to + 1) << 32
    while thap < cao:
        giua = (thap + cao + 1) // 2
        if (giua ** bac_can) <= muc_tieu:
            thap = giua
        else:
            cao = giua - 1
    return thap & MASK_32


# Sinh 8 giá trị băm khởi tạo H^(0) từ căn bậc hai của 8 số nguyên tố đầu tiên (2..19)
_DS_64_NGUYEN_TO = lay_n_so_nguyen_to_dau_tien(64)
GIA_TRI_KHOI_TAO_H0 = [trich_phan_thap_phan_32bit(p, 2) for p in _DS_64_NGUYEN_TO[:8]]

# Sinh 64 hằng số vòng K_0..K_63 từ căn bậc ba của 64 số nguyên tố đầu tiên (2..311)
HANG_SO_VONG_K = [trich_phan_thap_phan_32bit(p, 3) for p in _DS_64_NGUYEN_TO]


# ==============================================================================
# CÁC PHÉP TOÁN BIT 32-BIT CƠ SỞ (Theo chuẩn FIPS 180-4 Mục 4.1.2)
# ==============================================================================

def rotr(x: int, n: int) -> int:
    """
    Phép xoay phải bit (Rotate Right - ROTR^n(x)) trên từ 32-bit:
    Công thức: ROTR^n(x) = (x >> n) OR (x << (32 - n)) mod 2^32
    """
    return ((x >> n) | (x << (32 - n))) & MASK_32


def shr(x: int, n: int) -> int:
    """
    Phép dịch phải logic (Right Shift - SHR^n(x)) trên từ 32-bit:
    Công thức: SHR^n(x) = x >> n
    """
    return (x & MASK_32) >> n


def ham_ch(x: int, y: int, z: int) -> int:
    """
    Hàm chọn lựa bit (Choose - Ch(x, y, z)):
    Bit của x đóng vai trò bộ chọn: nếu bit của x là 1 thì chọn bit của y,
    ngược lại nếu bit của x là 0 thì chọn bit của z.
    Công thức: Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)
    """
    return ((x & y) ^ ((~x & MASK_32) & z)) & MASK_32


def ham_maj(x: int, y: int, z: int) -> int:
    """
    Hàm đa số theo từng vị trí bit (Majority - Maj(x, y, z)):
    Kết quả tại mỗi vị trí bit bằng 1 nếu có từ 2 biến trở lên mang bit 1.
    Công thức: Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    """
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK_32


def sigma_hoa_0(x: int) -> int:
    r"""
    Hàm khuếch tán Sigma lớn 0 dùng trong vòng lặp nén chính:
    Công thức: \Sigma_0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
    """
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def sigma_hoa_1(x: int) -> int:
    r"""
    Hàm khuếch tán Sigma lớn 1 dùng trong vòng lặp nén chính:
    Công thức: \Sigma_1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    """
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def sigma_thuong_0(x: int) -> int:
    r"""
    Hàm mở rộng lịch trình thông điệp sigma nhỏ 0:
    Công thức: \sigma_0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    """
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def sigma_thuong_1(x: int) -> int:
    r"""
    Hàm mở rộng lịch trình thông điệp sigma nhỏ 1:
    Công thức: \sigma_1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
    """
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


# ==============================================================================
# TIỀN XỬ LÝ: ĐỆM BIT (PADDING) VÀ CHIA KHỐI 512-BIT (64 BYTE)
# ==============================================================================

def dem_thong_diep(du_lieu_bytes: bytes) -> bytes:
    r"""
    Thực hiện đệm bit (Message Padding) theo cấu trúc Merkle-Damgård:
    1. Gắn thêm một bit '1' vào cuối thông điệp (tương ứng byte 0x80).
    2. Gắn thêm k bit '0' sao cho: l + 1 + k \equiv 448 (mod 512),
       hay tính theo byte: (len_bytes + 1 + k_bytes) % 64 == 56.
    3. Gắn độ dài gốc l (tính bằng số bit = len_bytes * 8) dưới dạng
       số nguyên 64-bit không dấu theo thứ tự Big-Endian (>Q).
    """
    do_dai_bit = len(du_lieu_bytes) * 8
    ket_qua = bytearray(du_lieu_bytes)

    # Bước 1: Thêm byte 0x80 (10000000_2)
    ket_qua.append(0x80)

    # Bước 2: Thêm các byte 0x00 cho đến khi độ dài đồng dư 56 mod 64
    while (len(ket_qua) % 64) != 56:
        ket_qua.append(0x00)

    # Bước 3: Đóng gói 64-bit độ dài gốc dạng Big-Endian
    ket_qua.extend(struct.pack(">Q", do_dai_bit))
    return bytes(ket_qua)


def chia_khoi_512bit(du_lieu_da_dem: bytes) -> list:
    """
    Chia thông điệp đã đệm thành danh sách các khối 512-bit (64 byte).
    """
    return [du_lieu_da_dem[i:i + 64] for i in range(0, len(du_lieu_da_dem), 64)]


# ==============================================================================
# HÀM NÉN SHA-256 (64 VÒNG LẶP)
# ==============================================================================

def nen_mot_khoi(khoi_64_byte: bytes, trang_thai_h: list) -> list:
    """
    Thực hiện mở rộng thông điệp thành 64 từ W[0..63] và chạy 64 vòng nén
    trên một khối 512-bit.
    """
    # 1. Tạo lịch trình thông điệp (Message Schedule) W[0..63]
    # 16 từ đầu tiên (W[0..15]) tách trực tiếp từ khối 64 byte theo Big-Endian (>16I)
    w = list(struct.unpack(">16I", khoi_64_byte)) + [0] * 48

    # 48 từ tiếp theo (W[16..63]) tính theo công thức:
    # W_t = (\sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16}) mod 2^32
    for t in range(16, 64):
        w[t] = (
            sigma_thuong_1(w[t - 2])
            + w[t - 7]
            + sigma_thuong_0(w[t - 15])
            + w[t - 16]
        ) & MASK_32

    # 2. Khởi tạo 8 thanh ghi làm việc a, b, c, d, e, f, g, h từ trạng thái băm trước đó
    a, b, c, d, e, f, g, h = trang_thai_h

    # 3. Vòng lặp nén 64 bước (t từ 0 đến 63)
    # T1 = (h + \Sigma_1(e) + Ch(e, f, g) + K_t + W_t) mod 2^32
    # T2 = (\Sigma_0(a) + Maj(a, b, c)) mod 2^32
    # Cập nhật dịch chuyển thanh ghi:
    # h = g; g = f; f = e; e = (d + T1) mod 2^32
    # d = c; c = b; b = a; a = (T1 + T2) mod 2^32
    for t in range(64):
        t1 = (h + sigma_hoa_1(e) + ham_ch(e, f, g) + HANG_SO_VONG_K[t] + w[t]) & MASK_32
        t2 = (sigma_hoa_0(a) + ham_maj(a, b, c)) & MASK_32
        h = g
        g = f
        f = e
        e = (d + t1) & MASK_32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK_32

    # 4. Cộng dồn (Feed-forward) theo cấu trúc Davies-Meyer:
    # H_i^(k) = (H_i^(k-1) + thanh_ghi_i) mod 2^32
    return [
        (trang_thai_h[0] + a) & MASK_32,
        (trang_thai_h[1] + b) & MASK_32,
        (trang_thai_h[2] + c) & MASK_32,
        (trang_thai_h[3] + d) & MASK_32,
        (trang_thai_h[4] + e) & MASK_32,
        (trang_thai_h[5] + f) & MASK_32,
        (trang_thai_h[6] + g) & MASK_32,
        (trang_thai_h[7] + h) & MASK_32,
    ]


def bam_sha256_bytes(du_lieu: bytes) -> bytes:
    """
    Tính giá trị băm SHA-256 trả về kết quả 32 byte (256 bit) thô.
    """
    trang_thai = list(GIA_TRI_KHOI_TAO_H0)
    du_lieu_da_dem = dem_thong_diep(du_lieu)
    cac_khoi = chia_khoi_512bit(du_lieu_da_dem)

    for khoi in cac_khoi:
        trang_thai = nen_mot_khoi(khoi, trang_thai)

    # Ghép 8 từ 32-bit Big-Endian thành chuỗi 32 byte
    return struct.pack(">8I", *trang_thai)


def bam_sha256_hex(du_lieu: bytes) -> str:
    """
    Tính giá trị băm SHA-256 trả về chuỗi Hex 64 ký tự.
    """
    return bam_sha256_bytes(du_lieu).hex()


# ==============================================================================
# ĐO THỜI GIAN CHẠY (BENCHMARK) VÀ KIỂM THỬ THỰC NGHIỆM
# ==============================================================================

def chay_benchmark():
    """
    Đo hiệu năng thuật toán SHA-256 Python thuần trên các kích thước 100B, 1KB, 10KB.
    """
    kich_thuoc_mau = [
        ("100 Bytes", 100),
        ("1 KB (1024 B)", 1024),
        ("10 KB (10240 B)", 10240),
    ]
    so_lan_lap = 50
    ket_qua_do = []

    for nhan, so_byte in kich_thuoc_mau:
        mau_du_lieu = (b"TranGiaThuan_SID3_" * ((so_byte // 18) + 1))[:so_byte]
        so_khoi = len(dem_thong_diep(mau_du_lieu)) // 64

        t_bat_dau = time.perf_counter()
        for _ in range(so_lan_lap):
            _ = bam_sha256_hex(mau_du_lieu)
        t_ket_thuc = time.perf_counter()

        tb_ms = ((t_ket_thuc - t_bat_dau) / so_lan_lap) * 1000.0
        toc_do_kbs = (so_byte / 1024.0) / (tb_ms / 1000.0) if tb_ms > 0 else 0.0
        ket_qua_do.append((nhan, so_byte, so_khoi, tb_ms, toc_do_kbs))

    return ket_qua_do


def main():
    print("=" * 76)
    print("ĐỒ ÁN AN TOÀN THÔNG TIN - CÀI ĐẶT SHA-256 TỪ NGUYÊN LÝ GỐC")
    print("Sinh viên: Trần Gia Thuận | Chữ số cuối SID: 3")
    print("=" * 76)

    # 1. Kiểm thử với vector chuẩn FIPS 180-4
    vector_kiem_thu = [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ]
    print("\n[1] KIỂM CHỨNG VECTOR TIÊU CHUẨN:")
    for dau_vao, ky_vong in vector_kiem_thu:
        thuc_te = bam_sha256_hex(dau_vao)
        trang_thai_kt = "ĐẠT (PASS)" if thuc_te == ky_vong else "LỖI (FAIL)"
        print(f" - Đầu vào : {dau_vao!r}")
        print(f"   Kết quả : {thuc_te}")
        print(f"   Đánh giá: {trang_thai_kt}")

    # 2. Băm chuỗi họ tên sinh viên "Trần Gia Thuận" (UTF-8) và trích khóa AES-128
    ho_ten = "Trần Gia Thuận"
    ho_ten_utf8 = ho_ten.encode("utf-8")
    ma_bam_day_du = bam_sha256_bytes(ho_ten_utf8)
    ma_bam_hex = ma_bam_day_du.hex()

    # Trích 128 bit (16 byte đầu tiên = 32 ký tự Hex đầu tiên) làm khóa cho AES-128
    khoa_aes_128_bytes = ma_bam_day_du[:16]
    khoa_aes_128_hex = khoa_aes_128_bytes.hex()

    print("\n[2] KẾT QUẢ BĂM HỌ TÊN SINH VIÊN & TRÍCH XUẤT KHÓA AES-128:")
    print(f" - Chuỗi họ tên gốc       : {ho_ten}")
    print(f" - Biểu diễn UTF-8 (Hex)  : {ho_ten_utf8.hex()} ({len(ho_ten_utf8)} bytes = {len(ho_ten_utf8)*8} bits)")
    print(f" - SHA-256 đầy đủ (256-bit): {ma_bam_hex}")
    print(f" - Khóa AES-128 (128-bit) : {khoa_aes_128_hex}")
    print(f" - Các byte khóa AES-128  : {' '.join(f'{b:02x}' for b in khoa_aes_128_bytes)}")

    # 3. In chi tiết minh họa cho chuỗi "abc" (đệm bit & 2 vòng nén đầu)
    print("\n[3] DỮ LIỆU ĐỐI CHIẾU VÍ DỤ TÍNH TAY ('abc'):")
    abc_padded = dem_thong_diep(b"abc")
    w_abc = list(struct.unpack(">16I", abc_padded)) + [0] * 48
    for t in range(16, 64):
        w_abc[t] = (
            sigma_thuong_1(w_abc[t - 2])
            + w_abc[t - 7]
            + sigma_thuong_0(w_abc[t - 15])
            + w_abc[t - 16]
        ) & MASK_32
    a, b, c, d, e, f, g, h = GIA_TRI_KHOI_TAO_H0
    print(f" - Khởi tạo H^(0): " + " ".join(f"H{i}={v:08x}" for i, v in enumerate(GIA_TRI_KHOI_TAO_H0)))
    for t in range(2):
        s1 = sigma_hoa_1(e)
        ch_val = ham_ch(e, f, g)
        t1 = (h + s1 + ch_val + HANG_SO_VONG_K[t] + w_abc[t]) & MASK_32
        s0 = sigma_hoa_0(a)
        maj_val = ham_maj(a, b, c)
        t2 = (s0 + maj_val) & MASK_32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK_32, c, b, a, (t1 + t2) & MASK_32
        print(f" - Vòng t={t}: W[{t}]=0x{w_abc[t]:08x}, K[{t}]=0x{HANG_SO_VONG_K[t]:08x}")
        print(f"   Sigma1(e)=0x{s1:08x}, Ch(e,f,g)=0x{ch_val:08x} => T1=0x{t1:08x}")
        print(f"   Sigma0(a)=0x{s0:08x}, Maj(a,b,c)=0x{maj_val:08x} => T2=0x{t2:08x}")
        print(f"   Thanh ghi sau t={t}: a={a:08x} b={b:08x} c={c:08x} d={d:08x} e={e:08x} f={f:08x} g={g:08x} h={h:08x}")

    # 4. Đo thời gian chạy (Benchmark)
    print("\n[4] KẾT QUẢ ĐO HIỆU NĂNG (BENCHMARK TRUNG BÌNH 50 LẦN CHẠY):")
    print(f"{'Kích thước':<18} | {'Số byte':>8} | {'Số khối 512b':>12} | {'Thời gian (ms)':>14} | {'Thông lượng (KB/s)':>18}")
    print("-" * 76)
    for nhan, so_byte, so_khoi, tb_ms, toc_do in chay_benchmark():
        print(f"{nhan:<18} | {so_byte:>8} | {so_khoi:>12} | {tb_ms:>14.4f} | {toc_do:>18.2f}")
    print("=" * 76)


if __name__ == "__main__":
    main()
