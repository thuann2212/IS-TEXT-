# -*- coding: utf-8 -*-
"""
Kịch bản kiểm định tự động toàn diện (Automated 4-Algorithm Crypto Auditor) cho Đồ án An toàn thông tin:
1. Hàm băm mật mã SHA-256 (sha256.py & bao_cao_sha256.md)
2. Mật mã khóa đối xứng AES-128 (aes128.py & bao_cao_aes128.md)
3. Mật mã khóa bất đối xứng RSA + CRT (rsa.py & bao_cao_rsa.md) [SID cuối 3: 3 mod 3 = 0]
4. Chữ ký số đường cong Elliptic ECDSA (ecdsa.py & bao_cao_ecdsa.md) [SID cuối 3: 3 mod 4 = 3]
Sinh viên: Trần Gia Thuận | Chữ số cuối SID: 3
"""

import ast
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ALGORITHMS_DIR = os.path.join(PROJECT_ROOT, "algorithms")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
for _path in (ALGORITHMS_DIR, PROJECT_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import sha256
import aes128
import rsa
import ecdsa

# Danh sách các thư viện mật mã có sẵn bị cấm sử dụng
THU_VIEN_CAM = {"hashlib", "Crypto", "cryptography", "hmac", "ssl", "OpenSSL", "pycryptodome"}


def kiem_tra_khong_dung_thu_vien_cam(duong_dan_file: str) -> tuple:
    """Quét cây cú pháp AST để đảm bảo không import bất kỳ thư viện mật mã có sẵn nào."""
    with open(duong_dan_file, "r", encoding="utf-8") as f:
        cay_ast = ast.parse(f.read(), filename=duong_dan_file)

    ds_import = set()
    for nut in ast.walk(cay_ast):
        if isinstance(nut, ast.Import):
            for alias in nut.names:
                ds_import.add(alias.name.split(".")[0])
        elif isinstance(nut, ast.ImportFrom) and nut.module:
            ds_import.add(nut.module.split(".")[0])

    vi_pham = ds_import.intersection(THU_VIEN_CAM)
    return (len(vi_pham) == 0, sorted(ds_import), sorted(vi_pham))


def main():
    print("=" * 90)
    print("HỆ THỐNG KIỂM ĐỊNH TỰ ĐỘNG 4 THUẬT TOÁN MẬT MÃ (SHA-256, AES-128, RSA, ECDSA)")
    print("Sinh viên: Trần Gia Thuận | Chữ số cuối SID: 3 (3 mod 3 = 0 -> RSA | 3 mod 4 = 3 -> ECDSA)")
    print("=" * 90)

    tong_so_test = 0
    so_test_dat = 0

    def ghi_nhan(ten_hang_muc: str, dieu_kien: bool, chi_tiet: str = ""):
        nonlocal tong_so_test, so_test_dat
        tong_so_test += 1
        if dieu_kien:
            so_test_dat += 1
            trang_thai = "[PASS]"
        else:
            trang_thai = "[FAIL]"
        print(f" {trang_thai} {ten_hang_muc}")
        if chi_tiet:
            print(f"        -> {chi_tiet}")

    # ==========================================================================
    # 1. KIỂM TRA AST CẢ 4 FILE CODE (KHÔNG DÙNG THƯ VIỆN MẬT MÃ CÓ SẴN)
    # ==========================================================================
    print("\n[1] KIỂM TRA QUY ĐỊNH KHÔNG DÙNG THƯ VIỆN MẬT MÃ CÓ SẴN TRÊN CẢ 4 FILE (AST SCAN):")
    for ten_file in ["sha256.py", "aes128.py", "rsa.py", "ecdsa.py"]:
        hop_le, ds_imp, vi_pham = kiem_tra_khong_dung_thu_vien_cam(os.path.join(ALGORITHMS_DIR, ten_file))
        ghi_nhan(
            f"Quét AST import trong algorithms/{ten_file}",
            hop_le,
            f"Module sử dụng: {ds_imp} (Vi phạm: {vi_pham if vi_pham else '0 - Hợp lệ 100%'})",
        )

    # ==========================================================================
    # 2. KIỂM ĐỊNH THUẬT TOÁN 1: SHA-256 (sha256.py & bao_cao_sha256.md)
    # ==========================================================================
    print("\n[2] KIỂM ĐỊNH THUẬT TOÁN 1: HÀM BĂM MẬT MÃ SHA-256 (sha256.py):")
    h_empty = sha256.bam_sha256_hex(b"")
    ghi_nhan(
        "Vector chuẩn NIST FIPS 180-4 (chuỗi rỗng '')",
        h_empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        f"Digest = {h_empty}",
    )
    h_abc = sha256.bam_sha256_hex(b"abc")
    ghi_nhan(
        "Vector chuẩn NIST FIPS 180-4 (chuỗi 'abc')",
        h_abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        f"Digest = {h_abc}",
    )
    h_448 = sha256.bam_sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    ghi_nhan(
        "Vector chuẩn NIST FIPS 180-4 đa khối biên 448-bit (56B -> 2 khối)",
        h_448 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        and sha256.rotr(0x1_510E527F, 6) == sha256.rotr(0x510E527F, 6),
        f"Digest = {h_448}",
    )
    bam_ten_sv = sha256.bam_sha256_hex("Trần Gia Thuận".encode("utf-8"))
    ghi_nhan(
        "Băm chuỗi họ tên sinh viên 'Trần Gia Thuận' (18B UTF-8, không kèm SID)",
        bam_ten_sv == "70c31dddb87cf9c3fd103a5669346839aa646cb3240d200a80859c06f07ef0e0",
        f"SHA-256 = {bam_ten_sv}",
    )

    # ==========================================================================
    # 3. KIỂM ĐỊNH THUẬT TOÁN 2: AES-128 (aes128.py & bao_cao_aes128.md)
    # ==========================================================================
    print("\n[3] KIỂM ĐỊNH THUẬT TOÁN 2: MẬT MÃ KHỐI ĐỐI XỨNG AES-128 (aes128.py):")
    khoa_sv, iv_sv, _ = aes128.lay_khoa_va_iv_sinh_vien("Trần Gia Thuận")
    ghi_nhan(
        "Trích xuất khóa AES-128 (16B đầu từ SHA-256('Trần Gia Thuận') trong sha256.py)",
        khoa_sv.hex() == "70c31dddb87cf9c3fd103a5669346839" and len(khoa_sv) == 16,
        f"Khóa 128-bit = {khoa_sv.hex()}",
    )
    ghi_nhan(
        "Kiểm chứng đại số 256 phần tử S-Box & InvS-Box trên GF(2^8) modulo 0x11B",
        aes128.kiem_chung_sbox_tu_nguyen_ly_goc(),
        "Khớp tuyệt đối 256/256 phần tử với nghịch đảo a^254 + biến đổi Affine 0x63",
    )
    pt_b = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    key_b = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ct_b_expect = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    rk_b = aes128.mo_rong_khoa_aes128(key_b)
    ct_b = aes128.ma_hoa_khoi_16byte(pt_b, rk_b)
    ghi_nhan(
        "Vector chuẩn NIST FIPS 197 (Appendix B & C.1)",
        ct_b == ct_b_expect and aes128.giai_ma_khoi_16byte(ct_b, rk_b) == pt_b,
        f"Ciphertext = {ct_b.hex()}",
    )

    # Kiểm tra ví dụ tính tay trên chuỗi tên "Tran Gia Thuan" (14B) đệm PKCS#7 (0x02 0x02)
    ten_14b = b"Tran Gia Thuan"
    khoi_16b_pkcs7 = aes128.dem_pkcs7(ten_14b, 16)
    ds_rk_sv = aes128.mo_rong_khoa_aes128(khoa_sv)
    ct_ten = aes128.ma_hoa_khoi_16byte(khoi_16b_pkcs7, ds_rk_sv)
    pt_ten_khoi_phuc = aes128.bo_dem_pkcs7(aes128.giai_ma_khoi_16byte(ct_ten, ds_rk_sv), 16)
    ghi_nhan(
        "Ví dụ tính tay 'Tran Gia Thuan' (14B) + Đệm PKCS#7 (0x02 0x02) & Gỡ đệm",
        khoi_16b_pkcs7.hex() == "5472616e2047696120546875616e0202"
        and ct_ten.hex() == "485472a086cb866f58d5b8c321a9d5df"
        and pt_ten_khoi_phuc == b"Tran Gia Thuan",
        f"CT = {ct_ten.hex()} -> Giải mã gỡ đệm = {pt_ten_khoi_phuc.decode('utf-8')!r}",
    )

    # Kiểm tra các trường hợp biên CBC & ECB + PKCS#7
    for nhan, du_lieu_goc in [
        ("Tên có dấu 'Trần Gia Thuận' (18B)", "Trần Gia Thuận".encode("utf-8")),
        ("Chuỗi rỗng 0B", b""),
        ("Chuỗi tròn 16B", b"0123456789ABCDEF"),
        ("Văn bản tiếng Việt dài UTF-8", "Đồ án An toàn thông tin - Trần Gia Thuận".encode("utf-8") * 3),
    ]:
        c_cbc = aes128.ma_hoa_aes128_cbc(du_lieu_goc, khoa_sv, iv_sv)
        p_cbc = aes128.giai_ma_aes128_cbc(c_cbc, khoa_sv, iv_sv)
        c_ecb = aes128.ma_hoa_aes128_ecb(du_lieu_goc, khoa_sv)
        p_ecb = aes128.giai_ma_aes128_ecb(c_ecb, khoa_sv)
        ghi_nhan(
            f"AES-128 CBC & ECB + PKCS#7: {nhan}",
            p_cbc == du_lieu_goc and p_ecb == du_lieu_goc,
            f"Gốc {len(du_lieu_goc)}B -> Bản mã {len(c_cbc)}B -> Khôi phục 100%",
        )

    # Kiểm tra phản biện biên AES-128 (chặn khối != 16B và đệm PKCS#7 giả mạo)
    aes_edge_ok = True
    try:
        aes128.bytes_sang_state(b"A" * 20)
        aes_edge_ok = False
    except ValueError:
        pass
    try:
        aes128.bo_dem_pkcs7(b"0123456789ABCDE\x02", 16)
        aes_edge_ok = False
    except ValueError:
        pass
    ghi_nhan(
        "Kiểm thử biên bảo mật AES-128 (chặn khối >16B cắt ngầm & phát hiện đệm PKCS#7 sai)",
        aes_edge_ok,
        "Từ chối chính xác khối sai kích thước và đệm giả mạo",
    )

    # ==========================================================================
    # 4. KIỂM ĐỊNH THUẬT TOÁN 3: RSA + GARNER CRT (rsa.py & bao_cao_rsa.md)
    # ==========================================================================
    print("\n[4] KIỂM ĐỊNH THUẬT TOÁN 3: MẬT MÃ BẤT ĐỐI XỨNG RSA + CRT (rsa.py - 3 mod 3 = 0):")
    p_nho, q_nho, e_nho = 61, 53, 17
    n_nho = p_nho * q_nho
    phi_nho = (p_nho - 1) * (q_nho - 1)
    d_nho = rsa.mod_inverse(e_nho, phi_nho)
    c_nho = rsa.pow_mod(65, e_nho, n_nho)
    m_nho = rsa.pow_mod(c_nho, d_nho, n_nho)
    ghi_nhan(
        "Ví dụ tính tay RSA số nhỏ (p=61, q=53, e=17 -> d=2753, m=65 -> c=2790)",
        n_nho == 3233 and phi_nho == 3120 and d_nho == 2753 and c_nho == 2790 and m_nho == 65,
        f"n={n_nho}, phi={phi_nho}, d={d_nho}, E(65)={c_nho}, D(2790)={m_nho}",
    )

    pub_rsa, priv_rsa = rsa.generate_keypair(key_size=1024, e=65537)
    thong_diep_rsa = "Đồ án An toàn thông tin - Kiểm định RSA-CRT và PKCS#1 v1.5 - Trần Gia Thuận"
    ct_rsa = rsa.encrypt_text(thong_diep_rsa, pub_rsa, use_padding=True)
    pt_rsa_std = rsa.decrypt_text(ct_rsa, priv_rsa, use_padding=True, use_crt=False)
    pt_rsa_crt = rsa.decrypt_text(ct_rsa, priv_rsa, use_padding=True, use_crt=True)
    ghi_nhan(
        "Sinh khóa RSA-1024 (Miller-Rabin 40 vòng), đệm PKCS#1 v1.5 & Giải mã Garner CRT",
        pt_rsa_std == thong_diep_rsa and pt_rsa_crt == thong_diep_rsa,
        f"Số khối bản mã: {len(ct_rsa)} -> Giải mã chuẩn và CRT khớp 100% văn bản tiếng Việt",
    )

    # Kiểm thử biên RSA: chuỗi rỗng "", raw chunking có byte \x00 đầu, và chặn e chẵn
    ct_empty_rsa = rsa.encrypt_text("", pub_rsa, use_padding=True)
    pt_empty_rsa = rsa.decrypt_text(ct_empty_rsa, priv_rsa, use_padding=True, use_crt=True)
    raw_msg_rsa = "\x00\x00Tiếng Việt Raw Chunking\x00"
    ct_raw_rsa = rsa.encrypt_text(raw_msg_rsa, pub_rsa, use_padding=False)
    pt_raw_rsa = rsa.decrypt_text(ct_raw_rsa, priv_rsa, use_padding=False, use_crt=True)
    rsa_even_e_blocked = False
    try:
        rsa.generate_keypair(key_size=512, e=2)
    except ValueError:
        rsa_even_e_blocked = True
    ghi_nhan(
        "Kiểm thử biên & an toàn RSA (chuỗi rỗng '', raw chunking chứa \\x00, chặn e chẵn)",
        len(ct_empty_rsa) == 1 and pt_empty_rsa == "" and pt_raw_rsa == raw_msg_rsa and rsa_even_e_blocked,
        "Mã hóa chuỗi rỗng thành 1 khối hợp lệ, bảo toàn byte 0x00 đầu và chặn vòng lặp vô tận e chẵn",
    )

    # ==========================================================================
    # 5. KIỂM ĐỊNH THUẬT TOÁN 4: ECDSA (ecdsa.py & bao_cao_ecdsa.md)
    # ==========================================================================
    print("\n[5] KIỂM ĐỊNH THUẬT TOÁN 4: CHỮ KÝ SỐ ĐƯỜNG CONG ELLIPTIC ECDSA (ecdsa.py - 3 mod 4 = 3):")
    curve_f17 = ecdsa.TOY_CURVE_F17
    Q_f17 = curve_f17.scalar_mult(7, curve_f17.G)
    R_f17 = curve_f17.scalar_mult(13, curve_f17.G)
    r_f17 = R_f17.x % curve_f17.n
    s_f17 = (ecdsa.mod_inverse(13, curve_f17.n) * (10 + r_f17 * 7)) % curve_f17.n
    w_f17 = ecdsa.mod_inverse(s_f17, curve_f17.n)
    u1_f17, u2_f17 = (10 * w_f17) % curve_f17.n, (r_f17 * w_f17) % curve_f17.n
    P_f17 = curve_f17.point_add(curve_f17.scalar_mult(u1_f17, curve_f17.G), curve_f17.scalar_mult(u2_f17, Q_f17))
    ghi_nhan(
        "Ví dụ tính tay ECDSA trên Toy Curve F_17 (G=(5,1), n=19, d=7, z=10, k=13)",
        Q_f17 == ecdsa.Point(0, 6) and (r_f17, s_f17) == (16, 5) and P_f17 == ecdsa.Point(16, 4),
        f"Q={Q_f17}, (r,s)=({r_f17},{s_f17}), P={P_f17} -> x_P mod 19 == r == 16",
    )

    d_ec, Q_ec = ecdsa.generate_keypair(ecdsa.SECP256K1)
    msg_ec = "Kiểm định chữ ký số ECDSA secp256k1 kết nối sha256.py - Trần Gia Thuận"
    sig_ec = ecdsa.sign_message(msg_ec, d_ec, ecdsa.SECP256K1)
    hop_le_ec = ecdsa.verify_signature(msg_ec, sig_ec, Q_ec, ecdsa.SECP256K1)
    gia_mao_ec = ecdsa.verify_signature(msg_ec + "!", sig_ec, Q_ec, ecdsa.SECP256K1)
    ghi_nhan(
        "Ký số & Xác minh ECDSA secp256k1 (tích hợp sha256.py) + Chống giả mạo thông điệp",
        hop_le_ec is True and gia_mao_ec is False,
        "Chữ ký gốc: VALID (True) | Thông điệp bị sửa 1 ký tự: REJECTED (False)",
    )

    k_lap = 123456789012345678901234567890
    sig_lap1 = ecdsa.sign_message("Giao dịch 1", d_ec, ecdsa.SECP256K1, k_custom=k_lap)
    sig_lap2 = ecdsa.sign_message("Giao dịch 2", d_ec, ecdsa.SECP256K1, k_custom=k_lap)
    d_thu_hoi = ecdsa.attack_nonce_reuse("Giao dịch 1", sig_lap1, "Giao dịch 2", sig_lap2, ecdsa.SECP256K1)
    ghi_nhan(
        "Mô phỏng tấn công thu hồi khóa riêng khi tái sử dụng Nonce k (Nonce Reuse Attack)",
        d_thu_hoi == d_ec,
        "Khôi phục chính xác 100% khóa riêng 256-bit d chỉ từ 2 chữ ký trùng nonce k",
    )

    # Kiểm thử phản biện bảo mật ECDSA: kiểm tra nhóm con cofactor h > 1, tọa độ ngoài trường [0, p-1], Low-S BIP-62
    curve_h8 = ecdsa.EllipticCurve("CofactorCurve_F17", p=17, a=1, b=0, G_x=0, G_y=0, n=2, h=8)
    bad_sub_pt = ecdsa.Point(1, 6)  # Điểm thuộc E(F_17) nhưng có bậc > 2 (2 * (1,6) = (0,0) != Infinity)
    subgroup_check_ok = (
        curve_h8.is_on_curve(bad_sub_pt)
        and not curve_h8.scalar_mult(2, bad_sub_pt).is_infinity
        and not ecdsa.verify_signature("test", (1, 1), bad_sub_pt, curve_h8)
    )
    non_canonical_q = ecdsa.Point(Q_ec.x + ecdsa.SECP256K1.p, Q_ec.y)
    sig_low_s = ecdsa.sign_message(msg_ec, d_ec, ecdsa.SECP256K1, low_s=True)
    ghi_nhan(
        "Kiểm thử bảo mật nâng cao ECDSA (nhóm con h > 1, tọa độ chuẩn tắc [0,p-1], BIP-62 Low-S)",
        subgroup_check_ok
        and not ecdsa.verify_signature(msg_ec, sig_ec, non_canonical_q, ecdsa.SECP256K1)
        and sig_low_s[1] <= (ecdsa.SECP256K1.n - 1) // 2
        and ecdsa.verify_signature(msg_ec, sig_low_s, Q_ec, ecdsa.SECP256K1),
        "Chặn thành công tấn công nhóm con nhỏ, khóa Q ngoài trường F_p và chuẩn hóa Low-S",
    )

    # ==========================================================================
    # 6. KIỂM TRA CHÉO 4 BÁO CÁO & ĐẢM BẢO KHÔNG CÒN CHUỖI SAI 'Tran Gia Thuan 3'
    # ==========================================================================
    print("\n[6] ĐỐI CHIẾU CHÉO 4 FILE BÁO CÁO (.md) VÀ KIỂM TRA LOẠI BỎ CHUỖI SAI 'Tran Gia Thuan 3':")
    with open(os.path.join(ALGORITHMS_DIR, "aes128.py"), "r", encoding="utf-8") as f:
        code_aes_str = f.read()
    with open(os.path.join(DOCS_DIR, "bao_cao_aes128.md"), "r", encoding="utf-8") as f:
        bc_aes_str = f.read()

    ghi_nhan(
        "Loại bỏ hoàn toàn chuỗi sai 'Tran Gia Thuan 3' khỏi algorithms/aes128.py và docs/bao_cao_aes128.md",
        ("Tran Gia Thuan 3" not in code_aes_str) and ("Tran Gia Thuan 3" not in bc_aes_str),
        "Không còn bất kỳ chuỗi 'Tran Gia Thuan 3' nào trong code và báo cáo",
    )

    s0 = aes128.add_round_key(aes128.bytes_sang_state(khoi_16b_pkcs7), ds_rk_sv[0])
    s1_out = aes128.add_round_key(
        aes128.mix_columns(aes128.shift_rows(aes128.sub_bytes(s0))), ds_rk_sv[1]
    )
    s0_hex = " ".join(f"{b:02x}" for b in aes128.state_sang_bytes(s0))
    s1_hex = " ".join(f"{b:02x}" for b in aes128.state_sang_bytes(s1_out))
    ghi_nhan(
        "Khớp ma trận Vòng 0, Vòng 1 và Bản mã của 'Tran Gia Thuan' (PKCS#7) trong docs/bao_cao_aes128.md",
        (s0_hex in bc_aes_str) and (s1_hex in bc_aes_str) and (ct_ten.hex() in bc_aes_str),
        f"Vòng 0: {s0_hex} | Vòng 1: {s1_hex} | CT: {ct_ten.hex()}",
    )

    for ten_bc in ["bao_cao_sha256.md", "bao_cao_aes128.md", "bao_cao_rsa.md", "bao_cao_ecdsa.md"]:
        with open(os.path.join(DOCS_DIR, ten_bc), "r", encoding="utf-8") as f:
            nd = f.read()
        du_8_muc = all(f"## Mục {i}." in nd for i in range(1, 9))
        ghi_nhan(
            f"Kiểm tra cấu trúc đủ 8 mục trong docs/{ten_bc}",
            du_8_muc,
            "Đầy đủ từ Mục 1 đến Mục 8",
        )

    print("\n" + "=" * 90)
    print(f"TỔNG KẾT KIỂM ĐỊNH 4 THUẬT TOÁN: ĐẠT {so_test_dat}/{tong_so_test} HẠNG MỤC ({so_test_dat * 100 // tong_so_test}%)")
    print("=" * 90)


if __name__ == "__main__":
    main()
