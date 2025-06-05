import ctypes
from ctypes import wintypes
import sys
import re
from Crypto.Cipher import AES

# 파일에서 바이트 범위만큼 읽어서 다른 파일로 쓰는 함수
def extract_bytes(input_file, output_file, skip, count=None):
    with open(input_file, 'rb') as f:
        f.seek(skip)
        data = f.read(count if count else -1)
    with open(output_file, 'wb') as out:
        out.write(data)

# t.wnry에서 필요한 바이트를 각각 추출
#  - offset 12에서 256바이트 읽어와서 "encrypted_aes_key"로 저장
#  - offset 280부터 끝까지 읽어와서 "t_file_data.bin"으로 저장
extract_bytes("t.wnry", "encrypted_aes_key", skip=12, count=256)
extract_bytes("t.wnry", "t_file_data.bin", skip=280)

# Win32 CryptoAPI 함수 불러오기
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# 자료형·상수 정의
PROV_RSA_AES           = 24
MS_ENH_RSA_AES_PROV    = "Microsoft Enhanced RSA and AES Cryptographic Provider"
CRYPT_VERIFYCONTEXT    = 0xF0000000

HCRYPTPROV = wintypes.HANDLE
HCRYPTKEY  = wintypes.HANDLE

# CryptAcquireContextW 프로토타입 설정
CryptAcquireContextW = advapi32.CryptAcquireContextW
CryptAcquireContextW.argtypes = [
    ctypes.POINTER(HCRYPTPROV),  # phProv
    wintypes.LPCWSTR,            # pszContainer
    wintypes.LPCWSTR,            # pszProvider
    wintypes.DWORD,              # dwProvType
    wintypes.DWORD               # dwFlags
]
CryptAcquireContextW.restype = wintypes.BOOL

# CryptImportKey 프로토타입 설정
CryptImportKey = advapi32.CryptImportKey
CryptImportKey.argtypes = [
    HCRYPTPROV,
    ctypes.POINTER(ctypes.c_ubyte),
    wintypes.DWORD,
    HCRYPTKEY,
    wintypes.DWORD,
    ctypes.POINTER(HCRYPTKEY)
]
CryptImportKey.restype = wintypes.BOOL

# CryptDecrypt 프로토타입 설정
CryptDecrypt = advapi32.CryptDecrypt
CryptDecrypt.argtypes = [
    HCRYPTKEY,
    HCRYPTKEY,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(wintypes.DWORD)
]
CryptDecrypt.restype = wintypes.BOOL

# rsa_key_hex.txt -> 바이너리 BLOB 읽어오기
def load_rsa_blob_from_hexfile(path: str) -> bytes:
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", txt)
    blob = bytes.fromhex(hex_only)
    return blob

try:
    key_blob = load_rsa_blob_from_hexfile("rsa_key_hex.txt")
except FileNotFoundError:
    print("Failed to open rsa_key_hex.txt (16진수 덤프 파일).")
    sys.exit(-1)

if len(key_blob) != 0x494:
    print(f"Invalid key blob length: expected 0x494 (1172), got {len(key_blob)} bytes.")
    sys.exit(-1)

# CryptAcquireContextW -> 컨텍스트 획득
hCryptProv = HCRYPTPROV()
ok = CryptAcquireContextW(
    ctypes.byref(hCryptProv),
    None,                       # 컨테이너 이름
    MS_ENH_RSA_AES_PROV,        # 프로바이더 이름
    PROV_RSA_AES,               # 프로바이더 타입 (24)
    CRYPT_VERIFYCONTEXT         # dwFlags = 0xF0000000
)
if not ok:
    print("CryptAcquireContextW failed. (Error code:", ctypes.get_last_error(), ")")
    sys.exit(-1)

print("Acquired crypto context.")

# CryptImportKey -> RSA PRIVATEKEYBLOB import
blob_buffer = (ctypes.c_ubyte * len(key_blob)).from_buffer_copy(key_blob)
hKey = HCRYPTKEY()

ok = CryptImportKey(
    hCryptProv,
    blob_buffer,
    len(key_blob),
    0,          # hPubKey
    0,          # dwFlags
    ctypes.byref(hKey)
)
if not ok:
    print("CryptImportKey failed. (Error code:", ctypes.get_last_error(), ")")
    sys.exit(-1)

print("Imported RSA key successfully.")

# encrypted_aes_key 파일 읽기 (256바이트)
try:
    with open("encrypted_aes_key", "rb") as f_enc:
        enc_data = f_enc.read()
except FileNotFoundError:
    print("Failed to open encrypted_aes_key.")
    sys.exit(-1)

if len(enc_data) != 256:
    print(f"Encrypted data must be exactly 256 bytes, got {len(enc_data)}.")
    sys.exit(-1)

# 버퍼 할당
buf = (ctypes.c_ubyte * 256).from_buffer_copy(enc_data)
data_len = wintypes.DWORD(len(enc_data))

# CryptDecrypt -> RSA 복호화
ok = CryptDecrypt(
    hKey,
    0,         # hHash
    True,      # Final = 1
    0,         # dwFlags = 0
    buf,
    ctypes.byref(data_len)
)
if not ok:
    print("CryptDecrypt failed. (Error code:", ctypes.get_last_error(), ")")
    sys.exit(-1)

print("Decryption successful.")

# 복호화된 바이트를 16진수로 출력
#    -> AES 키로 사용할 값
decrypted = bytes(buf[: data_len.value])
print("Decrypted AES key (hex):")

# 파일 열기
with open("aes_key_dump.txt", "w") as f:
    for i in range(0, len(decrypted), 16):
        line = decrypted[i : i + 16]
        hex_line = " ".join(f"{b:02x}" for b in line)
        print(hex_line)             # 콘솔 출력
        f.write(hex_line + "\n")    # 파일에 출력


# 암호화된 t_file_data.bin -> AES-CBC 복호화
key = decrypted             # 위에서 얻은 AES 키
iv  = b'\x00' * 16          # 빈(0) IV
cipher = AES.new(key, AES.MODE_CBC, iv=iv)

try:
    with open("t_file_data.bin", "rb") as f_in:
        encrypted_chunk = f_in.read()
except FileNotFoundError:
    print("Failed to open t_file_data.bin.")
    sys.exit(-1)

decrypted_chunk = cipher.decrypt(encrypted_chunk)

with open("t_file_data.dec", "wb") as f_out:
    f_out.write(decrypted_chunk)

print("t_file_data.bin has been decrypted to t_file_data.dec.")
