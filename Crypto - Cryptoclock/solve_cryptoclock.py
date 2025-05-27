#!/usr/bin/env python3
import socket

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    HOST = "challenge.nahamcon.com"
    PORT = 30675

    # 1) Mở kết nối và bọc thành file‐like để readline() dễ dùng
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb", newline=b"\n")

    # 2) Đọc cho tới khi gặp dòng encrypted flag
    enc_flag = None
    while True:
        line = f.readline().decode(errors="ignore")
        if not line:
            raise RuntimeError("Server closed kết nối trước khi gửi flag.")
        print(line, end="")                # in debug
        if line.startswith("The encrypted flag is:"):
            hexstr = line.split(":",1)[1].strip()
            enc_flag = bytes.fromhex(hexstr)
            break

    L = len(enc_flag)
    print(f"[+] Flag is {L} bytes long")

    # 3) Gửi payload độ dài bằng flag (ví dụ toàn 'A')
    payload = b"A" * L
    f.write(payload + b"\n")
    f.flush()

    # 4) Đọc về ciphertext của payload
    enc_payload = None
    while True:
        line = f.readline().decode(errors="ignore")
        if not line:
            raise RuntimeError("Server closed kết nối sau khi gửi payload.")
        print(line, end="")                # in debug
        if line.startswith("Encrypted:"):
            hexstr = line.split(":",1)[1].strip()
            enc_payload = bytes.fromhex(hexstr)
            break

    # 5) Tính key = enc_payload XOR payload
    key = xor_bytes(enc_payload, payload)

    # 6) Giải flag = enc_flag XOR key
    flag = xor_bytes(enc_flag, key)
    print("\n[+] Recovered flag:", flag.decode())

    # 7) Clean up
    f.write(b"quit\n")
    f.flush()
    s.close()

if __name__ == "__main__":
    main()
