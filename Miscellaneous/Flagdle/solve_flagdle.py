#!/usr/bin/env python3
import requests
import json
import time

URL = "http://challenge.nahamcon.com:31162/guess"

HEX_CHARS = "0123456789abcdef"
PLACEHOLDER = "z"   # ký tự không nằm trong set flag

def get_feedback(guess: str) -> str:
    """
    Gửi guess, nhận về chuỗi emoji trong JSON["result"].
    """
    headers = {"Content-Type": "application/json"}
    data = {"guess": guess}
    r = requests.post(URL, headers=headers, json=data)
    r.raise_for_status()
    return r.json()["result"]

def solve():
    # khởi tạo chuỗi flag body 32 ký tự (placeholder)
    body = [PLACEHOLDER] * 32

    for i in range(32):
        for c in HEX_CHARS:
            body[i] = c
            guess = "flag{" + "".join(body) + "}"
            fb = get_feedback(guess)

            # fb là một chuỗi unicode, mỗi ký tự 1 ô:
            # 🟩 = correct pos, 🟨 = right char wrong pos, ⬛ = wrong char
            if fb[i] == "🟩":
                print(f"Position {i}: found '{c}'")
                break
        else:
            raise RuntimeError(f"No hex char worked at pos {i}")
        # optional: sleep để tránh rate-limit
        time.sleep(0.1)

    flag = "flag{" + "".join(body) + "}"
    print("\n🎉 Recovered flag:", flag)

if __name__ == "__main__":
    solve()
