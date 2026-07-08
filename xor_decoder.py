#!/usr/bin/env python3
"""
Hex, XOR & AES Decoder/Encoder - Reverse Engineering Helper

Usage:
  # Hex -> ASCII
  python3 helper.py --hex "48656C6C6F"

  # XOR decode (key is known)
  python3 helper.py "5B 49 5C 50 56 58" 0x1A

  # XOR brute-force (key is unknown)
  python3 helper.py "5B495C505658"

  # AES Encrypt (Encrypts text using AES -> Outputs Hex)
  python3 helper.py --aes-enc "Secret Message" "16ByteKeyHere!!!"

  # AES Decrypt (Decrypts Hex ciphertext -> Outputs plaintext)
  python3 helper.py --aes-dec "CiphertextHex" "16ByteKeyHere!!!"
"""

import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def hex_to_bytes(hex_str):
    """'5B 49 5C' or '5B495C' -> bytes"""
    h = hex_str.replace(" ", "").replace("0x", "")
    if len(h) % 2 != 0:
        h = "0" + h
    return bytes(int(h[i : i + 2], 16) for i in range(0, len(h), 2))

def ascii_to_hex(text):
    """'Hello' -> '48 65 6C 6C 6F'"""
    return " ".join(f"{ord(c):02X}" for c in text)

def xor_decode(data, key):
    return bytes(b ^ key for b in data)

def brute_force(data):
    print(f"  Hex: {' '.join(f'{b:02X}' for b in data)}")
    ascii_rep = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    print(f"  Raw: {ascii_rep}")
    print()
    found = 0
    for k in range(256):
        r = xor_decode(data, k)
        if all(32 <= b < 127 for b in r):
            found += 1
            key_char = chr(k) if 32 <= k < 127 else "?"
            print(f"  XOR 0x{k:02X} ({key_char}) -> {r.decode()}")
    if found == 0:
        print("  (no readable results found)")

def show_hex_decode(hex_str):
    data = hex_to_bytes(hex_str)
    print(f"\n=== HEX -> DECIMAL -> ASCII ===")
    print(f"  {'Hex':>5}  {'Dec':>4}  {'Char'}")
    print(f"  {'-' * 5}  {'-' * 4}  {'-' * 4}")
    for b in data:
        c = chr(b) if 32 <= b < 127 else "."
        print(f"  0x{b:02X}  {b:>4}  {c}")
    print()
    print(f"  Hex:      {' '.join(f'{b:02X}' for b in data)}")
    print(f"  Decimal:  {' '.join(f'{b:3d}' for b in data)}")
    print(f"  ASCII:    {data.decode('ascii', errors='replace')}")

def show_tohex(text):
    h = " ".join(f"{ord(c):02X}" for c in text)
    print(f'\n  "{text}" -> {h}')

def aes_encrypt(text, key_str):
    """Encrypts plaintext using AES-CBC and outputs HEX"""
    # Key must be exactly 16 bytes for AES-128
    key = key_str.encode('utf-8')[:16].ljust(16, b'\x00')
    # Using a fixed IV for simplicity and consistency in helper scripts
    iv = b'\x00' * 16 
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(text.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    
    print(f"\n=== AES ENCRYPT ===")
    print(f"  Plaintext:  {text}")
    print(f"  Key:        {key_str} (Aligned to 16 Bytes)")
    print(f"  Result HEX: {encrypted_bytes.hex().upper()}")

def aes_decrypt(hex_str, key_str):
    """Decrypts HEX ciphertext using AES-CBC and outputs plaintext"""
    try:
        data = hex_to_bytes(hex_str)
        key = key_str.encode('utf-8')[:16].ljust(16, b'\x00')
        iv = b'\x00' * 16
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(data)
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        
        print(f"\n=== AES DECRYPT ===")
        print(f"  Ciphertext HEX: {hex_str}")
        print(f"  Decrypted Text: {decrypted_data.decode('utf-8')}")
    except Exception as e:
        print(f"\n[!] AES Decryption Error: Wrong key or corrupted data. ({e})")

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    args = sys.argv[1:]

    if args[0] == "--dec" and len(args) >= 2:
        val = int(args[1], 16)
        print(f"\n  {args[1]} = {val}")
        return

    if args[0] == "--hex" and len(args) >= 2:
        show_hex_decode(args[1])
        return

    if args[0] == "--tohex" and len(args) >= 2:
        show_tohex(" ".join(args[1:]))
        return

    if args[0] == "--aes-enc" and len(args) >= 3:
        aes_encrypt(args[1], args[2])
        return

    if args[0] == "--aes-dec" and len(args) >= 3:
        aes_decrypt(args[1], args[2])
        return

    try:
        data = hex_to_bytes(args[0])
    except:
        print(f"[!] Invalid hex: {args[0]}")
        return

    if len(args) >= 2:
        key = int(args[1], 16)
        r = xor_decode(data, key)
        print(f"\n  XOR 0x{key:02X} -> {r}")
        try:
            print(f"                 -> {r.decode()}")
        except:
            pass
    else:
        brute_force(data)

if __name__ == "__main__":
    main()
