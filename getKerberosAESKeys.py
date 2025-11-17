#!/usr/bin/env python3
"""
get_kerberos_aes_key.py

Generate Kerberos AES-128 / AES-256 keys from a username/hostname+realm salt,
password and iteration count. Equivalent to the provided PowerShell function.

Author: adapted for Python
Requires: pycryptodome (pip install pycryptodome)
"""

import argparse
import getpass
import binascii
import hashlib
from Crypto.Cipher import AES

# Constants (same byte values as the PowerShell script)
AES256_CONSTANT = bytes([
    0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,
    0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,
    0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,
    0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
])
AES128_CONSTANT = bytes([
    0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,
    0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93
])

ZERO_IV = bytes(16)  # 16 zero bytes

def pbkdf2_sha1(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """
    PBKDF2-HMAC-SHA1 (Rfc2898). Equivalent to .NET Rfc2898DeriveBytes default behavior.
    """
    return hashlib.pbkdf2_hmac('sha1', password, salt, iterations, dklen=dklen)

def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes = ZERO_IV) -> bytes:
    """
    AES CBC encrypt with no padding. The caller must ensure len(data) % 16 == 0.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)

def derive_keys(password: str, salt: str, iterations: int = 4096):
    pw_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # PBKDF2: derive 32 bytes (256-bit) then take first 16 bytes for AES128 key
    pbkdf2_aes256_key = pbkdf2_sha1(pw_bytes, salt_bytes, iterations, dklen=32)
    pbkdf2_aes128_key = pbkdf2_aes256_key[:16]

    # Prepare AES objects / encryption operations
    # AES-256 path (two encrypt rounds as in the PowerShell)
    # first encrypt AES256_CONSTANT with derived AES256 key
    enc1 = aes_cbc_encrypt(pbkdf2_aes256_key, AES256_CONSTANT, ZERO_IV)
    # then encrypt the result again with same AES key
    enc2 = aes_cbc_encrypt(pbkdf2_aes256_key, enc1, ZERO_IV)
    # AES256 key is first 16 bytes of enc1 followed by first 16 bytes of enc2
    aes256_key = enc1[:16] + enc2[:16]

    # AES-128 path (single encrypt of AES128_CONSTANT with derived AES128 key)
    aes128_key = aes_cbc_encrypt(pbkdf2_aes128_key, AES128_CONSTANT, ZERO_IV)

    return {
        'pbkdf2_aes128': pbkdf2_aes128_key,
        'pbkdf2_aes256': pbkdf2_aes256_key,
        'aes128_key': aes128_key,
        'aes256_key': aes256_key
    }

def hexd(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

def main():
    parser = argparse.ArgumentParser(description="Derive Kerberos AES keys from password + salt")
    parser.add_argument('-p', '--password', help='Password (if omitted, will prompt)')
    parser.add_argument('-s', '--salt', required=True, help='Salt (realm+username or realm+host...)')
    parser.add_argument('-i', '--iterations', type=int, default=4096, help='PBKDF2 iteration count (default 4096)')
    parser.add_argument('-o', '--output', choices=['AES','AES128','AES256','AES128ByteArray','AES256ByteArray'],
                        default='AES', help='Output format (default AES)')
    args = parser.parse_args()

    password = args.password
    if password is None:
        password = getpass.getpass("Enter password: ")

    keys = derive_keys(password, args.salt, args.iterations)

    out = args.output
    if out == 'AES':
        print(f"AES128 Key: {hexd(keys['aes128_key'])}")
        print(f"AES256 Key: {hexd(keys['aes256_key'])}")
    elif out == 'AES128':
        print(hexd(keys['aes128_key']))
    elif out == 'AES256':
        print(hexd(keys['aes256_key']))
    elif out == 'AES128ByteArray':
        # print python bytes repr for clarity
        print(repr(keys['aes128_key']))
    elif out == 'AES256ByteArray':
        print(repr(keys['aes256_key']))

if __name__ == '__main__':
    main()
