#!/usr/bin/env python
import struct
import random
import binascii

class QQTEA(object):
    def __init__(self):
        # key schedule constant
        self.delta = 0x9E3779B9

        self.round = 16

        self.op = 0xFFFFFFFF

        # append 7 '\0' in the end of the message.
        self.flag = bytes(7)

    # xor per 8 bytes
    def __xor(self, a, b):
        block = b''
        for byte_a, byte_b in zip(a, b):
            block += struct.pack("B", byte_a ^ byte_b)
        return block

    def __encipher(self, t, share_key):
        sum = self.delta

        keys = struct.unpack(">LLLL", share_key)
        uint32_1, uint32_2 = struct.unpack(">LL", t)

        for _ in range(self.round):
            uint32_1 += (((uint32_2 << 4) & 0xFFFFFFF0) + keys[0]) ^ (
                uint32_2 + sum) ^ (((uint32_2 >> 5) & 0x07ffffff) + keys[1])
            uint32_2 += (((uint32_1 << 4) & 0xFFFFFFF0) + keys[2]) ^ (
                uint32_1 + sum) ^ (((uint32_1 >> 5) & 0x07ffffff) + keys[3])
            sum += self.delta
        uint32_1 &= self.op
        uint32_2 &= self.op

        return struct.pack(">LL", uint32_1, uint32_2)

    def __decipher(self, t, share_key):
        sum = (self.delta << 4) & self.op

        keys = struct.unpack(">LLLL", share_key)
        uint32_1, uint32_2 = struct.unpack(">LL", t)

        for _ in range(self.round):
            uint32_2 -= (((uint32_1 << 4) & 0xFFFFFFF0) + keys[2]) ^ (
                uint32_1 + sum) ^ (((uint32_1 >> 5) & 0x07ffffff) + keys[3])
            uint32_1 -= (((uint32_2 << 4) & 0xFFFFFFF0) + keys[0]) ^ (
                uint32_2 + sum) ^ (((uint32_2 >> 5) & 0x07ffffff) + keys[1])
            sum -= self.delta
        uint32_1 &= self.op
        uint32_2 &= self.op

        return struct.pack(">LL", uint32_1, uint32_2)

    def encrypt(self, cleartext, share_key):
        cleartext_length = len(cleartext)

        # to count the number of fill bytes.
        padding_length = (8 - (cleartext_length + 2)) % 8
        padding_length += 2 + (8 if (padding_length < 0) else 0)

        # filling the random bytes
        padding_hex = b''
        for _ in range(0, padding_length):
            padding_hex += struct.pack("B", random.randrange(1, 254))

        # merge
        padded_cleartext = struct.pack(
            "B", (padding_length - 2) | 0xF8) + padding_hex + cleartext + self.flag

        b1 = b2 = bytes(8)
        result = b''
        # xor per 8 bytes
        for i in range(0, len(padded_cleartext), 8):
            t = self.__xor(padded_cleartext[i:i + 8], b1)
            b1 = self.__xor(self.__encipher(t, share_key), b2)
            b2 = t
            result += b1
        return result

    def decrypt(self, ciphertext, share_key):
        ciphertext_len = len(ciphertext)
        pre_crypt = ciphertext[0:8]
        pre_plain = self.__decipher(pre_crypt, share_key)

        pos = (pre_plain[0] & 0x07) + 2
        result = pre_plain
        for i in range(8, ciphertext_len, 8):
            a = self.__xor(self.__decipher(self.__xor(
                ciphertext[i:i + 8], pre_plain), share_key), pre_crypt)
            pre_plain = self.__xor(a, pre_crypt)
            pre_crypt = ciphertext[i:i + 8]
            result += a
        if result[-7:] == b'\0' * 7:
            return result[pos + 1:-7]
        else:
            return result

# 示例数据
cleartext_hex = "33b27688df3e5249a6a06fd2596bf35fe11f4abf84fb944cb1c332d02d51fd9f2719658f49c99c94e788680dc8ee7714b063304b96fb6cd0"
share_key_hex = "00000000000000000000000000000000"

# 转换十六进制数据到字节
cleartext = binascii.unhexlify(cleartext_hex)
share_key = binascii.unhexlify(share_key_hex)

# 创建 QQTEA 实例
tea = QQTEA()

# 加密
encrypted = tea.encrypt(cleartext, share_key)
encrypted_hex = binascii.hexlify(encrypted).decode('ascii')
print(f"Encrypted: {encrypted_hex}")

# 解密
decrypted = tea.decrypt(encrypted, share_key)
decrypted_hex = binascii.hexlify(decrypted).decode('ascii')
print(f"Decrypted: {decrypted_hex}")

# 验证解密结果
assert decrypted_hex == cleartext_hex, "Decryption failed: The decrypted text does not match the original plaintext."
