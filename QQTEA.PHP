<?php
class QQTEA
{
    // TEA 算法的 Delta 常量
    private $delta = 0x9E3779B9;
    // TEA 算法的轮数
    private $round = 16;
    // TEA 算法的掩码，用于保证 32 位操作
    private $op = 0xFFFFFFFF;
    // 填充标记，默认 7 个零字节
    private $flag = "\0\0\0\0\0\0\0";

    // 执行 XOR 操作
    private function xorBytes($a, $b)
    {
        return $a ^ $b;
    }

    // TEA 加密过程
    private function encipher($t, $share_key)
    {
        $sum = $this->delta;
        $keys = unpack('N4', $share_key); // 将密钥从二进制数据转换为四个 32 位无符号整数

        if (strlen($t) < 8) {
            throw new Exception('Input length is too short for encipher');
        }

        // 将输入数据分割成两个 32 位的整数
        $uint32_1 = unpack('N', substr($t, 0, 4))[1];
        $uint32_2 = unpack('N', substr($t, 4, 4))[1];

        // TEA 加密的主要计算循环
        for ($i = 0; $i < $this->round; $i++) {
            $uint32_1 += (((($uint32_2 << 4) & 0xFFFFFFF0) + $keys[1]) ^ ($uint32_2 + $sum)) ^ (((($uint32_2 >> 5) & 0x07FFFFFF) + $keys[2]));
            $uint32_2 += (((($uint32_1 << 4) & 0xFFFFFFF0) + $keys[3]) ^ ($uint32_1 + $sum)) ^ (((($uint32_1 >> 5) & 0x07FFFFFF) + $keys[4]));
            $sum += $this->delta;
        }

        // 进行 32 位掩码处理，确保结果在 32 位范围内
        $uint32_1 &= $this->op;
        $uint32_2 &= $this->op;

        // 将两个 32 位整数打包成二进制数据
        return pack('NN', $uint32_1, $uint32_2);
    }

    // TEA 解密过程
    private function decipher($t, $share_key)
    {
        $sum = ($this->delta << 4) & $this->op;
        $keys = unpack('N4', $share_key); // 将密钥从二进制数据转换为四个 32 位无符号整数

        if (strlen($t) < 8) {
            throw new Exception('Input length is too short for decipher');
        }

        // 将输入数据分割成两个 32 位的整数
        $uint32_1 = unpack('N', substr($t, 0, 4))[1];
        $uint32_2 = unpack('N', substr($t, 4, 4))[1];

        // TEA 解密的主要计算循环
        for ($i = 0; $i < $this->round; $i++) {
            $uint32_2 -= (((($uint32_1 << 4) & 0xFFFFFFF0) + $keys[3]) ^ ($uint32_1 + $sum)) ^ (((($uint32_1 >> 5) & 0x07FFFFFF) + $keys[4]));
            $uint32_1 -= (((($uint32_2 << 4) & 0xFFFFFFF0) + $keys[1]) ^ ($uint32_2 + $sum)) ^ (((($uint32_2 >> 5) & 0x07FFFFFF) + $keys[2]));
            $sum -= $this->delta;
        }

        // 进行 32 位掩码处理，确保结果在 32 位范围内
        $uint32_1 &= $this->op;
        $uint32_2 &= $this->op;

        // 将两个 32 位整数打包成二进制数据
        return pack('NN', $uint32_1, $uint32_2);
    }

    // 清理十六进制输入中的空格
    private function cleanHexInput($hex)
    {
        return str_replace(' ', '', $hex); // 去除输入中的空格
    }

    // 加密函数
    public function encrypt($cleartext_hex, $share_key_hex)
    {
        // 清理输入数据中的空格
        $cleartext_hex = $this->cleanHexInput($cleartext_hex);
        $share_key_hex = $this->cleanHexInput($share_key_hex);

        // 将十六进制文本转换为二进制数据
        $cleartext = hex2bin($cleartext_hex);
        $share_key = hex2bin($share_key_hex);

        // 计算填充长度
        $cleartext_length = strlen($cleartext);
        $padding_length = (8 - (($cleartext_length + 2) % 8)) % 8;
        $padding_length += 2 + ($padding_length < 0 ? 8 : 0);

        // 生成填充数据
        $padding_hex = '';
        for ($i = 0; $i < $padding_length; $i++) {
            $padding_hex .= chr(rand(1, 253)); // 随机填充字节
        }

        // 拼接填充数据和明文
        $padded_cleartext = chr(($padding_length - 2) | 0xF8) . $padding_hex . $cleartext . $this->flag;

        // TEA 加密
        $b1 = $b2 = str_repeat("\0", 8); // 初始化两个 8 字节的块
        $result = '';
        for ($i = 0; $i < strlen($padded_cleartext); $i += 8) {
            // 使用 XOR 操作与上一个块进行加密
            $t = $this->xorBytes(substr($padded_cleartext, $i, 8), $b1);
            $b1 = $this->xorBytes($this->encipher($t, $share_key), $b2);
            $b2 = $t;
            $result .= $b1;
        }

        // 返回加密结果的十六进制表示
        return bin2hex($result);
    }

    // 解密函数
    public function decrypt($ciphertext_hex, $share_key_hex)
    {
        // 清理输入数据中的空格
        $ciphertext_hex = $this->cleanHexInput($ciphertext_hex);
        $share_key_hex = $this->cleanHexInput($share_key_hex);

        // 将十六进制文本转换为二进制数据
        $ciphertext = hex2bin($ciphertext_hex);
        $share_key = hex2bin($share_key_hex);

        // 解密过程
        $ciphertext_len = strlen($ciphertext);

        if ($ciphertext_len < 8) {
            throw new Exception('Ciphertext length is too short for decryption');
        }

        // 解密第一个 8 字节的块
        $pre_crypt = substr($ciphertext, 0, 8);
        $pre_plain = $this->decipher($pre_crypt, $share_key);

        $result = $pre_plain;
        for ($i = 8; $i < $ciphertext_len; $i += 8) {
            // 解密过程中的块 XOR 操作
            $a = $this->xorBytes($this->decipher($this->xorBytes(substr($ciphertext, $i, 8), $pre_plain), $share_key), $pre_crypt);
            $pre_plain = $this->xorBytes($a, $pre_crypt);
            $pre_crypt = substr($ciphertext, $i, 8);
            $result .= $a;
        }

        // 去除填充
        $padding_length = ord($result[0]) & 0x07; // 计算填充长度
        $result = substr($result, 3 + $padding_length); // 去掉填充字段和填充数据
        $result = substr($result, 0, -7);// 去掉填充字段和填充数据

        // 返回解密结果的十六进制表示
        return bin2hex($result);
    }
}

// 使用示例
$tea = new QQTEA;
$jiami = $tea->encrypt("33b27688df3e5249a6a06fd2596bf35fe11f4abf84fb944cb1c332d02d51fd9f2719658f49c99c94e788680dc8ee7714b063304b96fb6cd0","00000000000000000000000000000000");
echo "加密内容：".$jiami."</br>";
$jiemi = $tea->decrypt($jiami,"00000000000000000000000000000000");
echo "解密内容：".$jiemi."</br>";
?>
