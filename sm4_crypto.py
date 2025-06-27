#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4加密、解密和爆破工具
SM4是中国国家密码管理局发布的分组密码标准
"""

import binascii
import itertools
import string
import time

class SM4Crypto:
    def __init__(self):
        # SM4 S盒
        self.S_BOX = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        ]
        
        # 系统参数FK
        self.FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        
        # 固定参数CK
        self.CK = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        ]
    
    def _rotl(self, n, k):
        """循环左移"""
        return ((n << k) | (n >> (32 - k))) & 0xffffffff
    
    def _bytes_to_list(self, data):
        """字节转换为32位整数列表"""
        return [int.from_bytes(data[i:i+4], 'big') for i in range(0, len(data), 4)]
    
    def _list_to_bytes(self, data):
        """32位整数列表转换为字节"""
        result = b''
        for x in data:
            result += x.to_bytes(4, 'big')
        return result
    
    def _sm4_sbox(self, inch):
        """SM4 S盒变换"""
        return (self.S_BOX[inch >> 24 & 0xff] << 24 |
                self.S_BOX[inch >> 16 & 0xff] << 16 |
                self.S_BOX[inch >> 8 & 0xff] << 8 |
                self.S_BOX[inch & 0xff])
    
    def _sm4_l(self, b):
        """线性变换L"""
        return b ^ self._rotl(b, 2) ^ self._rotl(b, 10) ^ self._rotl(b, 18) ^ self._rotl(b, 24)
    
    def _sm4_l1(self, b):
        """线性变换L1"""
        return b ^ self._rotl(b, 13) ^ self._rotl(b, 23)
    
    def _sm4_t(self, a):
        """合成置换T"""
        return self._sm4_l(self._sm4_sbox(a))
    
    def _sm4_t1(self, a):
        """合成置换T1"""
        return self._sm4_l1(self._sm4_sbox(a))
    
    def _sm4_key_schedule(self, key):
        """密钥扩展算法"""
        mkey = self._bytes_to_list(key)
        k = [0] * 36
        k[0] = mkey[0] ^ self.FK[0]
        k[1] = mkey[1] ^ self.FK[1]
        k[2] = mkey[2] ^ self.FK[2]
        k[3] = mkey[3] ^ self.FK[3]
        
        for i in range(32):
            k[i + 4] = k[i] ^ self._sm4_t1(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ self.CK[i])
            k[i + 4] &= 0xffffffff
        
        return k[4:]
    
    def _sm4_one_round(self, sk, plaintext):
        """SM4一轮加密"""
        ulbuf = self._bytes_to_list(plaintext)
        for i in range(32):
            ulbuf.append(ulbuf[i] ^ self._sm4_t(ulbuf[i + 1] ^ ulbuf[i + 2] ^ ulbuf[i + 3] ^ sk[i]))
            ulbuf[i + 4] &= 0xffffffff
        
        return self._list_to_bytes([ulbuf[35], ulbuf[34], ulbuf[33], ulbuf[32]])
    
    def encrypt(self, plaintext, key):
        """SM4加密"""
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")
        if len(plaintext) != 16:
            raise ValueError("SM4明文必须是16字节")
        
        round_key = self._sm4_key_schedule(key)
        return self._sm4_one_round(round_key, plaintext)
    
    def decrypt(self, ciphertext, key):
        """SM4解密"""
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")
        if len(ciphertext) != 16:
            raise ValueError("SM4密文必须是16字节")
        
        round_key = self._sm4_key_schedule(key)
        round_key.reverse()  # 解密时轮密钥逆序
        return self._sm4_one_round(round_key, ciphertext)
    
    def encrypt_ecb(self, plaintext, key):
        """SM4 ECB模式加密"""
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")
        
        # PKCS7填充
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += bytes([pad_len] * pad_len)
        
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            ciphertext += self.encrypt(block, key)
        
        return ciphertext
    
    def decrypt_ecb(self, ciphertext, key):
        """SM4 ECB模式解密"""
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度必须是16的倍数")
        
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            plaintext += self.decrypt(block, key)
        
        # 去除PKCS7填充
        pad_len = plaintext[-1]
        return plaintext[:-pad_len]


def get_custom_ascii_charset(start_ascii, end_ascii):
    """
    根据ASCII范围生成自定义字符集
    Args:
        start_ascii: 起始ASCII值 (0-255)
        end_ascii: 终止ASCII值 (0-255)
    Returns:
        str: 自定义字符集字符串
    """
    if start_ascii < 0 or end_ascii > 255:
        raise ValueError("ASCII值必须在0-255范围内")
    if start_ascii > end_ascii:
        raise ValueError("起始ASCII值不能大于终止ASCII值")
    
    charset = ""
    for i in range(start_ascii, end_ascii + 1):
        try:
            char = chr(i)
            # 过滤掉一些控制字符，但保留可打印的扩展ASCII字符
            if i >= 32 or char in ['\t', '\n', '\r']:
                charset += char
        except ValueError:
            continue  # 跳过无效字符
    return charset

def get_charset_by_choice(choice, custom_start=None, custom_end=None):
    """
    根据用户选择返回对应的字符集
    """
    charsets = {
        '1': string.ascii_uppercase,                    # 大写字母
        '2': string.ascii_lowercase,                    # 小写字母
        '3': string.digits,                             # 数字
        '4': string.digits + string.ascii_uppercase,    # 数字与大写字母
        '5': string.digits + string.ascii_lowercase,    # 数字与小写字母
        '6': string.ascii_uppercase + string.ascii_lowercase,  # 大写字母与小写字母
        '7': string.ascii_uppercase + string.ascii_lowercase + string.digits,  # 全部
        '8': get_custom_ascii_charset(custom_start, custom_end) if custom_start is not None and custom_end is not None else ""  # 自定义ASCII范围
    }
    return charsets.get(choice, string.ascii_lowercase)

def show_charset_menu():
    """显示字符集选择菜单"""
    print("\n字符集选择:")
    print("1. 大写字母 (A-Z)")
    print("2. 小写字母 (a-z)")
    print("3. 数字 (0-9)")
    print("4. 数字与大写字母 (0-9, A-Z)")
    print("5. 数字与小写字母 (0-9, a-z)")
    print("6. 大写字母与小写字母 (A-Z, a-z)")
    print("7. 大写字母与小写字母与数字 (A-Z, a-z, 0-9)")
    print("8. 自定义ASCII范围")
    
    while True:
        charset_choice = input("请选择字符集 (1-8): ").strip()
        if charset_choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
            if charset_choice == '8':
                return get_custom_charset_input()
            return charset_choice, None, None
        print("无效选择，请重新输入")

def get_custom_charset_input():
    """获取自定义ASCII范围输入"""
    print("\n自定义ASCII字符集范围:")
    print("常用ASCII参考:")
    print("  控制字符: 0-31")
    print("  可打印字符: 32-126")
    print("  数字: 48-57 (0-9)")
    print("  大写字母: 65-90 (A-Z)")
    print("  小写字母: 97-122 (a-z)")
    print("  扩展ASCII: 128-255")
    
    while True:
        try:
            start_ascii = int(input("请输入起始ASCII值 (0-255): ").strip())
            end_ascii = int(input("请输入终止ASCII值 (0-255): ").strip())
            
            if start_ascii < 0 or end_ascii > 255:
                print("❌ ASCII值必须在0-255范围内")
                continue
            if start_ascii > end_ascii:
                print("❌ 起始ASCII值不能大于终止ASCII值")
                continue
                
            # 生成字符集预览
            charset = get_custom_ascii_charset(start_ascii, end_ascii)
            print(f"生成的字符集长度: {len(charset)}")
            if len(charset) > 0:
                # 显示可打印字符的预览
                printable_chars = ''.join(c for c in charset if c.isprintable())
                if printable_chars:
                    preview = printable_chars[:50]
                    if len(printable_chars) > 50:
                        preview += "..."
                    print(f"可打印字符预览: {preview}")
                else:
                    print("注意：此范围主要包含控制字符")
            
            if len(charset) == 0:
                print("❌ 生成的字符集为空，请重新选择范围")
                continue
                
            confirm = input("确认使用此字符集? (y/n): ").strip().lower()
            if confirm == 'y':
                return '8', start_ascii, end_ascii
            else:
                continue
                
        except ValueError:
            print("❌ 请输入有效的数字")

def get_length_range():
    """获取密码长度范围"""
    print("\n密码长度范围设置:")
    while True:
        try:
            min_len = int(input("请输入最小长度 (默认1): ") or "1")
            max_len = int(input("请输入最大长度 (默认4): ") or "4")
            
            if min_len < 1:
                print("❌ 最小长度不能小于1")
                continue
            if max_len < min_len:
                print("❌ 最大长度不能小于最小长度")
                continue
            if max_len > 8:
                print("⚠️  警告：长度超过8可能需要很长时间")
                confirm = input("确定要继续吗? (y/n): ")
                if confirm.lower() != 'y':
                    continue
                    
            return min_len, max_len
        except ValueError:
            print("❌ 请输入有效的数字")

def brute_force_sm4_custom_charset(ciphertext, charset_choice, target_plaintext=None, min_length=1, max_length=4, custom_start=None, custom_end=None):
    """
    SM4自定义字符集暴力破解
    """
    sm4 = SM4Crypto()
    attempts = 0
    start_time = time.time()
    charset = get_charset_by_choice(charset_choice, custom_start, custom_end)
    
    charset_names = {
        '1': '大写字母',
        '2': '小写字母',
        '3': '数字',
        '4': '数字与大写字母',
        '5': '数字与小写字母',
        '6': '大写字母与小写字母',
        '7': '大写字母与小写字母与数字',
        '8': f'自定义ASCII范围 ({custom_start}-{custom_end})' if custom_start is not None and custom_end is not None else '自定义'
    }
    
    print(f"开始SM4自定义字符集暴力破解 (长度范围: {min_length}-{max_length})")
    print(f"选择的字符集: {charset_names.get(charset_choice, '未知')} ({charset})")
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    print("-" * 80)
    
    # 根据字符集大小调整最大尝试次数
    max_attempts = {
        '1': 50000,    # 大写字母 (26)
        '2': 50000,    # 小写字母 (26)
        '3': 100000,   # 数字 (10)
        '4': 80000,    # 数字+大写 (36)
        '5': 80000,    # 数字+小写 (36)
        '6': 60000,    # 大写+小写 (52)
        '7': 50000,    # 全部 (62)
        '8': 40000     # 自定义
    }.get(charset_choice, 50000)
    
    for length in range(min_length, max_length + 1):
        print(f"尝试长度为 {length} 的密钥...")
        
        for key_tuple in itertools.product(charset, repeat=length):
            attempts += 1
            key_str = ''.join(key_tuple)
            
            # 补齐到16字节
            key = (key_str * (16 // len(key_str) + 1))[:16].encode()
            
            try:
                decrypted = sm4.decrypt_ecb(ciphertext, key)
                result = decrypted.decode('utf-8', errors='ignore')
                
                if target_plaintext and target_plaintext.lower() in result.lower():
                    elapsed = time.time() - start_time
                    print(f"\n*** 找到密钥! ***")
                    print(f"密钥: {key_str} -> {key}")
                    print(f"解密结果: {result}")
                    print(f"尝试次数: {attempts}")
                    print(f"耗时: {elapsed:.2f}秒")
                    return key, result
                
                if all(c.isprintable() for c in result):
                    print(f"密钥 {key_str}: {result[:50]}")
                    
            except Exception:
                continue
                
            if attempts % 2000 == 0:
                elapsed = time.time() - start_time
                print(f"已尝试 {attempts} 个密钥... ({elapsed:.1f}秒)")
                
            # 移除尝试次数限制，允许无限次尝试
            # if attempts > max_attempts:
            #     print(f"达到最大尝试次数限制 ({max_attempts})")
            #     break
        
        # 移除长度循环的尝试次数限制
        # if attempts > max_attempts:
        #     break
    
    elapsed = time.time() - start_time
    print(f"\n暴力破解完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None

# 保留原有函数作为兼容性接口
def brute_force_sm4_numeric(ciphertext, target_plaintext=None, min_length=1, max_length=6):
    """SM4数字密钥暴力破解（兼容性接口）"""
    return brute_force_sm4_custom_charset(ciphertext, '3', target_plaintext, min_length, max_length)

def brute_force_sm4_alpha(ciphertext, target_plaintext=None, min_length=1, max_length=4):
    """SM4字母密钥暴力破解（兼容性接口）"""
    return brute_force_sm4_custom_charset(ciphertext, '2', target_plaintext, min_length, max_length)

def brute_force_sm4_alphanumeric(ciphertext, target_plaintext=None, min_length=1, max_length=3):
    """SM4字母数字混合密钥暴力破解（兼容性接口）"""
    return brute_force_sm4_custom_charset(ciphertext, '5', target_plaintext, min_length, max_length)

def main():
    print("=" * 60)
    print("SM4加密解密工具")
    print("=" * 60)
    
    sm4 = SM4Crypto()
    
    while True:
        print("\n选择操作:")
        print("1. 生成随机密钥")
        print("2. ECB模式加密")
        print("3. ECB模式解密")
        print("4. 单块加密")
        print("5. 单块解密")
        print("6. 数字密钥暴力破解")
        print("7. 字母密钥暴力破解")
        print("8. 字母数字混合密钥暴力破解")
        print("9. 自定义字符集暴力破解")
        print("10. 退出")
        
        choice = input("\n请选择 (1-10): ").strip()
        
        if choice == '1':
            import os
            key = os.urandom(16)
            print(f"随机密钥: {binascii.hexlify(key).decode()}")
            
        elif choice == '2':
            try:
                # 尝试导入通用函数
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                # 获取明文输入
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                # 获取密钥输入（SM4需要16字节密钥）
                key = get_key_input("请输入SM4密钥", 16)
                if key is None:
                    continue
                
                # 执行加密
                ciphertext = sm4.encrypt_ecb(plaintext_data, key)
                
                # 显示结果
                display_result(ciphertext, "ciphertext")
                
            except ImportError:
                # 如果无法导入通用函数，使用原来的方式
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = sm4.encrypt_ecb(plaintext, key)
                    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ 加密失败: {e}")
            except Exception as e:
                print(f"❌ SM4 ECB加密过程中发生错误: {e}")
                
        elif choice == '3':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                # 获取密文输入
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                # 获取密钥输入
                key = get_key_input("请输入SM4密钥", 16)
                if key is None:
                    continue
                
                # 执行解密
                plaintext = sm4.decrypt_ecb(ciphertext_data, key)
                
                # 显示结果
                display_result(plaintext, "plaintext")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = sm4.decrypt_ecb(ciphertext, key)
                    print(f"明文: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ 解密失败: {e}")
            except Exception as e:
                print(f"❌ SM4 ECB解密过程中发生错误: {e}")
                
        elif choice == '4':
            plaintext_hex = input("请输入明文(16进制，16字节): ").strip()
            key_hex = input("请输入密钥(16进制): ").strip()
            try:
                plaintext = binascii.unhexlify(plaintext_hex)
                key = binascii.unhexlify(key_hex)
                ciphertext = sm4.encrypt(plaintext, key)
                print(f"密文: {binascii.hexlify(ciphertext).decode()}")
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '5':
            ciphertext_hex = input("请输入密文(16进制，16字节): ").strip()
            key_hex = input("请输入密钥(16进制): ").strip()
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                key = binascii.unhexlify(key_hex)
                plaintext = sm4.decrypt(ciphertext, key)
                print(f"明文: {binascii.hexlify(plaintext).decode()}")
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '6':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            target = input("请输入目标明文(可选): ").strip()
            max_len = int(input("请输入最大密钥长度(默认6): ") or "6")
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_sm4_numeric(ciphertext, target, max_len)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '7':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            target = input("请输入目标明文(可选): ").strip()
            max_len = int(input("请输入最大密钥长度(默认4): ") or "4")
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_sm4_alpha(ciphertext, target, max_len)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '8':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            target = input("请输入目标明文(可选): ").strip()
            max_len = int(input("请输入最大密钥长度(默认3): ") or "3")
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_sm4_alphanumeric(ciphertext, target, max_len)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '9':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            charset_result = show_charset_menu()
            if len(charset_result) == 3:
                charset_choice, custom_start, custom_end = charset_result
            else:
                charset_choice = charset_result
                custom_start = custom_end = None
                
            target = input("请输入目标明文(可选): ").strip()
            min_len, max_len = get_length_range()
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_sm4_custom_charset(ciphertext, charset_choice, target, min_len, max_len, custom_start, custom_end)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '10':
            print("退出程序")
            break
            
        else:
            print("无效选择，请重新输入")

if __name__ == "__main__":
    # 示例用法
    print("SM4加密示例:")
    
    sm4 = SM4Crypto()
    
    # 生成密钥
    import os
    key = os.urandom(16)
    plaintext = "Hello SM4!".encode('utf-8')
    
    print(f"明文: {plaintext.decode()}")
    print(f"密钥: {binascii.hexlify(key).decode()}")
    
    # ECB加密
    ciphertext_ecb = sm4.encrypt_ecb(plaintext, key)
    print(f"ECB密文: {binascii.hexlify(ciphertext_ecb).decode()}")
    
    # ECB解密
    decrypted_ecb = sm4.decrypt_ecb(ciphertext_ecb, key)
    print(f"ECB解密: {decrypted_ecb.decode()}")
    
    print("\n" + "="*60)
    main()