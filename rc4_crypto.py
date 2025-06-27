#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC4加密、解密和爆破工具
RC4是流密码，加密和解密过程相同
"""

import binascii
import itertools
import string
import time

class RC4Crypto:
    def __init__(self):
        pass
    
    def rc4_init(self, key):
        """
        RC4密钥调度算法(KSA)
        """
        key_length = len(key)
        S = list(range(256))
        j = 0
        
        for i in range(256):
            j = (j + S[i] + key[i % key_length]) % 256
            S[i], S[j] = S[j], S[i]
        
        return S
    
    def rc4_crypt(self, data, key):
        """
        RC4加密/解密 (伪随机子密码生成算法PRGA)
        RC4加密和解密是同一个过程
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        S = self.rc4_init(key)
        
        i = j = 0
        result = []
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result)
    
    def encrypt(self, plaintext, key):
        """RC4加密"""
        return self.rc4_crypt(plaintext, key)
    
    def decrypt(self, ciphertext, key):
        """RC4解密（与加密相同）"""
        return self.rc4_crypt(ciphertext, key)

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
            max_len = int(input("请输入最大长度 (默认5): ") or "5")
            
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

def brute_force_rc4_custom_charset(ciphertext, charset_choice, target_plaintext=None, min_length=1, max_length=5, custom_start=None, custom_end=None):
    """
    RC4自定义字符集暴力破解
    """
    rc4 = RC4Crypto()
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
    
    print(f"开始RC4自定义字符集暴力破解 (长度范围: {min_length}-{max_length})")
    print(f"选择的字符集: {charset_names.get(charset_choice, '未知')} ({charset})")
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    print("-" * 80)
    
    # 根据字符集大小调整最大尝试次数
    max_attempts = {
        '1': 100000,   # 大写字母 (26)
        '2': 100000,   # 小写字母 (26)
        '3': 200000,   # 数字 (10)
        '4': 150000,   # 数字+大写 (36)
        '5': 150000,   # 数字+小写 (36)
        '6': 120000,   # 大写+小写 (52)
        '7': 100000,   # 全部 (62)
        '8': 80000     # 自定义
    }.get(charset_choice, 100000)
    
    for length in range(min_length, max_length + 1):
        print(f"尝试长度为 {length} 的密钥...")
        
        for key_tuple in itertools.product(charset, repeat=length):
            attempts += 1
            key = ''.join(key_tuple)
            
            try:
                decrypted = rc4.decrypt(ciphertext, key)
                result = decrypted.decode('utf-8', errors='ignore')
                
                if target_plaintext and target_plaintext.lower() in result.lower():
                    elapsed = time.time() - start_time
                    print(f"\n*** 找到密钥! ***")
                    print(f"密钥: {key}")
                    print(f"解密结果: {result}")
                    print(f"尝试次数: {attempts}")
                    print(f"耗时: {elapsed:.2f}秒")
                    return key, result
                
                if all(c.isprintable() for c in result):
                    print(f"密钥 {key}: {result[:50]}")
                    
            except Exception:
                continue
                
            if attempts % 5000 == 0:
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
def brute_force_rc4_numeric(ciphertext, target_plaintext=None, min_length=1, max_length=6):
    """RC4数字密钥暴力破解（兼容性接口）"""
    return brute_force_rc4_custom_charset(ciphertext, '3', target_plaintext, min_length, max_length)

def brute_force_rc4_alpha(ciphertext, target_plaintext=None, min_length=1, max_length=5):
    """RC4字母密钥暴力破解（兼容性接口）"""
    return brute_force_rc4_custom_charset(ciphertext, '2', target_plaintext, min_length, max_length)

def brute_force_rc4_alphanumeric(ciphertext, target_plaintext=None, min_length=1, max_length=4):
    """RC4字母数字混合密钥暴力破解（兼容性接口）"""
    return brute_force_rc4_custom_charset(ciphertext, '5', target_plaintext, min_length, max_length)

def dictionary_attack_rc4(ciphertext, wordlist_file):
    """
    基于字典的RC4攻击
    """
    rc4 = RC4Crypto()
    attempts = 0
    start_time = time.time()
    
    print(f"开始RC4字典攻击")
    print(f"字典文件: {wordlist_file}")
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    print("-" * 60)
    
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                attempts += 1
                key = line.strip()
                
                if not key:
                    continue
                
                try:
                    decrypted = rc4.decrypt(ciphertext, key)
                    result = decrypted.decode('utf-8', errors='ignore')
                    
                    # 检查是否为可读文本
                    if all(c.isprintable() or c.isspace() for c in result):
                        elapsed = time.time() - start_time
                        print(f"\n*** 可能找到密钥! ***")
                        print(f"密钥: {key}")
                        print(f"解密结果: {result}")
                        print(f"尝试次数: {attempts}")
                        print(f"耗时: {elapsed:.2f}秒")
                        
                        confirm = input("是否继续寻找其他可能的密钥? (y/n): ")
                        if confirm.lower() != 'y':
                            return key, result
                        
                except Exception:
                    continue
                    
                if attempts % 1000 == 0:
                    elapsed = time.time() - start_time
                    print(f"已尝试 {attempts} 个密钥... ({elapsed:.1f}秒)")
                    
    except FileNotFoundError:
        print(f"字典文件 {wordlist_file} 不存在")
        return None, None
    
    elapsed = time.time() - start_time
    print(f"\n字典攻击完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None

def keystream_analysis(ciphertext1, plaintext1, ciphertext2):
    """
    RC4密钥流分析（当已知一对明文密文时）
    """
    print("RC4密钥流分析")
    print(f"已知密文1: {binascii.hexlify(ciphertext1).decode()}")
    print(f"已知明文1: {plaintext1}")
    print(f"未知密文2: {binascii.hexlify(ciphertext2).decode()}")
    print("-" * 60)
    
    if isinstance(plaintext1, str):
        plaintext1 = plaintext1.encode('utf-8')
    
    # 计算密钥流
    keystream = bytes(a ^ b for a, b in zip(ciphertext1, plaintext1))
    print(f"提取的密钥流: {binascii.hexlify(keystream).decode()}")
    
    # 使用密钥流解密第二个密文
    min_len = min(len(keystream), len(ciphertext2))
    decrypted = bytes(keystream[i] ^ ciphertext2[i] for i in range(min_len))
    
    try:
        result = decrypted.decode('utf-8', errors='ignore')
        print(f"解密结果: {result}")
        return result
    except Exception as e:
        print(f"解密失败: {e}")
        return None

def main():
    print("=" * 60)
    print("RC4加密解密工具")
    print("=" * 60)
    
    rc4 = RC4Crypto()
    
    while True:
        print("\n选择操作:")
        print("1. 加密")
        print("2. 解密")
        print("3. 自定义字符集暴力破解")
        print("4. 字典攻击")
        print("5. 密钥流分析")
        print("6. 退出")
        
        choice = input("\n请选择 (1-6): ").strip()
        
        if choice == '1':
            try:
                from crypto_toolkit import get_input_with_format_choice, display_result
                
                # 获取明文输入
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                # 获取密钥输入
                key_data, _ = get_input_with_format_choice("请输入RC4密钥", "key")
                if key_data is None:
                    continue
                
                # 执行加密
                ciphertext = rc4.encrypt(plaintext_data, key_data)
                
                # 显示结果
                display_result(ciphertext, "ciphertext")
                
            except ImportError:
                plaintext = input("请输入明文: ")
                key = input("请输入密钥: ")
                ciphertext = rc4.encrypt(plaintext, key)
                print(f"密文: {binascii.hexlify(ciphertext).decode()}")
            except Exception as e:
                print(f"❌ RC4加密过程中发生错误: {e}")
            
        elif choice == '2':
            try:
                from crypto_toolkit import get_input_with_format_choice, display_result
                
                # 获取密文输入
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                # 获取密钥输入
                key_data, _ = get_input_with_format_choice("请输入RC4密钥", "key")
                if key_data is None:
                    continue
                
                # 执行解密
                plaintext = rc4.decrypt(ciphertext_data, key_data)
                
                # 显示结果
                display_result(plaintext, "plaintext")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制): ").strip()
                key = input("请输入密钥: ")
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    plaintext = rc4.decrypt(ciphertext, key)
                    print(f"明文: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ 解密失败: {e}")
            except Exception as e:
                print(f"❌ RC4解密过程中发生错误: {e}")
                
        elif choice == '3':
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
                brute_force_rc4_custom_charset(ciphertext, charset_choice, target, min_len, max_len, custom_start, custom_end)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '4':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            wordlist = input("请输入字典文件路径: ").strip()
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                dictionary_attack_rc4(ciphertext, wordlist)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '5':
            ciphertext1_hex = input("请输入已知密文1(16进制): ").strip()
            plaintext1 = input("请输入对应明文1: ").strip()
            ciphertext2_hex = input("请输入待解密密文2(16进制): ").strip()
            try:
                ciphertext1 = binascii.unhexlify(ciphertext1_hex)
                ciphertext2 = binascii.unhexlify(ciphertext2_hex)
                keystream_analysis(ciphertext1, plaintext1, ciphertext2)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '6':
            print("退出程序")
            break
            
        else:
            print("无效选择，请重新输入")

if __name__ == "__main__":
    # 示例用法
    print("RC4加密示例:")
    
    rc4 = RC4Crypto()
    
    plaintext = "Hello RC4!"
    key = "secret"
    
    print(f"明文: {plaintext}")
    print(f"密钥: {key}")
    
    # 加密
    ciphertext = rc4.encrypt(plaintext, key)
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    
    # 解密
    decrypted = rc4.decrypt(ciphertext, key)
    print(f"解密: {decrypted.decode()}")
    
    print("\n" + "="*60)
    main()