#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DES加密、解密和爆破工具
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import itertools
import string
import time
import sys

class DESCrypto:
    def __init__(self):
        self.block_size = DES.block_size
        
    def generate_key(self):
        """生成随机DES密钥（8字节）"""
        return get_random_bytes(8)
    
    def encrypt_ecb(self, plaintext, key, use_padding=True):
        """DES ECB模式加密"""
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节")
        
        if use_padding:
            cipher = DES.new(key, DES.MODE_ECB)
            padded_data = pad(plaintext, self.block_size)
            ciphertext = cipher.encrypt(padded_data)
        else:
            # 不使用填充时，明文长度必须是块大小的倍数
            if len(plaintext) % self.block_size != 0:
                raise ValueError(f"不使用填充时，明文长度必须是{self.block_size}字节的倍数")
            cipher = DES.new(key, DES.MODE_ECB)
            ciphertext = cipher.encrypt(plaintext)
        return ciphertext
    
    def decrypt_ecb(self, ciphertext, key, use_padding=True):
        """DES ECB模式解密"""
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节")
        
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_data = cipher.decrypt(ciphertext)
        
        if use_padding:
            plaintext = unpad(decrypted_data, self.block_size)
        else:
            plaintext = decrypted_data
        return plaintext
    
    def encrypt_cbc(self, plaintext, key, iv=None, use_padding=True):
        """DES CBC模式加密"""
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节")
        
        if iv is None:
            iv = get_random_bytes(8)
        elif len(iv) != 8:
            raise ValueError("IV必须是8字节")
        
        if use_padding:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_data = pad(plaintext, self.block_size)
            ciphertext = cipher.encrypt(padded_data)
        else:
            # 不使用填充时，明文长度必须是块大小的倍数
            if len(plaintext) % self.block_size != 0:
                raise ValueError(f"不使用填充时，明文长度必须是{self.block_size}字节的倍数")
            cipher = DES.new(key, DES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(plaintext)
        return iv + ciphertext
    
    def decrypt_cbc(self, ciphertext, key, use_padding=True):
        """DES CBC模式解密"""
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节")
        
        iv = ciphertext[:8]
        actual_ciphertext = ciphertext[8:]
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(actual_ciphertext)
        
        if use_padding:
            plaintext = unpad(decrypted_data, self.block_size)
        else:
            plaintext = decrypted_data
        return plaintext

def calculate_total_combinations(charset, min_length, max_length):
    """计算总的组合数"""
    total = 0
    charset_len = len(charset)
    for length in range(min_length, max_length + 1):
        total += charset_len ** length
    return total

def print_progress_bar(current, total, start_time, bar_length=50):
    """显示进度条"""
    if total == 0:
        return
        
    percent = min(100.0, (current / total) * 100)
    elapsed_time = time.time() - start_time
    
    # 计算预估剩余时间
    if current > 0:
        eta = (elapsed_time / current) * (total - current)
        eta_str = f"{int(eta//60):02d}:{int(eta%60):02d}"
    else:
        eta_str = "--:--"
    
    # 生成进度条
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    
    # 格式化输出
    sys.stdout.write(f'\r进度: [{bar}] {percent:.1f}% ({current}/{total}) '
                    f'用时: {int(elapsed_time//60):02d}:{int(elapsed_time%60):02d} '
                    f'预估剩余: {eta_str}')
    sys.stdout.flush()

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

def brute_force_des_numeric(ciphertext, target_plaintext=None, min_length=1, max_length=6, show_progress=True):
    """
    数字密钥暴力破解（适用于简单数字密钥）
    """
    des = DESCrypto()
    attempts = 0
    start_time = time.time()
    
    print(f"开始DES数字密钥暴力破解 (长度范围: {min_length}-{max_length})")
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    
    # 计算总组合数
    total_combinations = 0
    for length in range(min_length, max_length + 1):
        total_combinations += 10 ** length
    print(f"总组合数: {total_combinations:,}")
    print("-" * 60)
    
    # 尝试不同长度的数字密钥
    for length in range(min_length, max_length + 1):
        print(f"\n尝试长度为 {length} 的数字密钥...")
        
        for num in range(10**length):
            attempts += 1
            
            # 生成密钥（补齐到8字节）
            key_str = str(num).zfill(length)
            key = (key_str * (8 // len(key_str) + 1))[:8].encode()
            
            try:
                decrypted = des.decrypt_ecb(ciphertext, key)
                result = decrypted.decode('utf-8', errors='ignore')
                
                # 如果指定了目标明文，检查是否匹配
                if target_plaintext and target_plaintext.lower() in result.lower():
                    elapsed = time.time() - start_time
                    print(f"\n*** 找到密钥! ***")
                    print(f"密钥: {key_str} -> {key}")
                    print(f"解密结果: {result}")
                    print(f"尝试次数: {attempts}")
                    print(f"耗时: {elapsed:.2f}秒")
                    return key, result
                
                # 显示可读的解密结果
                if all(c.isprintable() for c in result):
                    print(f"密钥 {key_str}: {result[:50]}")
                    
            except Exception:
                continue
            
            # 显示进度条
            if show_progress and attempts % 1000 == 0:
                print_progress_bar(attempts, total_combinations, start_time)
            elif attempts % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"\n已尝试 {attempts} 个密钥... ({elapsed:.1f}秒)")
    
    elapsed = time.time() - start_time
    if show_progress:
        print_progress_bar(attempts, total_combinations, start_time)
    print(f"\n\n暴力破解完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None

def brute_force_des_alpha(ciphertext, target_plaintext=None, min_length=1, max_length=4, show_progress=True):
    """
    字母密钥暴力破解（适用于简单字母密钥）
    """
    des = DESCrypto()
    attempts = 0
    start_time = time.time()
    charset = string.ascii_lowercase
    
    print(f"开始DES字母密钥暴力破解 (最大长度: {max_length})")
    print(f"字符集: {charset}")
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    print("-" * 60)
    
    for length in range(1, max_length + 1):
        print(f"尝试长度为 {length} 的字母密钥...")
        
        for key_tuple in itertools.product(charset, repeat=length):
            attempts += 1
            key_str = ''.join(key_tuple)
            
            # 补齐到8字节
            key = (key_str * (8 // len(key_str) + 1))[:8].encode()
            
            try:
                decrypted = des.decrypt_ecb(ciphertext, key)
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
                
            if attempts % 1000 == 0:
                elapsed = time.time() - start_time
                print(f"已尝试 {attempts} 个密钥... ({elapsed:.1f}秒)")
                
            # 移除尝试次数限制，允许无限次尝试
            # if attempts > 50000:
            #     print("达到最大尝试次数限制")
            #     break
    
    elapsed = time.time() - start_time
    print(f"\n暴力破解完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None

def brute_force_des_alphanumeric(ciphertext, target_plaintext=None, max_length=4):
    """
    DES字母数字混合密钥暴力破解
    """
    des = DESCrypto()
    attempts = 0
    start_time = time.time()
    charset = string.ascii_lowercase + string.digits
    
    print(f"开始DES字母数字混合密钥暴力破解 (最大长度: {max_length})")
    print(f"字符集: {charset}")
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    print("-" * 60)
    
    for length in range(1, max_length + 1):
        print(f"尝试长度为 {length} 的字母数字混合密钥...")
        
        for key_tuple in itertools.product(charset, repeat=length):
            attempts += 1
            key_str = ''.join(key_tuple)
            
            # 补齐到8字节
            key = (key_str * (8 // len(key_str) + 1))[:8].encode()
            
            try:
                decrypted = des.decrypt_ecb(ciphertext, key)
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
                
            if attempts % 5000 == 0:
                elapsed = time.time() - start_time
                print(f"已尝试 {attempts} 个密钥... ({elapsed:.1f}秒)")
                
            # 移除尝试次数限制，允许无限次尝试
            # if attempts > 100000:
            #     print("达到最大尝试次数限制")
            #     break
    
    elapsed = time.time() - start_time
    print(f"\n暴力破解完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None

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

def brute_force_des_custom_charset(ciphertext, charset_choice, target_plaintext=None, min_length=1, max_length=4, custom_start=None, custom_end=None):
    """
    DES自定义字符集暴力破解
    """
    des = DESCrypto()
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
    
    print(f"开始DES自定义字符集暴力破解 (长度范围: {min_length}-{max_length})")
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
            key_str = ''.join(key_tuple)
            
            # 补齐到8字节
            key = (key_str * (8 // len(key_str) + 1))[:8].encode()
            
            try:
                decrypted = des.decrypt_ecb(ciphertext, key)
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

def main():
    print("=" * 60)
    print("DES加密解密工具")
    print("=" * 60)
    
    des = DESCrypto()
    
    while True:
        print("\n选择操作:")
        print("1. 生成随机密钥")
        print("2. ECB模式加密")
        print("3. ECB模式解密")
        print("4. CBC模式加密")
        print("5. CBC模式解密")
        print("6. ECB模式加密（无填充）")
        print("7. ECB模式解密（无填充）")
        print("8. CBC模式加密（无填充）")
        print("9. CBC模式解密（无填充）")
        print("10. 数字密钥暴力破解")
        print("11. 字母密钥暴力破解")
        print("12. 字母数字混合密钥暴力破解")
        print("13. 自定义字符集暴力破解")
        print("14. 退出")
        
        choice = input("\n请选择 (1-14): ").strip()
        
        if choice == '1':
            key = des.generate_key()
            print(f"随机密钥: {binascii.hexlify(key).decode()}")
            
        elif choice == '2':
            try:
                # 尝试导入通用函数
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                # 获取明文输入
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                # 获取密钥输入（DES需要8字节密钥）
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                # 执行加密
                ciphertext = des.encrypt_ecb(plaintext_data, key)
                
                # 显示结果
                display_result(ciphertext, "ciphertext")
                
            except ImportError:
                # 如果无法导入通用函数，使用原来的方式
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = des.encrypt_ecb(plaintext, key)
                    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ 加密失败: {e}")
            except Exception as e:
                print(f"❌ DES ECB加密过程中发生错误: {e}")
                
        elif choice == '3':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                # 获取密文输入
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                # 获取密钥输入
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                # 执行解密
                plaintext = des.decrypt_ecb(ciphertext_data, key)
                
                # 显示结果
                display_result(plaintext, "plaintext")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = des.decrypt_ecb(ciphertext, key)
                    print(f"明文: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ 解密失败: {e}")
            except Exception as e:
                print(f"❌ DES ECB解密过程中发生错误: {e}")
                
        elif choice == '4':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                ciphertext = des.encrypt_cbc(plaintext_data, key)
                display_result(ciphertext, "ciphertext")
                print("注意：密文包含随机生成的IV（前8字节）")
                
            except ImportError:
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = des.encrypt_cbc(plaintext, key)
                    print(f"密文(包含IV): {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ CBC加密失败: {e}")
            except Exception as e:
                print(f"❌ DES CBC加密过程中发生错误: {e}")
                
        elif choice == '5':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文（包含IV）", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                plaintext = des.decrypt_cbc(ciphertext_data, key)
                display_result(plaintext, "plaintext")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制，包含IV): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = des.decrypt_cbc(ciphertext, key)
                    print(f"明文: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ CBC解密失败: {e}")
            except Exception as e:
                print(f"❌ DES CBC解密过程中发生错误: {e}")
                
        elif choice == '6':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                ciphertext = des.encrypt_ecb(plaintext_data, key, use_padding=False)
                display_result(ciphertext, "ciphertext")
                print("注意：使用无填充模式")
                
            except ImportError:
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = des.encrypt_ecb(plaintext, key, use_padding=False)
                    print(f"密文(无填充): {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ 加密失败: {e}")
            except Exception as e:
                print(f"❌ DES ECB加密（无填充）过程中发生错误: {e}")
                
        elif choice == '7':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                plaintext = des.decrypt_ecb(ciphertext_data, key, use_padding=False)
                display_result(plaintext, "plaintext")
                print("注意：使用无填充模式")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = des.decrypt_ecb(ciphertext, key, use_padding=False)
                    print(f"明文(无填充): {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ 解密失败: {e}")
            except Exception as e:
                print(f"❌ DES ECB解密（无填充）过程中发生错误: {e}")
                
        elif choice == '8':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                ciphertext = des.encrypt_cbc(plaintext_data, key, use_padding=False)
                display_result(ciphertext, "ciphertext")
                print("注意：密文包含随机生成的IV（前8字节），使用无填充模式")
                
            except ImportError:
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = des.encrypt_cbc(plaintext, key, use_padding=False)
                    print(f"密文(包含IV，无填充): {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ CBC加密失败: {e}")
            except Exception as e:
                print(f"❌ DES CBC加密（无填充）过程中发生错误: {e}")
                
        elif choice == '9':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文（包含IV）", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                key = get_key_input("请输入DES密钥", 8)
                if key is None:
                    continue
                
                plaintext = des.decrypt_cbc(ciphertext_data, key, use_padding=False)
                display_result(plaintext, "plaintext")
                print("注意：使用无填充模式")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制，包含IV): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = des.decrypt_cbc(ciphertext, key, use_padding=False)
                    print(f"明文(无填充): {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ CBC解密失败: {e}")
            except Exception as e:
                print(f"❌ DES CBC解密（无填充）过程中发生错误: {e}")
                
        elif choice == '10':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            target = input("请输入目标明文(可选): ").strip()
            max_len = int(input("请输入最大密钥长度(默认6): ") or "6")
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_des_numeric(ciphertext, target, max_len)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '11':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            target = input("请输入目标明文(可选): ").strip()
            max_len = int(input("请输入最大密钥长度(默认4): ") or "4")
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_des_alpha(ciphertext, target, max_len)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '12':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            target = input("请输入目标明文(可选): ").strip()
            max_len = int(input("请输入最大密钥长度(默认4): ") or "4")
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_des_alphanumeric(ciphertext, target, max_len)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '13':
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
                brute_force_des_custom_charset(ciphertext, charset_choice, target, min_len, max_len, custom_start, custom_end)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '14':
            print("退出程序")
            break
            
        else:
            print("无效选择，请重新输入")

if __name__ == "__main__":
    # 示例用法
    print("DES加密示例:")
    
    des = DESCrypto()
    
    # 生成密钥
    key = des.generate_key()
    plaintext = "Hello DES!".encode('utf-8')
    
    print(f"明文: {plaintext.decode()}")
    print(f"密钥: {binascii.hexlify(key).decode()}")
    
    # ECB加密
    ciphertext_ecb = des.encrypt_ecb(plaintext, key)
    print(f"ECB密文: {binascii.hexlify(ciphertext_ecb).decode()}")
    
    # ECB解密
    decrypted_ecb = des.decrypt_ecb(ciphertext_ecb, key)
    print(f"ECB解密: {decrypted_ecb.decode()}")
    
    print("\n" + "="*60)
    main()