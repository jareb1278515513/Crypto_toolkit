#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES加密、解密和爆破工具
支持AES-128, AES-192, AES-256
支持ECB, CBC, CTR模式
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import itertools
import string
import time
import hashlib
import sys

class AESCrypto:
    def __init__(self, key_size=16):
        """
        初始化AES加密器
        Args:
            key_size: 密钥长度 16(AES-128), 24(AES-192), 32(AES-256)
        """
        if key_size not in [16, 24, 32]:
            raise ValueError("密钥长度必须是16, 24或32字节")
        self.key_size = key_size
        self.block_size = AES.block_size  # 16字节
        
    def generate_key(self):
        """生成随机AES密钥"""
        return get_random_bytes(self.key_size)
    
    def derive_key_from_password(self, password):
        """从密码派生密钥"""
        return hashlib.sha256(password.encode()).digest()[:self.key_size]
    
    def encrypt_ecb(self, plaintext, key, use_padding=True):
        """AES ECB模式加密"""
        if len(key) != self.key_size:
            raise ValueError(f"密钥长度必须是{self.key_size}字节")
        
        if use_padding:
            cipher = AES.new(key, AES.MODE_ECB)
            padded_data = pad(plaintext, self.block_size)
            ciphertext = cipher.encrypt(padded_data)
        else:
            # 不使用填充时，明文长度必须是块大小的倍数
            if len(plaintext) % self.block_size != 0:
                raise ValueError(f"不使用填充时，明文长度必须是{self.block_size}字节的倍数")
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(plaintext)
        return ciphertext
    
    def decrypt_ecb(self, ciphertext, key, use_padding=True):
        """AES ECB模式解密"""
        if len(key) != self.key_size:
            raise ValueError(f"密钥长度必须是{self.key_size}字节")
        
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(ciphertext)
        
        if use_padding:
            plaintext = unpad(decrypted_data, self.block_size)
        else:
            plaintext = decrypted_data
        return plaintext
    
    def encrypt_cbc(self, plaintext, key, iv=None, use_padding=True):
        """AES CBC模式加密"""
        if len(key) != self.key_size:
            raise ValueError(f"密钥长度必须是{self.key_size}字节")
        
        if iv is None:
            iv = get_random_bytes(16)
        elif len(iv) != 16:
            raise ValueError("IV必须是16字节")
        
        if use_padding:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(plaintext, self.block_size)
            ciphertext = cipher.encrypt(padded_data)
        else:
            # 不使用填充时，明文长度必须是块大小的倍数
            if len(plaintext) % self.block_size != 0:
                raise ValueError(f"不使用填充时，明文长度必须是{self.block_size}字节的倍数")
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(plaintext)
        return iv + ciphertext
    
    def decrypt_cbc(self, ciphertext, key, use_padding=True):
        """AES CBC模式解密"""
        if len(key) != self.key_size:
            raise ValueError(f"密钥长度必须是{self.key_size}字节")
        
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(actual_ciphertext)
        
        if use_padding:
            plaintext = unpad(decrypted_data, self.block_size)
        else:
            plaintext = decrypted_data
        return plaintext
    
    def encrypt_ctr(self, plaintext, key, nonce=None):
        """AES CTR模式加密"""
        if len(key) != self.key_size:
            raise ValueError(f"密钥长度必须是{self.key_size}字节")
        
        if nonce is None:
            nonce = get_random_bytes(8)
        elif len(nonce) != 8:
            raise ValueError("Nonce必须是8字节")
        
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        return nonce + ciphertext
    
    def decrypt_ctr(self, ciphertext, key):
        """AES CTR模式解密"""
        if len(key) != self.key_size:
            raise ValueError(f"密钥长度必须是{self.key_size}字节")
        
        nonce = ciphertext[:8]
        actual_ciphertext = ciphertext[8:]
        
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(actual_ciphertext)
        return plaintext

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
            if max_len > 10:
                print("⚠️  警告：长度超过10可能需要很长时间")
                confirm = input("确定要继续吗? (y/n): ")
                if confirm.lower() != 'y':
                    continue
                    
            return min_len, max_len
        except ValueError:
            print("❌ 请输入有效的数字")

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

def brute_force_aes_password(ciphertext, target_plaintext=None, min_length=1, max_length=6,
                           key_size=16, mode='ECB', charset_choice='2', custom_start=None, custom_end=None, show_progress=True):
    """
    基于密码的AES暴力破解
    """
    aes = AESCrypto(key_size)
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
    
    print(f"开始AES-{key_size*8}密码暴力破解 (长度范围: {min_length}-{max_length})")
    print(f"模式: {mode}")
    print(f"选择的字符集: {charset_names.get(charset_choice, '未知')} ({charset})")
    print(f"密文: {binascii.hexlify(ciphertext).decode()}")
    
    # 计算总组合数
    total_combinations = calculate_total_combinations(charset, min_length, max_length)
    print(f"总组合数: {total_combinations:,}")
    print("-" * 80)
    
    for length in range(min_length, max_length + 1):
        print(f"\n尝试长度为 {length} 的密码...")
        
        for password_tuple in itertools.product(charset, repeat=length):
            attempts += 1
            password = ''.join(password_tuple)
            
            # 从密码派生密钥
            key = aes.derive_key_from_password(password)
            
            try:
                if mode.upper() == 'ECB':
                    decrypted = aes.decrypt_ecb(ciphertext, key)
                elif mode.upper() == 'CBC':
                    decrypted = aes.decrypt_cbc(ciphertext, key)
                elif mode.upper() == 'CTR':
                    decrypted = aes.decrypt_ctr(ciphertext, key)
                else:
                    print(f"不支持的模式: {mode}")
                    return None, None
                
                result = decrypted.decode('utf-8', errors='ignore')
                
                if target_plaintext and target_plaintext.lower() in result.lower():
                    elapsed = time.time() - start_time
                    print(f"\n*** 找到密码! ***")
                    print(f"密码: {password}")
                    print(f"派生密钥: {binascii.hexlify(key).decode()}")
                    print(f"解密结果: {result}")
                    print(f"尝试次数: {attempts}")
                    print(f"耗时: {elapsed:.2f}秒")
                    return password, result
                
                if all(c.isprintable() for c in result):
                    print(f"密码 {password}: {result[:50]}")
                    
            except Exception:
                continue
                
            # 显示进度条
            if show_progress and attempts % 100 == 0:
                print_progress_bar(attempts, total_combinations, start_time)
            elif attempts % 1000 == 0:
                elapsed = time.time() - start_time
                print(f"\n已尝试 {attempts} 个密码... ({elapsed:.1f}秒)")
                
            # 移除尝试次数限制，允许无限次尝试
            # if attempts > 100000:
            #     print("达到最大尝试次数限制")
            #     break
    
    elapsed = time.time() - start_time
    if show_progress:
        print_progress_bar(attempts, total_combinations, start_time)
    print(f"\n\n暴力破解完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None

def dictionary_attack_aes(ciphertext, wordlist_file, key_size=16, mode='ECB'):
    """
    基于字典的AES攻击
    """
    aes = AESCrypto(key_size)
    attempts = 0
    start_time = time.time()
    
    print(f"开始AES-{key_size*8}字典攻击")
    print(f"模式: {mode}")
    print(f"字典文件: {wordlist_file}")
    print("-" * 60)
    
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                attempts += 1
                password = line.strip()
                
                if not password:
                    continue
                
                # 从密码派生密钥
                key = aes.derive_key_from_password(password)
                
                try:
                    if mode.upper() == 'ECB':
                        decrypted = aes.decrypt_ecb(ciphertext, key)
                    elif mode.upper() == 'CBC':
                        decrypted = aes.decrypt_cbc(ciphertext, key)
                    elif mode.upper() == 'CTR':
                        decrypted = aes.decrypt_ctr(ciphertext, key)
                    else:
                        print(f"不支持的模式: {mode}")
                        return None, None
                    
                    result = decrypted.decode('utf-8', errors='ignore')
                    
                    # 检查是否为可读文本
                    if all(c.isprintable() or c.isspace() for c in result):
                        elapsed = time.time() - start_time
                        print(f"\n*** 可能找到密码! ***")
                        print(f"密码: {password}")
                        print(f"派生密钥: {binascii.hexlify(key).decode()}")
                        print(f"解密结果: {result}")
                        print(f"尝试次数: {attempts}")
                        print(f"耗时: {elapsed:.2f}秒")
                        
                        confirm = input("是否继续寻找其他可能的密码? (y/n): ")
                        if confirm.lower() != 'y':
                            return password, result
                        
                except Exception:
                    continue
                    
                if attempts % 1000 == 0:
                    elapsed = time.time() - start_time
                    print(f"已尝试 {attempts} 个密码... ({elapsed:.1f}秒)")
                    
    except FileNotFoundError:
        print(f"字典文件 {wordlist_file} 不存在")
        return None, None
    
    elapsed = time.time() - start_time
    print(f"\n字典攻击完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None

def main():
    print("=" * 60)
    print("AES加密解密工具")
    print("=" * 60)
    
    while True:
        print("\n选择AES密钥长度:")
        print("1. AES-128 (16字节密钥)")
        print("2. AES-192 (24字节密钥)")
        print("3. AES-256 (32字节密钥)")
        
        key_choice = input("请选择 (1-3): ").strip()
        
        if key_choice == '1':
            key_size = 16
        elif key_choice == '2':
            key_size = 24
        elif key_choice == '3':
            key_size = 32
        else:
            print("无效选择")
            continue
            
        aes = AESCrypto(key_size)
        break
    
    while True:
        print(f"\n当前设置: AES-{key_size*8}")
        print("选择操作:")
        print("1. 生成随机密钥")
        print("2. 从密码派生密钥")
        print("3. ECB模式加密")
        print("4. ECB模式解密")
        print("5. CBC模式加密")
        print("6. CBC模式解密")
        print("7. CTR模式加密")
        print("8. CTR模式解密")
        print("9. ECB模式加密（无填充）")
        print("10. ECB模式解密（无填充）")
        print("11. CBC模式加密（无填充）")
        print("12. CBC模式解密（无填充）")
        print("13. 密码暴力破解")
        print("14. 字典攻击")
        print("15. 更换密钥长度")
        print("16. 退出")
        
        choice = input("\n请选择 (1-16): ").strip()
        
        if choice == '1':
            key = aes.generate_key()
            print(f"随机密钥: {binascii.hexlify(key).decode()}")
            
        elif choice == '2':
            password = input("请输入密码: ").strip()
            key = aes.derive_key_from_password(password)
            print(f"派生密钥: {binascii.hexlify(key).decode()}")
            
        elif choice == '3':
            try:
                # 导入通用函数（如果可用）
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                # 获取明文输入
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                # 获取密钥输入
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                # 执行加密
                ciphertext = aes.encrypt_ecb(plaintext_data, key)
                
                # 显示结果
                display_result(ciphertext, "ciphertext")
                
            except ImportError:
                # 如果无法导入通用函数，使用原来的方式
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = aes.encrypt_ecb(plaintext, key)
                    print(f"ECB密文: {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ 加密失败: {e}")
            except Exception as e:
                print(f"❌ ECB加密过程中发生错误: {e}")
                
        elif choice == '4':
            try:
                # 导入通用函数（如果可用）
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                # 获取密文输入
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                # 获取密钥输入
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                # 执行解密
                plaintext = aes.decrypt_ecb(ciphertext_data, key)
                
                # 显示结果
                display_result(plaintext, "plaintext")
                
            except ImportError:
                # 如果无法导入通用函数，使用原来的方式
                ciphertext_hex = input("请输入密文(16进制): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = aes.decrypt_ecb(ciphertext, key)
                    print(f"明文: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ 解密失败: {e}")
            except Exception as e:
                print(f"❌ ECB解密过程中发生错误: {e}")
                
        elif choice == '5':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                ciphertext = aes.encrypt_cbc(plaintext_data, key)
                display_result(ciphertext, "ciphertext")
                print("注意：密文包含随机生成的IV（前16字节）")
                
            except ImportError:
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = aes.encrypt_cbc(plaintext, key)
                    print(f"CBC密文(包含IV): {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ CBC加密失败: {e}")
            except Exception as e:
                print(f"❌ CBC加密过程中发生错误: {e}")
                
        elif choice == '6':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文（包含IV）", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                plaintext = aes.decrypt_cbc(ciphertext_data, key)
                display_result(plaintext, "plaintext")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制，包含IV): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = aes.decrypt_cbc(ciphertext, key)
                    print(f"明文: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ CBC解密失败: {e}")
            except Exception as e:
                print(f"❌ CBC解密过程中发生错误: {e}")
                
        elif choice == '7':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                ciphertext = aes.encrypt_ctr(plaintext_data, key)
                display_result(ciphertext, "ciphertext")
                print("注意：密文包含随机生成的Nonce（前8字节）")
                
            except ImportError:
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = aes.encrypt_ctr(plaintext, key)
                    print(f"CTR密文(包含Nonce): {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ CTR加密失败: {e}")
            except Exception as e:
                print(f"❌ CTR加密过程中发生错误: {e}")
                
        elif choice == '8':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文（包含Nonce）", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                plaintext = aes.decrypt_ctr(ciphertext_data, key)
                display_result(plaintext, "plaintext")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制，包含Nonce): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = aes.decrypt_ctr(ciphertext, key)
                    print(f"明文: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ CTR解密失败: {e}")
            except Exception as e:
                print(f"❌ CTR解密过程中发生错误: {e}")
                
        elif choice == '9':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                ciphertext = aes.encrypt_ecb(plaintext_data, key, use_padding=False)
                display_result(ciphertext, "ciphertext")
                print("注意：使用无填充模式")
                
            except ImportError:
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = aes.encrypt_ecb(plaintext, key, use_padding=False)
                    print(f"ECB密文(无填充): {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ 加密失败: {e}")
            except Exception as e:
                print(f"❌ ECB加密（无填充）过程中发生错误: {e}")
                
        elif choice == '10':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                plaintext = aes.decrypt_ecb(ciphertext_data, key, use_padding=False)
                display_result(plaintext, "plaintext")
                print("注意：使用无填充模式")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = aes.decrypt_ecb(ciphertext, key, use_padding=False)
                    print(f"明文(无填充): {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ 解密失败: {e}")
            except Exception as e:
                print(f"❌ ECB解密（无填充）过程中发生错误: {e}")
                
        elif choice == '11':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                plaintext_data, _ = get_input_with_format_choice("请输入要加密的明文", "plaintext")
                if plaintext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                ciphertext = aes.encrypt_cbc(plaintext_data, key, use_padding=False)
                display_result(ciphertext, "ciphertext")
                print("注意：密文包含随机生成的IV（前16字节），使用无填充模式")
                
            except ImportError:
                plaintext = input("请输入明文: ").encode('utf-8')
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    key = binascii.unhexlify(key_hex)
                    ciphertext = aes.encrypt_cbc(plaintext, key, use_padding=False)
                    print(f"CBC密文(包含IV，无填充): {binascii.hexlify(ciphertext).decode()}")
                except Exception as e:
                    print(f"❌ CBC加密失败: {e}")
            except Exception as e:
                print(f"❌ CBC加密（无填充）过程中发生错误: {e}")
                
        elif choice == '12':
            try:
                from crypto_toolkit import get_input_with_format_choice, get_key_input, display_result
                
                ciphertext_data, _ = get_input_with_format_choice("请输入要解密的密文（包含IV）", "ciphertext")
                if ciphertext_data is None:
                    continue
                
                key = get_key_input("请输入AES密钥", key_size)
                if key is None:
                    continue
                
                plaintext = aes.decrypt_cbc(ciphertext_data, key, use_padding=False)
                display_result(plaintext, "plaintext")
                print("注意：使用无填充模式")
                
            except ImportError:
                ciphertext_hex = input("请输入密文(16进制，包含IV): ").strip()
                key_hex = input("请输入密钥(16进制): ").strip()
                try:
                    ciphertext = binascii.unhexlify(ciphertext_hex)
                    key = binascii.unhexlify(key_hex)
                    plaintext = aes.decrypt_cbc(ciphertext, key, use_padding=False)
                    print(f"明文(无填充): {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"❌ CBC解密失败: {e}")
            except Exception as e:
                print(f"❌ CBC解密（无填充）过程中发生错误: {e}")
                
        elif choice == '13':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            mode = input("请输入模式(ECB/CBC/CTR): ").strip().upper()
            charset_result = show_charset_menu()
            if len(charset_result) == 3:
                charset_choice, custom_start, custom_end = charset_result
            else:
                charset_choice = charset_result
                custom_start = custom_end = None
                
            target = input("请输入目标明文(可选): ").strip()
            min_len, max_len = get_length_range()
            
            print("\n进度显示选项:")
            print("1. 显示详细进度条")
            print("2. 显示简单进度信息")
            progress_choice = input("请选择进度显示方式 (1-2, 默认1): ").strip() or "1"
            show_progress = progress_choice == "1"
            
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                target = target if target else None
                brute_force_aes_password(ciphertext, target, min_len, max_len, key_size, mode, charset_choice, custom_start, custom_end, show_progress)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '14':
            ciphertext_hex = input("请输入密文(16进制): ").strip()
            mode = input("请输入模式(ECB/CBC/CTR): ").strip().upper()
            wordlist = input("请输入字典文件路径: ").strip()
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                dictionary_attack_aes(ciphertext, wordlist, key_size, mode)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '15':
            break
            
        elif choice == '16':
            print("退出程序")
            return
            
        else:
            print("无效选择，请重新输入")

if __name__ == "__main__":
    # 示例用法
    print("AES加密示例:")
    
    aes = AESCrypto(16)  # AES-128
    
    # 生成密钥
    key = aes.generate_key()
    plaintext = "Hello AES!".encode('utf-8')
    
    print(f"明文: {plaintext.decode()}")
    print(f"密钥: {binascii.hexlify(key).decode()}")
    
    # ECB加密
    ciphertext_ecb = aes.encrypt_ecb(plaintext, key)
    print(f"ECB密文: {binascii.hexlify(ciphertext_ecb).decode()}")
    
    # ECB解密
    decrypted_ecb = aes.decrypt_ecb(ciphertext_ecb, key)
    print(f"ECB解密: {decrypted_ecb.decode()}")
    
    print("\n" + "="*60)
    main()