#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
哈希算法工具：SHA-1、SHA256、MD5
包含哈希计算、验证和爆破功能
"""

import hashlib
import itertools
import string
import time
import binascii

class HashCrypto:
    def __init__(self):
        self.algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
    
    def hash_text(self, text, algorithm='md5'):
        """
        计算文本的哈希值
        Args:
            text: 待哈希的文本
            algorithm: 哈希算法 (md5, sha1, sha256等)
        """
        if algorithm.lower() not in self.algorithms:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        if isinstance(text, str):
            text = text.encode('utf-8')
        
        hash_obj = self.algorithms[algorithm.lower()]()
        hash_obj.update(text)
        return hash_obj.hexdigest()
    
    def hash_file(self, filename, algorithm='md5'):
        """
        计算文件的哈希值
        """
        if algorithm.lower() not in self.algorithms:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        hash_obj = self.algorithms[algorithm.lower()]()
        
        try:
            with open(filename, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except FileNotFoundError:
            raise FileNotFoundError(f"文件 {filename} 不存在")
    
    def verify_hash(self, text, target_hash, algorithm='md5'):
        """
        验证文本的哈希值
        """
        calculated_hash = self.hash_text(text, algorithm)
        return calculated_hash.lower() == target_hash.lower()

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
            max_len = int(input("请输入最大长度 (默认6): ") or "6")
            
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

def brute_force_hash_custom_charset(target_hash, charset_choice, algorithm='md5', min_length=1, max_length=6, custom_start=None, custom_end=None):
    """
    自定义字符集哈希暴力破解
    """
    hasher = HashCrypto()
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
    
    print(f"开始{algorithm.upper()}自定义字符集密码暴力破解 (长度范围: {min_length}-{max_length})")
    print(f"选择的字符集: {charset_names.get(charset_choice, '未知')} ({charset})")
    print(f"目标哈希: {target_hash}")
    print("-" * 80)
    
    # 根据字符集大小调整最大尝试次数
    max_attempts = {
        '1': 500000,   # 大写字母 (26)
        '2': 500000,   # 小写字母 (26)
        '3': 1000000,  # 数字 (10)
        '4': 800000,   # 数字+大写 (36)
        '5': 800000,   # 数字+小写 (36)
        '6': 600000,   # 大写+小写 (52)
        '7': 500000,   # 全部 (62)
        '8': 400000    # 自定义
    }.get(charset_choice, 500000)
    
    for length in range(min_length, max_length + 1):
        print(f"尝试长度为 {length} 的密码...")
        
        for password_tuple in itertools.product(charset, repeat=length):
            attempts += 1
            password = ''.join(password_tuple)
            
            calculated_hash = hasher.hash_text(password, algorithm)
            
            if calculated_hash.lower() == target_hash.lower():
                elapsed = time.time() - start_time
                print(f"\n*** 找到密码! ***")
                print(f"密码: {password}")
                print(f"哈希: {calculated_hash}")
                print(f"尝试次数: {attempts}")
                print(f"耗时: {elapsed:.2f}秒")
                return password
            
            if attempts % 50000 == 0:
                elapsed = time.time() - start_time
                print(f"已尝试 {attempts} 个密码... ({elapsed:.1f}秒)")
                
            # 移除尝试次数限制，允许无限次尝试
            # if attempts > max_attempts:
            #     print(f"达到最大尝试次数限制 ({max_attempts})")
            #     break
        
        # 移除长度循环的尝试次数限制
        # if attempts > max_attempts:
        #     break
    
    elapsed = time.time() - start_time
    print(f"\n暴力破解完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None

# 保留原有函数作为兼容性接口
def brute_force_hash_numeric(target_hash, algorithm='md5', min_length=1, max_length=8):
    """数字密码哈希暴力破解（兼容性接口）"""
    return brute_force_hash_custom_charset(target_hash, '3', algorithm, min_length, max_length)

def brute_force_hash_alpha(target_hash, algorithm='md5', min_length=1, max_length=6):
    """字母密码哈希暴力破解（兼容性接口）"""
    return brute_force_hash_custom_charset(target_hash, '2', algorithm, min_length, max_length)

def brute_force_hash_alphanumeric(target_hash, algorithm='md5', min_length=1, max_length=5):
    """字母数字混合密码哈希暴力破解（兼容性接口）"""
    return brute_force_hash_custom_charset(target_hash, '5', algorithm, min_length, max_length)

def dictionary_attack_hash(target_hash, wordlist_file, algorithm='md5'):
    """
    基于字典的哈希攻击
    """
    hasher = HashCrypto()
    attempts = 0
    start_time = time.time()
    
    print(f"开始{algorithm.upper()}字典攻击")
    print(f"字典文件: {wordlist_file}")
    print(f"目标哈希: {target_hash}")
    print("-" * 60)
    
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                attempts += 1
                password = line.strip()
                
                if not password:
                    continue
                
                calculated_hash = hasher.hash_text(password, algorithm)
                
                if calculated_hash.lower() == target_hash.lower():
                    elapsed = time.time() - start_time
                    print(f"\n*** 找到密码! ***")
                    print(f"密码: {password}")
                    print(f"哈希: {calculated_hash}")
                    print(f"尝试次数: {attempts}")
                    print(f"耗时: {elapsed:.2f}秒")
                    return password
                
                if attempts % 10000 == 0:
                    elapsed = time.time() - start_time
                    print(f"已尝试 {attempts} 个密码... ({elapsed:.1f}秒)")
                    
    except FileNotFoundError:
        print(f"字典文件 {wordlist_file} 不存在")
        return None
    
    elapsed = time.time() - start_time
    print(f"\n字典攻击完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None

def rainbow_table_attack(target_hash, algorithm='md5', charset=None, max_length=6):
    """
    简单的彩虹表攻击模拟（预计算常见密码哈希）
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    
    hasher = HashCrypto()
    
    print(f"生成{algorithm.upper()}彩虹表...")
    print(f"字符集: {charset}")
    print(f"最大长度: {max_length}")
    print("-" * 60)
    
    # 生成常见密码
    common_passwords = [
        'password', '123456', '123456789', 'qwerty', 'abc123', 
        'password123', 'admin', 'root', 'user', 'guest',
        '12345', '1234', '12345678', 'welcome', 'login',
        'pass', 'test', 'demo', 'temp', 'secret'
    ]
    
    # 检查常见密码
    print("检查常见密码...")
    for password in common_passwords:
        calculated_hash = hasher.hash_text(password, algorithm)
        if calculated_hash.lower() == target_hash.lower():
            print(f"\n*** 在常见密码中找到! ***")
            print(f"密码: {password}")
            print(f"哈希: {calculated_hash}")
            return password
    
    # 生成简单组合
    print("生成简单密码组合...")
    rainbow_table = {}
    count = 0
    
    for length in range(1, min(max_length + 1, 5)):  # 限制长度避免内存过大
        for password_tuple in itertools.product(charset[:10], repeat=length):  # 限制字符集
            count += 1
            password = ''.join(password_tuple)
            calculated_hash = hasher.hash_text(password, algorithm)
            rainbow_table[calculated_hash.lower()] = password
            
            if count % 10000 == 0:
                print(f"已生成 {count} 条记录...")
                
            if count > 100000:  # 限制表大小
                break
        
        if count > 100000:
            break
    
    print(f"彩虹表生成完成，共 {len(rainbow_table)} 条记录")
    
    # 查找目标哈希
    if target_hash.lower() in rainbow_table:
        password = rainbow_table[target_hash.lower()]
        print(f"\n*** 在彩虹表中找到! ***")
        print(f"密码: {password}")
        print(f"哈希: {target_hash}")
        return password
    else:
        print("在彩虹表中未找到匹配项")
        return None

def hash_collision_demo():
    """
    哈希碰撞演示（寻找两个不同输入产生相同哈希）
    """
    hasher = HashCrypto()
    
    print("哈希碰撞演示")
    print("寻找两个不同的输入产生相同的MD5哈希...")
    print("-" * 60)
    
    hash_dict = {}
    attempts = 0
    
    # 生成随机字符串并计算哈希
    import random
    charset = string.ascii_letters + string.digits
    
    while attempts < 1000000:  # 限制尝试次数
        attempts += 1
        
        # 生成随机字符串
        length = random.randint(5, 10)
        text = ''.join(random.choices(charset, k=length))
        
        # 计算MD5（取前16位模拟碰撞）
        full_hash = hasher.hash_text(text, 'md5')
        short_hash = full_hash[:8]  # 使用短哈希增加碰撞概率
        
        if short_hash in hash_dict:
            print(f"\n*** 找到碰撞! ***")
            print(f"文本1: {hash_dict[short_hash]}")
            print(f"文本2: {text}")
            print(f"短哈希: {short_hash}")
            print(f"尝试次数: {attempts}")
            return hash_dict[short_hash], text
        
        hash_dict[short_hash] = text
        
        if attempts % 10000 == 0:
            print(f"已尝试 {attempts} 次...")
    
    print("未找到碰撞")
    return None, None

def main():
    print("=" * 60)
    print("哈希算法工具 (MD5, SHA-1, SHA256)")
    print("=" * 60)
    
    hasher = HashCrypto()
    
    while True:
        print("\n选择操作:")
        print("1. 计算文本哈希")
        print("2. 计算文件哈希")
        print("3. 验证哈希")
        print("4. 自定义字符集暴力破解")
        print("5. 字典攻击")
        print("6. 彩虹表攻击")
        print("7. 哈希碰撞演示")
        print("8. 退出")
        
        choice = input("\n请选择 (1-8): ").strip()
        
        if choice == '1':
            try:
                from crypto_toolkit import get_input_with_format_choice, safe_input
                
                # 获取文本输入
                text_data, format_type = get_input_with_format_choice("请输入要计算哈希的文本", "data")
                if text_data is None:
                    continue
                
                # 获取算法选择
                algorithm = safe_input("请选择算法 (md5/sha1/sha256): ", "string").strip().lower()
                if algorithm not in hasher.algorithms:
                    print("❌ 不支持的算法，请选择: md5, sha1, sha256")
                    continue
                
                # 计算哈希
                if format_type == 'string':
                    hash_value = hasher.hash_text(text_data.decode('utf-8'), algorithm)
                else:
                    hash_value = hasher.hash_text(text_data, algorithm)
                
                print(f"\n{algorithm.upper()}哈希结果:")
                print("-" * 50)
                print(f"哈希值: {hash_value.upper()}")
                print("-" * 50)
                
            except ImportError:
                text = input("请输入文本: ")
                algorithm = input("请选择算法 (md5/sha1/sha256): ").strip().lower()
                if algorithm not in hasher.algorithms:
                    print("❌ 不支持的算法")
                    continue
                hash_value = hasher.hash_text(text, algorithm)
                print(f"{algorithm.upper()}哈希: {hash_value}")
            except Exception as e:
                print(f"❌ 计算哈希过程中发生错误: {e}")
            
        elif choice == '2':
            filename = input("请输入文件路径: ").strip()
            algorithm = input("请选择算法 (md5/sha1/sha256): ").strip().lower()
            if algorithm not in hasher.algorithms:
                print("不支持的算法")
                continue
            try:
                hash_value = hasher.hash_file(filename, algorithm)
                print(f"文件{algorithm.upper()}哈希: {hash_value}")
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '3':
            try:
                from crypto_toolkit import get_input_with_format_choice, safe_input
                
                # 获取文本输入
                text_data, format_type = get_input_with_format_choice("请输入要验证的文本", "data")
                if text_data is None:
                    continue
                
                # 获取目标哈希
                target_hash = safe_input("请输入目标哈希值: ", "string").strip()
                if not target_hash:
                    continue
                
                # 获取算法选择
                algorithm = safe_input("请选择算法 (md5/sha1/sha256): ", "string").strip().lower()
                if algorithm not in hasher.algorithms:
                    print("❌ 不支持的算法，请选择: md5, sha1, sha256")
                    continue
                
                # 执行验证
                if format_type == 'string':
                    text_to_verify = text_data.decode('utf-8')
                else:
                    text_to_verify = text_data
                
                if hasher.verify_hash(text_to_verify, target_hash, algorithm):
                    print("\n✅ 哈希验证成功!")
                    print(f"文本的{algorithm.upper()}哈希值与目标哈希值匹配")
                else:
                    calculated = hasher.hash_text(text_to_verify, algorithm)
                    print("\n❌ 哈希验证失败")
                    print(f"计算得到: {calculated.upper()}")
                    print(f"目标哈希: {target_hash.upper()}")
                
            except ImportError:
                text = input("请输入文本: ")
                target_hash = input("请输入目标哈希: ").strip()
                algorithm = input("请选择算法 (md5/sha1/sha256): ").strip().lower()
                if algorithm not in hasher.algorithms:
                    print("❌ 不支持的算法")
                    continue
                
                if hasher.verify_hash(text, target_hash, algorithm):
                    print("✅ 哈希验证成功!")
                else:
                    calculated = hasher.hash_text(text, algorithm)
                    print("❌ 哈希验证失败")
                    print(f"计算得到: {calculated}")
                    print(f"目标哈希: {target_hash}")
            except Exception as e:
                print(f"❌ 哈希验证过程中发生错误: {e}")
                
        elif choice == '4':
            target_hash = input("请输入目标哈希: ").strip()
            algorithm = input("请选择算法 (md5/sha1/sha256): ").strip().lower()
            if algorithm not in hasher.algorithms:
                print("不支持的算法")
                continue
            charset_result = show_charset_menu()
            if len(charset_result) == 3:
                charset_choice, custom_start, custom_end = charset_result
            else:
                charset_choice = charset_result
                custom_start = custom_end = None
            
            min_len, max_len = get_length_range()
            brute_force_hash_custom_charset(target_hash, charset_choice, algorithm, min_len, max_len, custom_start, custom_end)
            
        elif choice == '5':
            target_hash = input("请输入目标哈希: ").strip()
            algorithm = input("请选择算法 (md5/sha1/sha256): ").strip().lower()
            wordlist = input("请输入字典文件路径: ").strip()
            if algorithm not in hasher.algorithms:
                print("不支持的算法")
                continue
            dictionary_attack_hash(target_hash, wordlist, algorithm)
            
        elif choice == '6':
            target_hash = input("请输入目标哈希: ").strip()
            algorithm = input("请选择算法 (md5/sha1/sha256): ").strip().lower()
            max_len = int(input("请输入最大密码长度(默认6): ") or "6")
            if algorithm not in hasher.algorithms:
                print("不支持的算法")
                continue
            rainbow_table_attack(target_hash, algorithm, None, max_len)
            
        elif choice == '7':
            hash_collision_demo()
            
        elif choice == '8':
            print("退出程序")
            break
            
        else:
            print("无效选择，请重新输入")

if __name__ == "__main__":
    # 示例用法
    print("哈希算法示例:")
    
    hasher = HashCrypto()
    
    text = "Hello Hash!"
    print(f"文本: {text}")
    
    md5_hash = hasher.hash_text(text, 'md5')
    sha1_hash = hasher.hash_text(text, 'sha1')
    sha256_hash = hasher.hash_text(text, 'sha256')
    
    print(f"MD5:    {md5_hash}")
    print(f"SHA-1:  {sha1_hash}")
    print(f"SHA256: {sha256_hash}")
    
    print("\n" + "="*60)
    main()