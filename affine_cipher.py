#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仿射密码加密、解密和爆破工具
仿射密码公式：E(x) = (ax + b) mod m
解密公式：D(y) = a^(-1)(y - b) mod m
"""

import string
import time

def gcd(a, b):
    """计算最大公约数"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """计算模逆元"""
    if gcd(a, m) != 1:
        return None
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_encrypt(plaintext, a, b, m=26):
    """
    仿射密码加密
    Args:
        plaintext: 明文
        a: 乘数密钥（必须与m互质）
        b: 加数密钥
        m: 字母表大小（默认26）
    """
    if gcd(a, m) != 1:
        raise ValueError(f"a({a})必须与m({m})互质")
    
    result = ""
    for char in plaintext:
        if char.isalpha():
            # 检查字符是大写还是小写
            if char.isupper():
                x = ord(char) - ord('A')
                y = (a * x + b) % m
                result += chr(y + ord('A'))
            else:  # 小写字母
                x = ord(char) - ord('a')
                y = (a * x + b) % m
                result += chr(y + ord('a'))
        else:
            result += char
    return result

def affine_decrypt(ciphertext, a, b, m=26):
    """
    仿射密码解密
    Args:
        ciphertext: 密文
        a: 乘数密钥
        b: 加数密钥
        m: 字母表大小
    """
    a_inv = mod_inverse(a, m)
    if a_inv is None:
        raise ValueError(f"a({a})在模{m}下没有逆元")
    
    result = ""
    for char in ciphertext:
        if char.isalpha():
            # 检查字符是大写还是小写
            if char.isupper():
                y = ord(char) - ord('A')
                x = (a_inv * (y - b)) % m
                result += chr(x + ord('A'))
            else:  # 小写字母
                y = ord(char) - ord('a')
                x = (a_inv * (y - b)) % m
                result += chr(x + ord('a'))
        else:
            result += char
    return result

def affine_brute_force(ciphertext, target_word=None, m=26):
    """
    仿射密码暴力破解
    Args:
        ciphertext: 待破解的密文
        target_word: 目标单词（用于验证）
        m: 字母表大小
    """
    results = []
    valid_a_values = [i for i in range(1, m) if gcd(i, m) == 1]
    
    print(f"正在尝试破解密文: {ciphertext}")
    print(f"有效的a值: {valid_a_values}")
    print("-" * 50)
    
    for a in valid_a_values:
        for b in range(m):
            try:
                decrypted = affine_decrypt(ciphertext, a, b, m)
                results.append((a, b, decrypted))
                
                if target_word and target_word.upper() in decrypted.upper():
                    print(f"*** 可能找到正确密钥! a={a}, b={b} ***")
                    print(f"解密结果: {decrypted}")
                    return a, b, decrypted
                    
            except ValueError:
                continue
    
    # 如果没有目标词，显示所有结果
    if not target_word:
        print("所有可能的解密结果:")
        for i, (a, b, decrypted) in enumerate(results):
            print(f"{i+1:2d}. a={a:2d}, b={b:2d} -> {decrypted}")
            if i > 20:  # 限制显示数量
                print("... (更多结果)")
                break
    
    return results

def frequency_analysis(text):
    """简单的频率分析"""
    text = text.upper().replace(' ', '')
    freq = {}
    total = 0
    
    for char in text:
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
            total += 1
    
    print("字母频率分析:")
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    for char, count in sorted_freq[:5]:
        percentage = (count / total) * 100
        print(f"{char}: {count} ({percentage:.1f}%)")

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

def brute_force_affine_custom_charset(ciphertext, charset_choice, target_plaintext=None, custom_start=None, custom_end=None):
    """
    Affine密码自定义字符集暴力破解
    """
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
    
    print(f"开始Affine密码自定义字符集暴力破解")
    print(f"选择的字符集: {charset_names.get(charset_choice, '未知')} (长度: {len(charset)})")
    print(f"密文: {ciphertext}")
    print("-" * 80)
    
    m = len(charset)
    if m == 0:
        print("❌ 字符集为空，无法进行破解")
        return None, None, None
    
    valid_a_values = [i for i in range(1, m) if gcd(i, m) == 1]
    print(f"有效的a值数量: {len(valid_a_values)}")
    
    for a in valid_a_values:
        for b in range(m):
            attempts += 1
            try:
                # 使用自定义字符集进行解密
                result = ""
                for char in ciphertext:
                    if char in charset:
                        y = charset.index(char)
                        a_inv = mod_inverse(a, m)
                        if a_inv is not None:
                            x = (a_inv * (y - b)) % m
                            result += charset[x]
                        else:
                            result += char
                    else:
                        result += char
                
                if target_plaintext and target_plaintext.lower() in result.lower():
                    elapsed = time.time() - start_time
                    print(f"\n*** 找到密钥! ***")
                    print(f"密钥: a={a}, b={b}")
                    print(f"解密结果: {result}")
                    print(f"尝试次数: {attempts}")
                    print(f"耗时: {elapsed:.2f}秒")
                    return a, b, result
                
                # 检查是否为可读文本
                if len(result) > 3 and all(c in charset for c in result):
                    printable_count = sum(1 for c in result if c.isprintable())
                    if printable_count / len(result) > 0.8:  # 80%以上可打印字符
                        print(f"可能的解密 a={a}, b={b}: {result[:50]}")
                        
            except Exception:
                continue
                
            if attempts % 1000 == 0:
                elapsed = time.time() - start_time
                print(f"已尝试 {attempts} 个密钥组合... ({elapsed:.1f}秒)")
    
    elapsed = time.time() - start_time
    print(f"\n暴力破解完成。总尝试次数: {attempts}，耗时: {elapsed:.2f}秒")
    return None, None, None

def main():
    print("=" * 60)
    print("仿射密码工具")
    print("=" * 60)
    
    while True:
        print("\n选择操作:")
        print("1. 加密")
        print("2. 解密")
        print("3. 暴力破解")
        print("4. 频率分析")
        print("5. 自定义字符集暴力破解")
        print("6. 退出")
        
        choice = input("\n请选择 (1-6): ").strip()
        
        if choice == '1':
            plaintext = input("请输入明文: ").strip()
            if not plaintext:
                print("❌ 明文不能为空")
                continue
                
            try:
                a = int(input("请输入a值 (必须与26互质): "))
                b = int(input("请输入b值: "))
                encrypted = affine_encrypt(plaintext, a, b)
                print(f"\n✅ 加密成功!")
                print(f"明文: {plaintext}")
                print(f"密钥: a={a}, b={b}")
                print(f"密文: {encrypted}")
            except ValueError as e:
                if "invalid literal" in str(e):
                    print("❌ 输入错误：请输入有效的整数")
                else:
                    print(f"❌ 加密失败: {e}")
            except Exception as e:
                print(f"❌ 加密过程中发生错误: {e}")
                
        elif choice == '2':
            ciphertext = input("请输入密文: ").strip()
            if not ciphertext:
                print("❌ 密文不能为空")
                continue
                
            try:
                a = int(input("请输入a值: "))
                b = int(input("请输入b值: "))
                decrypted = affine_decrypt(ciphertext, a, b)
                print(f"\n✅ 解密成功!")
                print(f"密文: {ciphertext}")
                print(f"密钥: a={a}, b={b}")
                print(f"明文: {decrypted}")
            except ValueError as e:
                if "invalid literal" in str(e):
                    print("❌ 输入错误：请输入有效的整数")
                else:
                    print(f"❌ 解密失败: {e}")
            except Exception as e:
                print(f"❌ 解密过程中发生错误: {e}")
                
        elif choice == '3':
            ciphertext = input("请输入待破解的密文: ").strip()
            if not ciphertext:
                print("❌ 密文不能为空")
                continue
                
            target = input("请输入目标单词(可选，回车跳过): ").strip()
            target = target if target else None
            
            try:
                print(f"\n开始仿射密码暴力破解...")
                print(f"密文: {ciphertext}")
                if target:
                    print(f"目标单词: {target}")
                print("-" * 50)
                
                if target:
                    result = affine_brute_force(ciphertext, target)
                    if isinstance(result, tuple):
                        a, b, decrypted = result
                        print(f"\n✅ 暴力破解成功!")
                        print(f"找到密钥: a={a}, b={b}")
                        print(f"完整解密: {decrypted}")
                    else:
                        print("❌ 未找到匹配的密钥")
                else:
                    affine_brute_force(ciphertext)
            except Exception as e:
                print(f"❌ 暴力破解过程中发生错误: {e}")
                
        elif choice == '4':
            text = input("请输入要分析的文本: ").strip()
            if not text:
                print("❌ 文本不能为空")
                continue
                
            try:
                print(f"\n开始频率分析...")
                print(f"分析文本: {text}")
                print("-" * 50)
                frequency_analysis(text)
            except Exception as e:
                print(f"❌ 频率分析过程中发生错误: {e}")
            
        elif choice == '5':
            ciphertext = input("请输入密文: ").strip()
            charset_result = show_charset_menu()
            if len(charset_result) == 3:
                charset_choice, custom_start, custom_end = charset_result
            else:
                charset_choice = charset_result
                custom_start = custom_end = None
                
            target = input("请输入目标明文(可选): ").strip()
            try:
                target = target if target else None
                brute_force_affine_custom_charset(ciphertext, charset_choice, target, custom_start, custom_end)
            except Exception as e:
                print(f"错误: {e}")
                
        elif choice == '6':
            print("退出程序")
            break
            
        else:
            print("无效选择，请重新输入")

if __name__ == "__main__":
    # 示例用法
    print("仿射密码示例:")
    
    # 加密示例
    plaintext = "Hello World"
    a, b = 5, 8
    print(f"明文: {plaintext}")
    print(f"密钥: a={a}, b={b}")
    
    encrypted = affine_encrypt(plaintext, a, b)
    print(f"密文: {encrypted}")
    
    # 解密验证
    decrypted = affine_decrypt(encrypted, a, b)
    print(f"解密: {decrypted}")
    
    print("\n" + "="*60)
    main()