#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码学工具包主程序
集成了仿射密码、DES、AES、RC4、哈希算法、SM4等工具
"""

import os
import sys
import binascii

def get_input_with_format_choice(prompt, data_type="data"):
    """
    通用输入函数，支持用户选择输入格式（字符串或十六进制）
    Args:
        prompt: 输入提示信息
        data_type: 数据类型提示 ("data", "key", "plaintext", "ciphertext")
    Returns:
        tuple: (data_bytes, format_type) 或 (None, None) 如果出错
    """
    type_names = {
        "data": "数据",
        "key": "密钥",
        "plaintext": "明文",
        "ciphertext": "密文"
    }
    
    type_name = type_names.get(data_type, "数据")
    
    print(f"\n{prompt}")
    print("请选择输入格式:")
    print("1. 字符串格式")
    print("2. 十六进制格式")
    print("3. 字节列表格式 (十六进制逗号隔开，如: 41,42,43)")
    
    while True:
        format_choice = input("请选择输入格式 (1-3): ").strip()
        if format_choice in ['1', '2', '3']:
            break
        print("❌ 输入格式选择无效，请输入1、2或3")
    
    if format_choice == '1':
        # 字符串输入
        while True:
            data_str = input(f"请输入{type_name}(字符串): ").strip()
            if data_str:
                try:
                    return data_str.encode('utf-8'), 'string'
                except Exception as e:
                    print(f"❌ 字符串编码失败: {str(e)}")
                    continue
            else:
                print(f"❌ {type_name}不能为空，请重新输入")
    
    elif format_choice == '2':
        # 十六进制输入
        while True:
            hex_str = input(f"请输入{type_name}(十六进制): ").strip()
            if hex_str:
                try:
                    # 移除可能的空格和0x前缀
                    hex_str = hex_str.replace(' ', '').replace('0x', '').replace('0X', '')
                    if len(hex_str) % 2 != 0:
                        print("❌ 十六进制字符串长度必须为偶数")
                        continue
                    return binascii.unhexlify(hex_str), 'hex'
                except Exception as e:
                    print(f"❌ 十六进制格式错误: {str(e)}")
                    print("请确保输入的是有效的十六进制字符串（如：48656c6c6f）")
                    continue
            else:
                print(f"❌ {type_name}不能为空，请重新输入")
    
    else:
        # 字节列表输入 (format_choice == '3')
        while True:
            byte_list_str = input(f"请输入{type_name}(十六进制字节列表，逗号隔开): ").strip()
            if byte_list_str:
                try:
                    # 移除可能的空格并分割
                    byte_values = byte_list_str.replace(' ', '').split(',')
                    byte_data = []
                    
                    for byte_str in byte_values:
                        if not byte_str:  # 跳过空字符串
                            continue
                        
                        # 移除可能的0x前缀
                        byte_str = byte_str.replace('0x', '').replace('0X', '')
                        
                        # 解析十六进制字节值
                        byte_val = int(byte_str, 16)
                        if byte_val < 0 or byte_val > 255:
                            print(f"❌ 字节值必须在0x00-0xFF范围内，发现无效值: 0x{byte_val:02X}")
                            raise ValueError(f"字节值超出范围: 0x{byte_val:02X}")
                        byte_data.append(byte_val)
                    
                    if not byte_data:
                        print("❌ 未找到有效的字节值")
                        continue
                        
                    return bytes(byte_data), 'bytes'
                except ValueError as e:
                    print(f"❌ 字节列表格式错误: {str(e)}")
                    print("请确保输入格式正确，例如: 48,65,6c,6c,6f (十六进制，每个值为00-FF)")
                    continue
                except Exception as e:
                    print(f"❌ 解析字节列表时发生错误: {str(e)}")
                    continue
            else:
                print(f"❌ {type_name}不能为空，请重新输入")

def get_key_input(prompt, required_length=None):
    """
    专门用于密钥输入的函数
    Args:
        prompt: 输入提示
        required_length: 要求的密钥长度（字节数），None表示不限制
    Returns:
        bytes: 密钥数据，失败返回None
    """
    while True:
        key_data, format_type = get_input_with_format_choice(prompt, "key")
        if key_data is None:
            return None
            
        if required_length and len(key_data) != required_length:
            print(f"❌ 密钥长度错误：需要{required_length}字节，实际{len(key_data)}字节")
            print("请重新输入正确长度的密钥")
            continue
            
        return key_data

def display_result(result_data, result_type="result"):
    """
    显示结果，同时以字符串和十六进制格式输出
    Args:
        result_data: 结果数据 (bytes)
        result_type: 结果类型 ("result", "plaintext", "ciphertext", "hash")
    """
    type_names = {
        "result": "结果",
        "plaintext": "明文",
        "ciphertext": "密文",
        "hash": "哈希值"
    }
    
    type_name = type_names.get(result_type, "结果")
    
    print(f"\n{type_name}:")
    print("-" * 50)
    
    # 显示十六进制格式
    hex_result = binascii.hexlify(result_data).decode().upper()
    print(f"十六进制: {hex_result}")
    
    # 显示字节列表格式（十六进制）
    byte_list = ','.join(f'{b:02X}' for b in result_data)
    print(f"字节列表: {byte_list}")
    
    # 尝试显示字符串格式
    try:
        str_result = result_data.decode('utf-8')
        # 检查是否包含可打印字符
        if all(c.isprintable() or c.isspace() for c in str_result):
            print(f"字符串: {str_result}")
        else:
            print("字符串: [包含不可打印字符]")
    except UnicodeDecodeError:
        print("字符串: [无法解码为UTF-8]")
    
    print("-" * 50)

def safe_input(prompt, input_type="string", default=None):
    """
    安全输入函数，带有错误处理和默认值
    Args:
        prompt: 输入提示
        input_type: 输入类型 ("string", "int", "choice")
        default: 默认值
    Returns:
        输入的值或默认值
    """
    while True:
        try:
            user_input = input(prompt).strip()
            
            if not user_input and default is not None:
                return default
                
            if not user_input:
                print("❌ 输入不能为空，请重新输入")
                continue
                
            if input_type == "int":
                return int(user_input)
            elif input_type == "choice":
                return user_input
            else:
                return user_input
                
        except ValueError as e:
            print(f"❌ 输入格式错误: {str(e)}")
            continue
        except KeyboardInterrupt:
            print("\n\n用户中断操作")
            return None
        except Exception as e:
            print(f"❌ 输入错误: {str(e)}")
            continue

def print_banner():
    """打印程序横幅"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                      密码学工具包 v5.1                        ║
    ║                    Contribute by Jaren                       ║
    ║  支持算法: 仿射密码、DES、AES、RC4、SHA-1、SHA256、MD5、SM4     ║
    ║  功能: 加密、解密、暴力破解、字典攻击、哈希计算                  ║
    ║  输入格式: 字符串、十六进制、字节列表                           ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def run_tool(script_name):
    """运行指定的工具脚本"""
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    
    if not os.path.exists(script_path):
        print(f"错误: 找不到脚本文件 {script_name}")
        return
    
    try:
        # 使用exec执行脚本
        with open(script_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        # 创建新的命名空间执行脚本
        namespace = {'__name__': '__main__', '__file__': script_path}
        exec(code, namespace)
        
    except KeyboardInterrupt:
        print("\n\n用户中断操作")
    except Exception as e:
        print(f"执行脚本时发生错误: {e}")

def show_tool_info():
    """显示各工具的详细信息"""
    tools_info = {
        '1': {
            'name': '仿射密码工具',
            'file': 'affine_cipher.py',
            'description': '经典密码学中的仿射密码，支持加密、解密和暴力破解',
            'features': [
                '• 仿射密码加密/解密',
                '• 暴力破解所有可能的密钥组合',
                '• 频率分析功能',
                '• 支持目标单词验证'
            ]
        },
        '2': {
            'name': 'DES加密工具',
            'file': 'des_crypto.py',
            'description': 'DES对称加密算法，支持ECB和CBC模式',
            'features': [
                '• DES ECB/CBC模式加密解密',
                '• 随机密钥生成',
                '• 数字、字母和字母数字混合密钥暴力破解',
                '• 支持自定义密钥长度范围'
            ]
        },
        '3': {
            'name': 'AES加密工具',
            'file': 'aes_crypto.py',
            'description': 'AES对称加密算法，支持128/192/256位密钥',
            'features': [
                '• AES-128/192/256加密解密',
                '• ECB/CBC/CTR多种模式',
                '• 基于密码的密钥派生',
                '• 字典攻击和暴力破解'
            ]
        },
        '4': {
            'name': 'RC4流密码工具',
            'file': 'rc4_crypto.py',
            'description': 'RC4流密码算法，广泛应用于网络协议',
            'features': [
                '• RC4流密码加密/解密',
                '• 多种字符集暴力破解',
                '• 字典攻击支持',
                '• 密钥流分析功能'
            ]
        },
        '5': {
            'name': '哈希算法工具',
            'file': 'hash_crypto.py',
            'description': '支持MD5、SHA-1、SHA256等哈希算法',
            'features': [
                '• MD5/SHA-1/SHA-256哈希计算',
                '• 文件哈希值计算',
                '• 哈希值验证',
                '• 密码哈希暴力破解',
                '• 字典攻击和彩虹表攻击',
                '• 哈希碰撞演示'
            ]
        },
        '6': {
            'name': 'SM4国密算法工具',
            'file': 'sm4_crypto.py',
            'description': '中国国家密码标准SM4分组密码算法',
            'features': [
                '• SM4分组密码加密/解密',
                '• ECB模式支持',
                '• 单块和多块数据处理',
                '• 数字、字母和字母数字混合密钥暴力破解功能'
            ]
        }
    }
    
    print("\n" + "="*80)
    print("工具详细信息")
    print("="*80)
    
    for key, info in tools_info.items():
        print(f"\n【{key}】{info['name']} ({info['file']})")
        print(f"    {info['description']}")
        print("    功能特性:")
        for feature in info['features']:
            print(f"    {feature}")

def show_quick_examples():
    """显示快速使用示例"""
    examples = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                        快速使用示例                          ║
    ╚══════════════════════════════════════════════════════════════╝
    
    输入格式支持:
    • 字符串格式: Hello World
    • 十六进制格式: 48656c6c6f20576f726c64
    • 字节列表格式: 48,65,6C,6C,6F,20,57,6F,72,6C,64
    
    1. 仿射密码破解:
       • 已知密文: "IHHQS"
       • 可能包含: "HELLO"
       • 选择仿射密码工具 → 暴力破解 → 输入密文和目标词
    
    2. AES密码破解:
       • 已知AES-128密文 (任意格式): "a1b2c3d4..." 或 A1,B2,C3,D4,...
       • 疑似简单密码
       • 选择AES工具 → 密码暴力破解 → 设置字符集和长度
    
    3. 哈希密码恢复:
       • MD5哈希: "5d41402abc4b2a76b9719d911017c592"
       • 选择哈希工具 → 暴力破解 → 尝试常见密码
    
    4. RC4流密码分析:
       • 已知明文密文对，需解密另一密文
       • 选择RC4工具 → 密钥流分析
    
    5. SM4国密算法:
       • 测试SM4加密强度
       • 选择SM4工具 → 生成随机密钥 → 测试加密解密
    """
    print(examples)

def check_dependencies():
    """检查依赖库"""
    required_modules = ['hashlib', 'itertools', 'binascii', 'time', 'string']
    crypto_modules = ['Crypto.Cipher', 'Crypto.Util.Padding', 'Crypto.Random']
    
    print("检查依赖库...")
    
    # 检查标准库
    missing_std = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_std.append(module)
    
    # 检查pycryptodome
    missing_crypto = []
    for module in crypto_modules:
        try:
            __import__(module)
        except ImportError:
            missing_crypto.append(module)
    
    if missing_std:
        print(f"❌ 缺少标准库: {', '.join(missing_std)}")
        return False
    
    if missing_crypto:
        print("❌ 缺少pycryptodome库")
        print("请运行: pip install pycryptodome")
        return False
    
    print("✅ 所有依赖库检查通过")
    return True

def main():
    """主程序"""
    print_banner()
    
    # 检查依赖
    if not check_dependencies():
        print("\n请安装缺失的依赖库后重新运行")
        return
    
    while True:
        print("\n" + "="*60)
        print("主菜单 - 请选择要使用的工具:")
        print("="*60)
        print("1. 仿射密码工具 (affine_cipher.py)")
        print("2. DES加密工具 (des_crypto.py)")
        print("3. AES加密工具 (aes_crypto.py)")
        print("4. RC4流密码工具 (rc4_crypto.py)")
        print("5. 哈希算法工具 (hash_crypto.py)")
        print("6. SM4国密算法工具 (sm4_crypto.py)")
        print("-" * 60)
        print("7. 查看工具详细信息")
        print("8. 查看快速使用示例")
        print("9. 退出程序")
        
        choice = input("\n请选择 (1-9): ").strip()
        
        if choice == '1':
            print("\n启动仿射密码工具...")
            run_tool('affine_cipher.py')
            
        elif choice == '2':
            print("\n启动DES加密工具...")
            run_tool('des_crypto.py')
            
        elif choice == '3':
            print("\n启动AES加密工具...")
            run_tool('aes_crypto.py')
            
        elif choice == '4':
            print("\n启动RC4流密码工具...")
            run_tool('rc4_crypto.py')
            
        elif choice == '5':
            print("\n启动哈希算法工具...")
            run_tool('hash_crypto.py')
            
        elif choice == '6':
            print("\n启动SM4国密算法工具...")
            run_tool('sm4_crypto.py')
            
        elif choice == '7':
            show_tool_info()
            
        elif choice == '8':
            show_quick_examples()
            
        elif choice == '9':
            print("\n感谢使用密码学工具包！")
            break
            
        else:
            print("❌ 无效选择，请重新输入")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断程序")
    except Exception as e:
        print(f"\n程序发生错误: {e}")
        import traceback
        traceback.print_exc()