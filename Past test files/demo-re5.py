#添加了密钥文件直接读取
import os
import time
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_file(input_file, output_file, salt, password):
    # 读取输入文件
    with open(input_file, 'rb') as f:
        input_data = f.read()

    # 对数据进行填充
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(input_data) + padder.finalize()

    # 初始化加密器
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(password), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()

    # 加密数据
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag

    # 将盐和 IV 附加到密文中
    output_data = salt + iv + tag + ciphertext

    # 将输出写入文件
    with open(output_file, 'wb') as f:
        f.write(output_data)


def decrypt_file(input_file, output_file, salt, password, access_code):
    for i in range(3):
        # 获取用户输入的访问代码
        user_access_code = input("请输入访问代码：")

        if user_access_code == access_code:
            # 读取输入文件
            with open(input_file, 'rb') as f:
                input_data = f.read()

            # 提取盐、IV、tag 和密文
            input_salt, iv, tag, ciphertext = input_data[:16], input_data[16:32], input_data[32:48], input_data[48:]

            # 验证输入的盐是否匹配
            if salt != input_salt:
                print("短加密片段不匹配！")
                if i < 2:
                    print("请重新输入短加密片段")
                else:
                    print("尝试次数超过限制，程序退出")
                    time.sleep(2)
                    return
            else:
                # 初始化解密器
                backend = default_backend()
                cipher = Cipher(algorithms.AES(password), modes.GCM(iv, tag), backend=backend)
                decryptor = cipher.decryptor()

                # 解密数据
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                decrypted_data = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()

                # 将输出写入文件
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)

                break
        else:
            print("访问代码错误！")
            if i < 2:
                print("请重新输入访问代码")
            else:
                print("尝试次数超过限制，程序退出")
                time.sleep(2)
                return

def get_input_file():
    while True:
        input_file = filedialog.askopenfilename(title='选择加密文件')
        if input_file:
            return input_file
        print("未选择加密文件，请重新选择")

def get_key_info(has_key_file):
    if has_key_file:
        while True:
            key_file_path = filedialog.askopenfilename(title='选择密钥文件')
            if key_file_path:
                with open(key_file_path, 'r') as f:
                    lines = f.readlines()
                    salt = bytes.fromhex(lines[0].split(':')[1].strip())
                    password = bytes.fromhex(lines[1].split(':')[1].strip())
                return salt, password
            print("未选择密钥文件，请重新选择")
    else:
        for i in range(3):
            try:
                salt = bytes.fromhex(input("请输入短加密片段："))
            except ValueError:
                if i < 2:
                    print("短加密片段错误，请重新输入")
                else:
                    print("尝试次数超过限制，程序退出")
                    time.sleep(2)
                    return None, None
            else:
                if len(salt) != 16 or salt != salt_from_file:
                    if i < 2:
                        print("短加密片段错误，请重新输入")
                    else:
                        print("尝试次数超过限制，程序退出")
                        time.sleep(2)
                        return None, None

                password = bytes.fromhex(input("请输入加密密钥："))
                if len(password) != 32:
                    if i < 2:
                        print("加密密钥长度错误，请重新输入")
                    else:
                        print("尝试次数超过限制，程序退出")
                        time.sleep(2)
                        return None, None
                else:
                    return salt, password

def get_output_file():
    while True:
        output_file = filedialog.asksaveasfilename(title='选择输出文件')
        if output_file:
            return output_file
        print("未选择输出文件，请重新选择")

# 创建 GUI
root = tk.Tk()
root.withdraw() # 隐藏主窗口

# 使用资源管理器选择输入文件
input_file = get_input_file()

# 检查是否存在密钥文件
while True:
    has_key_file = input("是否拥有密钥文件？(yes/no): ").lower() == "yes"
    if has_key_file or not has_key_file:
        break
    print("请输入有效的选项 (yes/no)")

if has_key_file:
    while True:
        key_file_path = filedialog.askopenfilename(title='选择密钥文件')
        if key_file_path:
            with open(key_file_path, 'r') as f:
                lines = f.readlines()
                salt_from_file = bytes.fromhex(lines[0].split(':')[1].strip())
                password = bytes.fromhex(lines[1].split(':')[1].strip())
            break
        print("未选择密钥文件，请重新选择")

else:
    salt, password = get_key_info(has_key_file)
    if salt is None or password is None:
        exit()

# 使用资源管理器选择输出文件
output_file = get_output_file()

access_code = 'EBc77012'

decrypt_file(input_file, output_file, salt_from_file if has_key_file else salt, password, access_code)
