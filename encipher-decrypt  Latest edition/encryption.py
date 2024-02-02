'''
re6.5  
latest edition

1. Code structure, the encryption and decryption parts of the code are packaged into functions, and the use of 'if __name__ == "__main__":' to protect the main program, so that the code has better readability and maintainability.
2. During file encryption, if a file with the same name exists in the output file path, ask the user whether to overwrite the original file.
3. When the declassified documents, by capturing ` cryptography. Exceptions. InvalidTag ` exception to determine the access code input is correct.
4. When obtaining short encryption fragments and encryption keys, use the 'getpass' module to hide the input and increase security.

1. 代码结构上，将加密和解密部分的代码分别封装成函数，并且使用 `if __name__ == "__main__":` 保护主程序，使得代码具有更好的可读性和可维护性。
2. 在加密文件时，如果输出文件路径已经存在同名文件，询问用户是否覆盖原文件。
3. 在解密文件时，通过捕获 `cryptography.exceptions.InvalidTag` 异常来判断输入的访问代码是否正确。
4. 在获取短加密片段和加密密钥时，使用 `getpass` 模块隐藏输入，增加安全性。
'''
import os
import time
import tkinter as tk
from tkinter import filedialog
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

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
        user_access_code = getpass("请输入访问代码：")

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
                try:
                    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                    decrypted_data = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()
                except InvalidTag:
                    print("访问代码错误！")
                    if i < 2:
                        print("请重新输入访问代码")
                    else:
                        print("尝试次数超过限制，程序退出")
                        time.sleep(2)
                        return

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

def get_key_info(has_key_file, salt_from_file):
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
                salt = bytes.fromhex(getpass("请输入短加密片段："))
            except ValueError:
                if i < 2:
                    print("短加密片段错误，请重新输入")
                else:
                    print("尝试次数超过限制，程序退出")
                    time.sleep(2)
                    return None, None
            else:
                if len(salt) != 16:
                    print("短加密片段长度错误，请重新输入")
                    continue

                while True:
                    password_input = getpass("请输入加密密钥：")
                    try:
                        password = bytes.fromhex(password_input)
                        if len(password) != 32:
                            print("加密密钥长度错误，请重新输入")
                        else:
                            return salt, password
                    except ValueError:
                        print("加密密钥格式错误，请重新输入")

def get_output_file():
    while True:
        output_file = filedialog.asksaveasfilename(title='选择输出文件')
        if output_file:
            if os.path.exists(output_file):
                overwrite = input("输出文件已经存在，是否覆盖？(yes/no): ").lower()
                if overwrite != "yes":
                    continue
            return output_file
        print("未选择输出文件，请重新选择")

def main():
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
        salt, password = get_key_info(has_key_file, None)
        if salt is None or password is None:
            return

    # 使用资源管理器选择输出文件
    output_file = get_output_file()

    access_code = 'EBc77012'#随便写的，可以改

    decrypt_file(input_file, output_file, salt_from_file if has_key_file else salt, password, access_code)

if __name__ == "__main__":
    main()
```
