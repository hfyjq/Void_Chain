"""new"""

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog

time.sleep(1)


def generate_key_salt_file(key_salt_file, salt, password):
    with open(key_salt_file, 'w') as f:
        f.write(f"Salt: {salt.hex()}\n")
        f.write(f"Password: {password.hex()}")


def encrypt_file(input_file, output_file, key_salt_file):
    # 读取输入文件
    with open(input_file, 'rb') as f:
        input_data = f.read()

    # 生成随机盐和密钥
    salt = os.urandom(16)
    password = os.urandom(32)

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
    # 写入密钥和盐到文件
    generate_key_salt_file(key_salt_file, salt, password)

    return salt, password


def decrypt_file(input_file, output_file, salt, password):
    # 读取输入文件
    with open(input_file, 'rb') as f:
        input_data = f.read()

    # 提取盐、IV、tag 和密文
    salt, iv, tag, ciphertext = input_data[:16], input_data[16:32], input_data[32:48], input_data[48:]
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


# 创建 GUI
root = tk.Tk()
root.withdraw()  # 隐藏主窗口

# 使用资源管理器选择输入文件
input_file = filedialog.askopenfilename(title='选择需要加密的文件')

# 检查是否选择了文件
if not input_file:
    print("未选择任何文件！程序退出。")
    time.sleep(2)
    exit()

# 检查文件是否存在
if not os.path.isfile(input_file):
    print('文件不存在！程序退出。')
    time.sleep(2)
    exit()

output_file = input_file + '-encrypted.bin'
key_salt_file = input_file + '-key_salt.txt'

# 加密文件
salt, password = encrypt_file(input_file, output_file, key_salt_file)

# 在解密时需要提供 salt 和 password
decrypted_file = input_file + '-decrypted.txt'
decrypt_file(output_file, decrypted_file, salt, password)
print('文件加密成功！')
