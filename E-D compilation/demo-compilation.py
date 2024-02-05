import os
import tkinter as tk
from tkinter import filedialog
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_key_salt_file(key_salt_file, salt, password):
    with open(key_salt_file, 'w') as f:
        f.write(f"Salt: {salt.hex()}\n")
        f.write(f"Password: {password.hex()}")

def encrypt_file(input_file, output_file, password=None, salt=None):
    # 如果没有提供盐和密码，则生成随机值
    if not salt:
        salt = os.urandom(16)
    if not password:
        password = os.urandom(32)

    with open(input_file, 'rb') as f:
        input_data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(input_data) + padder.finalize()

    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(password), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag

    output_data = salt + iv + tag + ciphertext

    with open(output_file, 'wb') as f:
        f.write(output_data)

    return salt, password

def decrypt_file(input_file, output_file, salt, password, access_code=None):
    try:
        with open(input_file, 'rb') as f:
            input_data = f.read()

        salt, iv, tag, ciphertext = input_data[:16], input_data[16:32], input_data[32:48], input_data[48:]

        backend = default_backend()
        cipher = Cipher(algorithms.AES(password), modes.GCM(iv, tag), backend=backend)
        decryptor = cipher.decryptor()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

    except InvalidTag:
        print("解密失败：无效的访问代码或损坏的文件。")

def main():
    root = tk.Tk()
    root.withdraw()

    operation = input("请选择操作，加密(E)或解密(D): ").upper()
    if operation not in ['E', 'D']:
        print("无效的操作选择。")
        return

    input_file = filedialog.askopenfilename(title='选择文件')
    if not input_file:
        print("未选择任何文件！程序退出。")
        return

    if operation == 'E':
        output_file = input_file + '-encrypted.bin'
        key_salt_file = input_file + '-key_salt.txt'
        salt, password = encrypt_file(input_file, output_file)
        generate_key_salt_file(key_salt_file, salt, password)
        print('文件加密成功！')
    elif operation == 'D':
        output_file = filedialog.asksaveasfilename(title='选择输出文件')
        key_file_path = filedialog.askopenfilename(title='选择密钥文件')
        if key_file_path:
            with open(key_file_path, 'r') as f:
                lines = f.readlines()
                salt = bytes.fromhex(lines[0].split(':')[1].strip())
                password = bytes.fromhex(lines[1].split(':')[1].strip())
            decrypt_file(input_file, output_file, salt, password)
            print('文件解密成功！')
        else:
            print("未选择密钥文件，无法解密。")

if __name__ == "__main__":
    main()
