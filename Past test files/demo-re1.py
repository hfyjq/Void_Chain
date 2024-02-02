import os
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
    # 获取用户输入的访问代码
    user_access_code = input("请输入访问代码：")

    if user_access_code != access_code:
        print("访问代码错误！")
        return

    # 读取输入文件
    with open(input_file, 'rb') as f:
        input_data = f.read()

    # 提取盐、IV、tag 和密文
    input_salt, iv, tag, ciphertext = input_data[:16], input_data[16:32], input_data[32:48], input_data[48:]

    # 验证输入的盐是否匹配
    if salt != input_salt:
        print("盐不匹配！")
        return

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

input_file = 'large_file_encrypted.bin'
output_file = 'large_file_decrypted.txt'
access_code = '123'

# 获取用户输入的盐和密钥
salt = bytes.fromhex(input("请输入盐（16/32）："))
password = bytes.fromhex(input("请输入加密密钥（32/64）："))

# 在解密时需要提供 salt 和 password，并输入访问代码
decrypt_file(input_file, output_file, salt, password, access_code)
