import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


time.sleep(1)

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

        if i == 2:
            print("尝试次数超过限制，程序退出")
            time.sleep(2)
            return


input_file = input('请输入加密文件的路径：')
output_file = input('请输入输出文件的路径：')
access_code = 'EBc77012'

for i in range(3):
    try:
        salt = bytes.fromhex(input("请输入短加密片段："))
        password = bytes.fromhex(input("请输入加密密钥："))
        decrypt_file(input_file, output_file, salt, password, access_code)
        break

    except ValueError:
        print("输入错误，请确保输入的短加密片段和密钥是正确的")

    if i == 2:
        print("尝试次数超过限制，程序退出")
        time.sleep(2)
