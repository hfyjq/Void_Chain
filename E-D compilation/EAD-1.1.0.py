import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Dictionary for language translations
translations = {
    'en': {
        'operation_prompt': "Choose operation, Encrypt(E) or Decrypt(D): ",
        'no_file_selected': "No file selected! Program exiting.",
        'encryption_successful': "File encryption successful!",
        'no_key_file_selected': "No key file selected, cannot decrypt.",
        'decryption_successful': "File decryption successful!",
        'terms_and_conditions': "Terms and Conditions:",
        'terms_content': "Please read and accept the terms and conditions before using this software.",
        'terms_agree': "I agree to the terms and conditions",
        'terms_disagree': "I disagree",
        'language_prompt': "Select language: English (E) or 中文 (C): ",
        'invalid_language': "Invalid language selection.",
        'language_change_successful': "Language changed successfully!",
        'select_file': "Select a file",
        'select_output_file': "Select an output file",
        'select_key_file': "Select a key file",
        'choose_operation': 'Choose operation: (E)ncrypt, (D)ecrypt, (S)ettings\n',
        'adjust_settings': 'Enter "1" to adjust language preference: ',
        'language_changed': 'Language preference changed successfully.',
        'invalid_operation': 'Invalid operation. Please try again.',
        'settings_panel': "Settings Panel:",
        'language_preference': "[1] Adjust Language Preference",
        'enter_choice': "Enter the options you want to adjust:",
    },
    'zh': {
        'operation_prompt': "选择操作，加密(E) 或 解密(D): ",
        'no_file_selected': "未选择文件！程序退出。",
        'encryption_successful': "文件加密成功！",
        'no_key_file_selected': "未选择密钥文件，无法解密。",
        'decryption_successful': "文件解密成功！",
        'terms_and_conditions': "条款和条件：",
        'terms_content': "请在使用本软件之前阅读并同意条款和条件。",
        'terms_agree': "我接受/Yes, I accept",
        'terms_disagree': "我不接受/No,I don't accept",
        'language_prompt': "选择语言：English (E) 或 中文 (C): ",
        'invalid_language': "无效的语言选择。",
        'language_change_successful': "语言更改成功！",
        'select_file': "选择文件",
        'select_output_file': "选择输出文件",
        'select_key_file': "选择密钥文件",
        'choose_operation': '选择操作：(E)加密，(D)解密，(S)设置\n',
        'adjust_settings': '输入“1”调整语言偏好设置：',
        'language_changed': '语言偏好设置已成功更改。',
        'invalid_operation': '无效操作。请重试。',
        'settings_panel': "设置面板：",
        'language_preference': "[1] 调整语言首选项",
        'enter_choice': "输入要调整的选项:",
    }
}

# Default language
current_language = 'zh'

def save_language_preference(language_code):
    with open("language_setting.txt", 'w') as f:
        f.write(language_code)

def load_language_preference():
    if os.path.isfile("language_setting.txt"):
        with open("language_setting.txt", 'r') as f:
            language_code = f.read().strip()
            return language_code
    return None

def generate_key_salt_file(key_salt_file, salt, password):
    with open(key_salt_file, 'wb') as f:
        f.write(salt + password)

def encrypt_file(input_file, output_file, password=None, salt=None):
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

def decrypt_file(input_file, output_file, key_file_path):
    try:
        with open(input_file, 'rb') as f:
            input_data = f.read()

        with open(key_file_path, 'rb') as f:
            key_data = f.read()
            salt = key_data[:16]
            password = key_data[16:48]
        iv, tag, ciphertext = input_data[16:32], input_data[32:48], input_data[48:]

        backend = default_backend()
        cipher = Cipher(algorithms.AES(password), modes.GCM(iv, tag), backend=backend)
        decryptor = cipher.decryptor()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

    except InvalidTag:
        print("Decryption failed: Invalid access code or corrupted file.")

def show_terms_window():
    # 条款窗口
    terms_window = tk.Toplevel()
    terms_window.title(translations[current_language]['terms_and_conditions'])
    terms_window.geometry("500x400")
    terms_window.resizable(False, False)
    terms_window.focus_set()

    # 居中显示条款窗口
    window_width = terms_window.winfo_reqwidth()
    window_height = terms_window.winfo_reqheight()
    position_right = int(terms_window.winfo_screenwidth() / 2 - window_width / 2)
    position_down = int(terms_window.winfo_screenheight() / 2 - window_height / 2)
    terms_window.geometry(f"+{position_right}+{position_down}")

    # 滚动条
    scrollbar = tk.Scrollbar(terms_window)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # 文本框
    terms_text = tk.Text(terms_window, wrap=tk.WORD, yscrollcommand=scrollbar.set)
    terms_text.pack()

    # 将用户条款添加到文本框
    terms_text.insert(tk.END, "本软件的使用受用户许可协议的约束。软件的主体部分运行时不会与互联网有任何的连接，使用者的数据等文件都会保存在本地；但软件的一些辅助性功能可能需要网络连接。开发者在任何时候都不保证联网功能的可用性，例如高级功能的详细使用说明，某些加密算法的具体解析，或其他补充DLC。"
                              "开发者保留修改和终止任意功能的权利。软件部分内容、技术支持请访问对应内容提供的Github页面链接。任何说明文本、软件、脚本命名若与现实世界中的地点、人物、技术或实体重名以及相似纯属巧合，并不意味着本软件有任何第三方的赞助和认可。\n"
                              "\n要获取补充DLC以及其它附加实验性内容，可能需要提供额外费用、特殊序列号。获取这些内容可能需要互联网连接，可能不适用于所有使用者。\n"
                              "\n版权所有  Copyright (c) 2024 Akasi梦梦没做梦 ，遵从Apache V2.0开源协议。任何说明文本、软件、脚本命名若与现实世界中的地点、人物、技术或实体重名以及相似纯属巧合，不含有任何暗示或煽动。开发者并不以任何形式支持、容忍或鼓励任何人将本软件用于非法用途\n"
                              "\n#请严格遵从软件内的使用说明，过失操作导致的一切损失均由您自行承担\n#不建议自行更改任何依赖文件，这可能导致部分功能的失效、部分文件异常或损毁\n#出现“加载中”等字样时请不要关闭软件，可能会导致意外的错误和损失\n"
                              "\nEnglish version:\n"
                              "The use of the software is governed by the user license agreement. The main part of the software will not have any connection with the Internet when running, and your data and other files will be saved locally; However, some ancillary features of the software may require an Internet connection. "
                              "The Developer does not guarantee the availability of networking features at any time, such as detailed usage instructions for advanced features, specific parsing of certain encryption algorithms, or other supplementary DLC. The Developer reserves the right to modify and discontinue any functionality. "
                              "For some software content and technical support, please visit the Github page link provided by the corresponding content. The fact that any description text, software, scripts are named in the same name or similar to a real world place, person, technology, or entity is purely coincidental does not imply "
                              "that the Software is sponsored or endorsed by any third party.\n"
                              "\nAdditional DLC and other additional experimental content may be available for an additional fee and special serial numbers. Access to this content may require an Internet connection and may not be available to all users.\n"
                              "\nCopyright (c) 2024 Akasi梦梦没做梦, compliant with the Apache V2.0 open source license. Any description text, software, or script naming that bears the same name or resemblance to a real world place, person, technology, or entity is purely coincidental and does not imply or incite anything."
                              " The Developer does not in any way endorse, condone or encourage anyone to use the Software for illegal purposes\n"
                              "\n# Please strictly follow the instructions in the software, all losses caused by negligence will be borne by you\n# It is not recommended to change any dependent files on your own, as this may cause some functionality to fail, some files to be abnormal or corrupted\n"
                              "# Do not close the software when words such as ‘Loading’ appear, it may cause unexpected errors and losses")

    # 配置滚动条与文本框的关联
    scrollbar.config(command=terms_text.yview)

    def agree_terms():
        with open("terms_accepted.txt", 'w') as f:
            f.write('Terms Accepted')
        terms_window.destroy()
        main()  # 同意条款后继续执行主函数

    def disagree_terms():
        messagebox.showinfo("Exit", "You have not agreed to the terms and conditions. Program exiting.")
        terms_window.destroy()
        exit()

    # 同意和不同意按钮
    agree_button = tk.Button(terms_window, text=translations[current_language]['terms_agree'], width=20, command=agree_terms)
    agree_button.pack(pady=10)
    disagree_button = tk.Button(terms_window, text=translations[current_language]['terms_disagree'], width=26, command=disagree_terms)
    disagree_button.pack(pady=5)

    # 运行条款窗口
    terms_window.mainloop()

def change_language(new_language):
    global current_language
    current_language = new_language
    save_language_preference(new_language)  # 保存新的语言偏好
    messagebox.showinfo("Language Change", translations[current_language]['language_change_successful'])

def adjust_settings():
    global current_language
    settings_choice = input(translations[current_language]['adjust_settings'])
    if settings_choice == '1':
        lang_choice = input(translations[current_language]['language_prompt'])
        if lang_choice.lower() == 'e':
            new_language = 'en'
        elif lang_choice.lower() == 'c':
            new_language = 'zh'
        else:
            print(translations[current_language]['invalid_language'])
            return  # 返回设置菜单或退出

        if new_language != current_language:
            change_language(new_language)
    show_main_menu()  # 设置完成后返回主菜单
def select_file():
    file_path = filedialog.askopenfilename(title=translations[current_language]['select_file'])
    return file_path

def select_output_file():
    file_path = filedialog.asksaveasfilename(title=translations[current_language]['select_output_file'])
    return file_path

def select_key_file():
    file_path = filedialog.askopenfilename(title=translations[current_language]['select_key_file'])
    return file_path

def show_main_menu():
    # 提示用户选择
    operation_choice = input(translations[current_language]['choose_operation'])
    if operation_choice.lower() == 'e':
        input_file = select_file()
        if not input_file:  # 检查是否选择了文件
            print(translations[current_language]['no_file_selected'])
            return

        output_directory = os.path.dirname(input_file)
        file_name_without_extension = os.path.splitext(os.path.basename(input_file))[0]

        output_file = os.path.join(output_directory, file_name_without_extension + ".bin")
        key_salt_file = os.path.join(output_directory, file_name_without_extension + "_key.bin")

        salt, password = encrypt_file(input_file, output_file)  # 调整了返回值的接收方式
        generate_key_salt_file(key_salt_file, salt, password)  # 使用返回的salt和password生成键盐文件

        print(
            f"{translations[current_language]['encryption_successful']}\nEncrypted File: {output_file}\nKey File: {key_salt_file}")

    elif operation_choice.lower() == 'd':
        input_file = select_file()
        if not input_file:
            print(translations[current_language]['no_file_selected'])
            return
        key_file = select_key_file()
        if not key_file:  # 检查是否选择密钥文件
            print(translations[current_language]['no_key_file_selected'])
            return
        output_file = select_output_file()  # 让用户选择输出文件的位置和名称
        if not output_file:  # 检查是否选择输出文件
            print(translations[current_language]['no_output_file_selected'])
            return
        decrypt_file(input_file, output_file, key_file) 
        print(translations[current_language]['decryption_successful'])
    elif operation_choice.lower() == 's':
        show_settings_panel()
    else:
        print(translations[current_language]['invalid_operation'])
    show_main_menu()

def show_settings_panel():
    print(translations[current_language]['settings_panel'])
    print(translations[current_language]['language_preference'])
    choice = input(translations[current_language]['enter_choice'])
    if choice == '1':
        adjust_settings()
    else:
        print("Invalid choice.")


def main():
    global current_language
    # 尝试加载之前保存的语言偏好
    saved_language = load_language_preference()
    if saved_language:
        current_language = saved_language
    else:
        # 如果没有找到保存的语言偏好，提示用户选择语言
        lang_choice = input("Please choose a language (e for English, c for Chinese): ")
        if lang_choice.lower() == 'e':
            new_language = 'en'
        elif lang_choice.lower() == 'c':
            new_language = 'zh'
        else:
            print("Invalid language choice.")
            exit()
        # 保存用户选择的语言偏好
        save_language_preference(new_language)
        current_language = new_language

    # 检查是否已经接受过条款
    if not os.path.isfile("terms_accepted.txt"):
        show_terms_window()
    else:
        # 条款已接受
        show_main_menu()

if __name__ == "__main__":
    main()
