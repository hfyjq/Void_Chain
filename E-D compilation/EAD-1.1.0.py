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
    },
    'zh': {
        'operation_prompt': "选择操作，加密(E) 或 解密(D): ",
        'no_file_selected': "未选择文件！程序退出。",
        'encryption_successful': "文件加密成功！",
        'no_key_file_selected': "未选择密钥文件，无法解密。",
        'decryption_successful': "文件解密成功！",
        'terms_and_conditions': "条款和条件：",
        'terms_content': "请在使用本软件之前阅读并同意条款和条件。",
        'terms_agree': "我同意条款和条件",
        'terms_disagree': "我不同意",
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
    # Create terms window
    terms_window = tk.Toplevel()
    terms_window.title(translations[current_language]['terms_and_conditions'])
    terms_window.geometry("500x400")
    terms_window.resizable(False, False)
    terms_window.focus_set()
    # Center the terms window
    window_width = terms_window.winfo_reqwidth()
    window_height = terms_window.winfo_reqheight()
    position_right = int(terms_window.winfo_screenwidth() / 2 - window_width / 2)
    position_down = int(terms_window.winfo_screenheight() / 2 - window_height / 2)
    terms_window.geometry(f"+{position_right}+{position_down}")
    # Terms content
    terms_label = tk.Label(terms_window, text=translations[current_language]['terms_content'], pady=20)
    terms_label.pack()

    def agree_terms():
        with open("terms_accepted.txt", 'w') as f:
            f.write('Terms Accepted')
        terms_window.destroy()
        main()  # Continue to main function after agreeing to terms

    def disagree_terms():
        messagebox.showinfo("Exit", "You have not agreed to the terms and conditions. Program exiting.")
        terms_window.destroy()
        exit()

    # Agree and disagree buttons
    agree_button = tk.Button(terms_window, text=translations[current_language]['terms_agree'], width=20, command=agree_terms)
    agree_button.pack(pady=10)
    disagree_button = tk.Button(terms_window, text=translations[current_language]['terms_disagree'], width=20, command=disagree_terms)
    disagree_button.pack(pady=5)

    # Run the terms window
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
    # 提示用户选择操作
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
        if not key_file:  # 检查是否选择了密钥文件
            print(translations[current_language]['no_key_file_selected'])
            return
        output_file = select_output_file()  # 让用户选择输出文件的位置和名称
        if not output_file:  # 检查是否选择了输出文件
            print(translations[current_language]['no_output_file_selected'])
            return
        decrypt_file(input_file, output_file, key_file)  # 正确调用decrypt_file函数
        print(translations[current_language]['decryption_successful'])
    elif operation_choice.lower() == 's':
        adjust_settings()
    else:
        print(translations[current_language]['invalid_operation'])
    show_main_menu()
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
        # 条款已接受，显示主菜单
        show_main_menu()

if __name__ == "__main__":
    main()