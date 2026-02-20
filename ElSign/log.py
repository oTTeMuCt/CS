import json
import os
import hashlib
import subprocess
from datetime import datetime, timedelta
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox, Text, END
from tkinter import ttk 
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class ElSignPro:
    def __init__(self, root):
        self.root = root
        self.root.title("ElSign Professional - Certificate Generator")
        self.root.geometry("600x750")

        self.base_path = r"os.path.abspath(__file__)"
        if not os.path.exists(self.base_path):
            try:
                os.makedirs(self.base_path)
            except:
                self.base_path = "."

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both')

        self.tab_input = ttk.Frame(self.notebook)
        self.tab_cert = ttk.Frame(self.notebook)
        self.tab_help = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_input, text=" ➕ Создание ")
        self.notebook.add(self.tab_cert, text=" 📄 Просмотр сертификата ")
        self.notebook.add(self.tab_help, text=" ℹ️ Инструкция ")

        self.setup_input_tab()
        self.setup_cert_tab()
        self.setup_help_tab()

    def setup_input_tab(self):
        Label(self.tab_input, text="ПАРАМЕТРЫ ЦИФРОВОЙ ПОДПИСИ", font=("Arial", 11, "bold")).pack(pady=20)
        
        Label(self.tab_input, text="Организация:").pack(pady=5)
        self.ent_org = Entry(self.tab_input, width=45, font=("Arial", 10))
        self.ent_org.pack()

        Label(self.tab_input, text="Город:").pack(pady=5)
        self.ent_city = Entry(self.tab_input, width=45, font=("Arial", 10))
        self.ent_city.pack()

        Label(self.tab_input, text="Страна (например, RU):").pack(pady=5)
        self.ent_country = Entry(self.tab_input, width=45, font=("Arial", 10))
        self.ent_country.pack()

        Button(self.tab_input, text="🔐 ПОДПИСАТЬ ФАЙЛ И СОЗДАТЬ СЕРТИФИКАТ", 
               command=self.process_all, bg="#d1ffd1", height=2, font=("Arial", 9, "bold")).pack(pady=40, padx=50, fill='x')

    def setup_cert_tab(self):
        self.log = Text(self.tab_cert, font=("Consolas", 10), bg="#ffffff", padx=15, pady=15)
        self.log.pack(expand=True, fill='both')
        self.log.insert(END, "Здесь появится ваш сертификат после подписания файла.")
        
        self.btn_open_folder = Button(self.tab_cert, text="📂 Открыть папку ElSign", 
                                      command=self.open_folder, bg="#f0f0f0", height=2)
        self.btn_open_folder.pack(fill='x', padx=15, pady=10)

    def setup_help_tab(self):
        help_box = Text(self.tab_help, font=("Arial", 10), bg="#fcfcfc", padx=20, pady=20, wrap="word")
        help_box.pack(expand=True, fill='both')
        
        help_text = (
            "РУКОВОДСТВО ПОЛЬЗОВАТЕЛЯ\n"
            "==========================================\n\n"
            "1. ВКЛАДКА 'СОЗДАНИЕ':\n"
            "   - Введите название вашей организации, город и страну.\n"
            "   - Нажмите кнопку 'Подписать файл'.\n"
            "   - Выберите документ, который хотите защитить.\n\n"
            "2. ЧТО ПРОИСХОДИТ ПОСЛЕ НАЖАТИЯ:\n"
            "   - Программа создаст пару RSA-ключей (закрытый и открытый).\n"
            "   - Сформирует текстовый сертификат с вашими реквизитами.\n"
            "   - Установит срок действия сертификата на 1 год.\n\n"
            "3. ВКЛАДКА 'ПРОСМОТР':\n"
            "   - Программа автоматически переключит вас сюда.\n"
            "   - Вы увидите цифровые отпечатки (SHA-256) вашего файла.\n\n"
            "4. ХРАНЕНИЕ ФАЙЛОВ:\n"
            "   - Все результаты сохраняются в папку: E:\\КиберБез\\ElSign\n"
            "   - Кнопка внизу вкладки 'Просмотр' поможет быстро открыть папку.\n\n"
            "⚠️ ВНИМАНИЕ: Файл private_key.pem является секретным. "
            "Не передавайте его посторонним лицам!"
        )
        help_box.insert(END, help_text)
        help_box.config(state="disabled")

    def open_folder(self):
        try:
            os.startfile(self.base_path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть папку: {e}")

    def generate_secure_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_path = os.path.join(self.base_path, "private_key.pem")
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        try: os.chmod(priv_path, 0o600) 
        except: pass
        return private_key

    def process_all(self):
        file_path = filedialog.askopenfilename(title="Выберите файл для подписи")
        if not file_path: return

        if not self.ent_org.get() or not self.ent_city.get():
            messagebox.showwarning("Внимание", "Пожалуйста, заполните данные организации.")
            return

        priv_key = self.generate_secure_keys()
        pub_key = priv_key.public_key()
        
        issue_date = datetime(2025, 9, 4, 5, 0, 0)
        expiry_date = issue_date + timedelta(days=356)
        
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        cert_hash = hashlib.sha256(file_data).hexdigest()
        
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key_hash = hashlib.sha256(pub_bytes).hexdigest()

        cert_content = (
            f"Выдан:\n\n"
            f"  Организация            {self.ent_org.get()}\n"
            f"  Город                  {self.ent_city.get()}\n"
            f"  Страна                 {self.ent_country.get()}\n\n"
            f"Выдан:\n\n"
            f"  Общее имя (ЦС)         RapidSSL TLS RSA CA G1\n"
            f"  Организация            DigiCert Inc\n"
            f"  Подразделение          www.digicert.com\n\n"
            f"Срок действия\n\n"
            f"  Дата выдачи            {issue_date.strftime('%A, %d %B %Y г. в %H:%M:%S')}\n"
            f"  Срок действия истекает {expiry_date.strftime('%A, %d %B %Y г. в %H:%M:%S')}\n\n"
            f"Цифровые отпечатки сертификата\n"
            f"с подписью SHA-256\n\n"
            f"  Сертификат             {cert_hash[:32]}\n"
            f"                         {cert_hash[32:]}\n"
            f"  Открытый ключ          {pub_key_hash[:32]}\n"
            f"                         {pub_key_hash[32:]}\n"
        )

        cert_file_path = os.path.join(self.base_path, f"Certificate_{os.path.basename(file_path)}.txt")
        with open(cert_file_path, "w", encoding="utf-8") as f:
            f.write(cert_content)

        self.log.config(state="normal")
        self.log.delete(1.0, END)
        self.log.insert(END, cert_content)

        self.notebook.select(self.tab_cert)
        messagebox.showinfo("Успех", "Сертификат создан и сохранен!")

if __name__ == "__main__":
    root = Tk()
    app = ElSignPro(root)
    root.mainloop()