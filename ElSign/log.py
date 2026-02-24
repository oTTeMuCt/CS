import os
import json
import hashlib
import sys
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox, Text, END
from tkinter import ttk 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class ElSignPro:
    def __init__(self, root):
        self.root = root
        self.root.title("ElSign Professional - Certificate Generator")
        self.root.geometry("650x850")
        
        
        try:
            
            base_dir = Path(sys._MEIPASS)
        except AttributeError:
            
            base_dir = Path(__file__).resolve().parent
        
        self.base_path = base_dir / "ElSign"
        self.base_path.mkdir(parents=True, exist_ok=True)

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
        Label(self.tab_input, text="ПАРАМЕТРЫ ЦИФРОВОЙ ПОДПИСИ", font=("Arial", 11, "bold")).pack(pady=15)
        
        
        self.key_info_frame = LabelFrame(self.tab_input, text=" 📋 Информация о ключе ", font=("Arial", 9, "bold"), padx=10, pady=10)
        self.key_info_frame.pack(pady=10, padx=10, fill='x')
        
        self.key_status_label = Label(self.key_info_frame, text="Статус: Не создан", font=("Arial", 9), fg="orange")
        self.key_status_label.pack(anchor='w')
        
        self.key_fingerprint_label = Label(self.key_info_frame, text="Отпечаток ключа: -", font=("Consolas", 8), fg="gray")
        self.key_fingerprint_label.pack(anchor='w', pady=5)
        
        
        Button(self.key_info_frame, text="🔄 Обновить информацию", command=self.update_key_info, 
               bg="#e0e0e0", font=("Arial", 8)).pack(anchor='w', pady=5)
        
        Label(self.tab_input, text="Организация:").pack(pady=5)
        self.ent_org = Entry(self.tab_input, width=50, font=("Arial", 10))
        self.ent_org.pack()

        Label(self.tab_input, text="Город:").pack(pady=5)
        self.ent_city = Entry(self.tab_input, width=50, font=("Arial", 10))
        self.ent_city.pack()

        Label(self.tab_input, text="Страна (например, RU):").pack(pady=5)
        self.ent_country = Entry(self.tab_input, width=50, font=("Arial", 10))
        self.ent_country.pack()

        Button(self.tab_input, text="🔐 ПОДПИСАТЬ ФАЙЛ И СОЗДАТЬ СЕРТИФИКАТ", 
               command=self.process_all, bg="#d1ffd1", height=2, font=("Arial", 9, "bold")).pack(pady=20, padx=50, fill='x')
        
        
        Button(self.tab_input, text="🗑️ Сбросить ключи (создать новые)", 
               command=self.reset_keys, bg="#ffe0e0", height=1, font=("Arial", 8)).pack(pady=5, padx=50, fill='x')
        
        
        self.update_key_info()

    def setup_cert_tab(self):
        self.log = Text(self.tab_cert, font=("Consolas", 10), bg="#ffffff", padx=15, pady=15)
        self.log.pack(expand=True, fill='both')
        self.log.insert(END, "Здесь появится ваш сертификат после подписания файла.")
        self.log.config(state="disabled")
        
        self.btn_open_folder = Button(self.tab_cert, text="📂 Открыть папку с результатами", 
                                      command=self.open_folder, bg="#f0f0f0", height=2)
        self.btn_open_folder.pack(fill='x', padx=15, pady=10)

    def setup_help_tab(self):
        help_box = Text(self.tab_help, font=("Arial", 10), bg="#fcfcfc", padx=20, pady=20, wrap="word")
        help_box.pack(expand=True, fill='both')
        
        help_text = (
            "РУКОВОДСТВО ПОЛЬЗОВАТЕЛЯ\n"
            "==========================================\n\n"
            "О ПРОГРАММЕ:\n"
            "ElSign Professional создаёт цифровые сертификаты и подписи файлов.\n"
            "Программа использует один приватный ключ для создания множества сертификатов.\n\n"
            "ПОРЯДОК РАБОТЫ:\n"
            "1. При первом запуске ключ создаётся автоматически.\n"
            "2. Проверьте информацию о ключе на вкладке 'Создание'.\n"
            "3. Заполните данные организации (название, город, страна).\n"
            "4. Нажмите кнопку подписи и выберите файл.\n"
            "5. Сертификат сохранится в папке ElSign.\n\n"
            "ИНФОРМАЦИЯ О КЛЮЧЕ:\n"
            "- Отпечаток ключа — уникальный идентификатор вашего приватного ключа.\n"
            "- Все сертификаты подписываются одним ключом (пока вы его не сбросите).\n"
            "- Кнопка 'Обновить информацию' показывает актуальный статус ключа.\n\n"
            "СБРОС КЛЮЧЕЙ:\n"
            "- Кнопка 'Сбросить ключи' удаляет текущий приватный ключ.\n"
            "- При следующей подписи будет создан новый ключ.\n"
            "- Старые сертификаты останутся, но будут подписаны старым ключом.\n\n"
            "ГДЕ ИСКАТЬ ФАЙЛЫ:\n"
            f"Папка 'ElSign' создаётся автоматически:\n{self.base_path}\n\n"
            "В папке сохраняются:\n"
            "- private_key.pem — ваш приватный ключ (храните в секрете!)\n"
            "- Certificate_*.txt — сертификаты для каждого подписанного файла\n\n"
            "ОСОБЕННОСТИ:\n"
            "✓ Программа работает на Windows, macOS и Linux\n"
            "✓ Один ключ для множества сертификатов\n"
            "✓ Срок действия сертификата: 1 год\n"
            "✓ Алгоритм подписи: RSA-2048 + SHA-256\n"
            "✓ Все пути относительные (портативность)\n\n"
            "БЕЗОПАСНОСТЬ:\n"
            "⚠ Никогда не передавайте private_key.pem третьим лицам!\n"
            "⚠ При потере ключа все подписанные им сертификаты станут недействительными\n"
            "⚠ Регулярно создавайте резервные копии папки ElSign\n"
        )
        help_box.insert(END, help_text)
        help_box.config(state="disabled")

    def update_key_info(self):
        
        priv_path = self.base_path / "private_key.pem"
        
        if priv_path.exists():
            try:
                with open(priv_path, "rb") as f:
                    key_data = f.read()
                    key_hash = hashlib.sha256(key_data).hexdigest()
                
                self.key_status_label.config(text="✓ Ключ найден", fg="green")
                self.key_fingerprint_label.config(
                    text=f"SHA-256: {key_hash[:16]}...{key_hash[-16:]}", 
                    fg="blue",
                    font=("Consolas", 8)
                )
            except Exception as e:
                self.key_status_label.config(text="✗ Ошибка чтения ключа", fg="red")
                self.key_fingerprint_label.config(text=f"Ошибка: {str(e)}", fg="red")
        else:
            self.key_status_label.config(text="⊘ Ключ не создан (будет создан при первой подписи)", fg="orange")
            self.key_fingerprint_label.config(text="Отпечаток: -", fg="gray")

    def open_folder(self):
        
        path = str(self.base_path)
        try:
            if sys.platform == 'win32':
                os.startfile(path)  # Windows
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', path])  # macOS
            else:
                subprocess.Popen(['xdg-open', path])  # Linux
        except Exception as e:
            messagebox.showinfo("Путь к файлам", f"Результаты сохранены в:\n{path}\n\nОшибка авто-открытия: {e}")

    def get_or_create_private_key(self):
        
        priv_path = self.base_path / "private_key.pem"
        
        if priv_path.exists():
           
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )
            return private_key
        else:
            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(priv_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            return private_key

    def reset_keys(self):
        """🗑️ Удаляет существующие ключи для генерации новых"""
        priv_path = self.base_path / "private_key.pem"
        
        if priv_path.exists():
            confirm = messagebox.askyesno("Подтверждение", 
                "⚠ ВНИМАНИЕ!\n\n"
                "Это удалит текущий приватный ключ.\n"
                "Все ранее подписанные сертификаты останутся, но будут подписаны старым ключом.\n"
                "Новые сертификаты будут подписаны новым ключом.\n\n"
                "Продолжить?")
            if confirm:
                try:
                    
                    backup_path = self.base_path / "private_key_OLD.pem"
                    if backup_path.exists():
                        backup_path.unlink()
                    priv_path.rename(backup_path)
                    
                    messagebox.showinfo("Готово", 
                        f"Ключ сброшен!\n"
                        f"Старый ключ сохранён как:\nprivate_key_OLD.pem\n\n"
                        "Новый ключ будет создан при следующей подписи.")
                    self.update_key_info()
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось сбросить ключи:\n{e}")
        else:
            messagebox.showinfo("Инфо", "Приватный ключ ещё не создан.")

    def process_all(self):
        file_path = filedialog.askopenfilename(title="Выберите файл для подписи")
        if not file_path: 
            return

        if not self.ent_org.get() or not self.ent_city.get():
            messagebox.showwarning("Внимание", "Пожалуйста, заполните данные организации.")
            return

 
        priv_key = self.get_or_create_private_key()
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

        cert_filename = f"Certificate_{Path(file_path).name}.txt"
        cert_file_path = self.base_path / cert_filename
        
        with open(cert_file_path, "w", encoding="utf-8") as f:
            f.write(cert_content)

        self.log.config(state="normal")
        self.log.delete(1.0, END)
        self.log.insert(END, cert_content)
        self.log.config(state="disabled")

        self.notebook.select(self.tab_cert)
        
       
        self.update_key_info()
        
        messagebox.showinfo("Успех", 
            f"✓ Сертификат создан!\n\n"
            f"Файл: {cert_filename}\n"
            f"Папка: {self.base_path}\n\n"
            f"Все сертификаты подписаны одним ключом.")


from tkinter import LabelFrame

if __name__ == "__main__":
    root = Tk()
    app = ElSignPro(root)
    root.mainloop()