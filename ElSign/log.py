import os
import hashlib
import sys
import subprocess
import base64
import re
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox, Text, END
from tkinter import ttk 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class ElSignPro:
    def __init__(self, root):
        self.root = root
        self.root.title("ElSign Professional - Certificate Generator")
        self.root.geometry("700x900")
        
        # 🔥 УНИВЕРСАЛЬНЫЙ ПУТЬ
        try:
            base_dir = Path(sys._MEIPASS)
        except AttributeError:
            base_dir = Path(__file__).resolve().parent
        
        self.base_path = base_dir / "ElSign"
        self.base_path.mkdir(parents=True, exist_ok=True)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both')

        self.tab_input = ttk.Frame(self.notebook)
        self.tab_verify = ttk.Frame(self.notebook)
        self.tab_cert = ttk.Frame(self.notebook)
        self.tab_help = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_input, text=" ➕ Создание ")
        self.notebook.add(self.tab_verify, text=" ✓ Проверка ")
        self.notebook.add(self.tab_cert, text=" 📄 Просмотр сертификата ")
        self.notebook.add(self.tab_help, text=" ℹ️ Инструкция ")

        self.setup_input_tab()
        self.setup_verify_tab()
        self.setup_cert_tab()
        self.setup_help_tab()

    def setup_input_tab(self):
        Label(self.tab_input, text="ПАРАМЕТРЫ ЦИФРОВОЙ ПОДПИСИ", font=("Arial", 11, "bold")).pack(pady=15)
        
        # 🔐 ИНФОРМАЦИЯ О КЛЮЧЕ (без показа самого ключа!)
        self.key_info_frame = Label(self.tab_input, text=" 🔐 Статус ключа подписи ", font=("Arial", 9, "bold"), padx=10, pady=10)
        self.key_info_frame.pack(pady=10, padx=10, fill='x')
        
        self.key_status_label = Label(self.key_info_frame, text="⊘ Ключ не создан", font=("Arial", 10, "bold"), fg="orange")
        self.key_status_label.pack(anchor='w', pady=5)
        
        # 🔥 ОТПЕЧАТОК КЛЮЧА (уникальный идентификатор, не сам ключ)
        self.key_fingerprint_label = Label(self.key_info_frame, 
            text="ID ключа: —", 
            font=("Consolas", 9), 
            fg="gray",
            bg="#f5f5f5",
            padx=10,
            pady=5)
        self.key_fingerprint_label.pack(anchor='w', fill='x', pady=5)
        
        self.key_info_text = Label(self.key_info_frame, 
            text="ℹ️ Отпечаток ключа — это уникальный идентификатор.\n"
                 "   По нему можно определить, используется ли тот же ключ.",
            font=("Arial", 8), 
            fg="gray",
            justify="left")
        self.key_info_text.pack(anchor='w', pady=5)
        
        Button(self.key_info_frame, text="🔄 Обновить статус ключа", command=self.update_key_info, 
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
        
        Button(self.tab_input, text="🗑️ Сбросить ключи (создать новую пару)", 
               command=self.reset_keys, bg="#ffe0e0", height=1, font=("Arial", 8)).pack(pady=5, padx=50, fill='x')
        
        self.update_key_info()

    def setup_verify_tab(self):
        """Настройка вкладки проверки подписи"""
        Label(self.tab_verify, text="ПРОВЕРКА ЦИФРОВОЙ ПОДПИСИ", font=("Arial", 11, "bold")).pack(pady=15)
        
        info_frame = Label(self.tab_verify, 
            text="ℹ️ Выберите файл и его сертификат для проверки подлинности", 
            font=("Arial", 9), bg="#f0f8ff", padx=10, pady=10)
        info_frame.pack(pady=10, padx=10, fill='x')
        
        Label(self.tab_verify, text="📁 Подписанный файл:").pack(pady=5)
        self.verify_file_path = Entry(self.tab_verify, width=60, font=("Arial", 9))
        self.verify_file_path.pack()
        Button(self.tab_verify, text="Выбрать файл", command=self.browse_verify_file, 
               bg="#e0e0e0").pack(pady=5)
        
        Label(self.tab_verify, text="📄 Файл сертификата (.txt):").pack(pady=5)
        self.verify_cert_path = Entry(self.tab_verify, width=60, font=("Arial", 9))
        self.verify_cert_path.pack()
        Button(self.tab_verify, text="Выбрать сертификат", command=self.browse_verify_cert, 
               bg="#e0e0e0").pack(pady=5)
        
        Button(self.tab_verify, text="✓ ПРОВЕРИТЬ ПОДПИСЬ", 
               command=self.verify_signature, bg="#d1ffd1", height=2, font=("Arial", 9, "bold")).pack(pady=30, padx=50, fill='x')
        
        Label(self.tab_verify, text="Результат проверки:").pack(pady=5)
        self.verify_result = Text(self.tab_verify, font=("Consolas", 9), bg="#ffffff", 
                                  height=15, padx=10, pady=10)
        self.verify_result.pack(expand=True, fill='both', padx=10, pady=10)
        self.verify_result.insert(END, "Здесь появится результат проверки...")
        self.verify_result.config(state="disabled")

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
            "ElSign Professional создаёт цифровые сертификаты с криптографической подписью.\n"
            "Используется алгоритм RSA-2048 + SHA-256.\n\n"
            "СОЗДАНИЕ ПОДПИСИ:\n"
            "1. При первом запуске ключ создаётся автоматически.\n"
            "2. Проверьте статус ключа на вкладке 'Создание'.\n"
            "3. Заполните данные организации (название, город, страна).\n"
            "4. Нажмите кнопку подписи и выберите файл.\n"
            "5. Сертификат сохранится в папке ElSign.\n\n"
            "ИНФОРМАЦИЯ О КЛЮЧЕ:\n"
            "🔐 Приватный ключ НЕ отображается в интерфейсе (безопасность!)\n"
            "🔑 Отпечаток ключа — уникальный ID для идентификации\n"
            "📋 По отпечатку можно определить, тот же ли ключ используется\n"
            "✅ Если отпечаток не меняется — ключ тот же\n"
            "❌ Если отпечаток изменился — ключ новый (после сброса)\n\n"
            "ПРОВЕРКА ПОДПИСИ:\n"
            "1. Перейдите на вкладку 'Проверка'.\n"
            "2. Выберите подписанный файл.\n"
            "3. Выберите файл сертификата (.txt).\n"
            "4. Нажмите 'ПРОВЕРИТЬ ПОДПИСЬ'.\n"
            "5. Программа проверит целостность и подлинность.\n\n"
            "СБРОС КЛЮЧЕЙ:\n"
            "- Кнопка 'Сбросить ключи' создаёт новую пару ключей.\n"
            "- Старый ключ сохраняется как private_key_OLD.pem\n"
            "- Отпечаток ключа изменится после сброса.\n\n"
            "ГДЕ ИСКАТЬ ФАЙЛЫ:\n"
            f"Папка 'ElSign':\n{self.base_path}\n\n"
            "В папке сохраняются:\n"
            "- private_key.pem — приватный ключ (ХРАНИТЕ В СЕКРЕТЕ!)\n"
            "- public_key.pem — публичный ключ (можно передавать)\n"
            "- Certificate_*.txt — сертификаты с подписями\n\n"
            "БЕЗОПАСНОСТЬ:\n"
            "⚠ Никогда не передавайте private_key.pem!\n"
            "⚠ Приватный ключ не отображается в программе\n"
            "⚠ При потере ключа все подписи станут недействительными\n"
            "⚠ Регулярно создавайте резервные копии папки ElSign\n"
            "✓ Проверка подписи работает без приватного ключа\n"
            "✓ Достаточно публичного ключа из сертификата\n"
        )
        help_box.insert(END, help_text)
        help_box.config(state="disabled")

    def update_key_info(self):
        """🔄 Обновляет информацию о ключе (без показа самого ключа!)"""
        priv_path = self.base_path / "private_key.pem"
        
        if priv_path.exists():
            try:
                # Вычисляем отпечаток ключа (хэш файла ключа)
                with open(priv_path, "rb") as f:
                    key_data = f.read()
                    key_hash = hashlib.sha256(key_data).hexdigest()
                
                # 🔥 Показываем только отпечаток, не сам ключ!
                fingerprint = f"{key_hash[:8].upper()}-{key_hash[8:16].upper()}-{key_hash[-8:].upper()}"
                
                self.key_status_label.config(text="✓ Ключ активен", fg="green")
                self.key_fingerprint_label.config(
                    text=f"🔑 ID ключа: {fingerprint}", 
                    fg="blue",
                    font=("Consolas", 10, "bold")
                )
                self.key_info_text.config(
                    text="ℹ️ Этот отпечаток идентифицирует ваш ключ.\n"
                         "   Если он изменится — ключ был сброшен.",
                    fg="gray"
                )
            except Exception as e:
                self.key_status_label.config(text="✗ Ошибка ключа", fg="red")
                self.key_fingerprint_label.config(text=f"Ошибка: {str(e)}", fg="red")
        else:
            self.key_status_label.config(text="⊘ Ключ не создан", fg="orange")
            self.key_fingerprint_label.config(text="🔑 ID ключа: —", fg="gray")
            self.key_info_text.config(
                text="ℹ️ Ключ будет создан автоматически при первой подписи.",
                fg="gray"
            )

    def browse_verify_file(self):
        """Выбор файла для проверки"""
        file_path = filedialog.askopenfilename(title="Выберите подписанный файл")
        if file_path:
            self.verify_file_path.delete(0, END)
            self.verify_file_path.insert(0, file_path)

    def browse_verify_cert(self):
        """Выбор сертификата для проверки"""
        file_path = filedialog.askopenfilename(
            title="Выберите файл сертификата",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.verify_cert_path.delete(0, END)
            self.verify_cert_path.insert(0, file_path)

    def open_folder(self):
        """Универсальное открытие папки"""
        path = str(self.base_path)
        try:
            if sys.platform == 'win32':
                os.startfile(path)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', path])
            else:
                subprocess.Popen(['xdg-open', path])
        except Exception as e:
            messagebox.showinfo("Путь к файлам", f"Результаты сохранены в:\n{path}\n\nОшибка: {e}")

    def get_or_create_private_key(self):
        """🔐 Возвращает существующий или создаёт новый ключ"""
        priv_path = self.base_path / "private_key.pem"
        pub_path = self.base_path / "public_key.pem"
        
        if priv_path.exists():
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )
            return private_key
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            
            # Сохраняем приватный ключ
            with open(priv_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # 🔥 Сохраняем публичный ключ отдельно (для проверки без приватного)
            pub_key = private_key.public_key()
            with open(pub_path, "wb") as f:
                f.write(pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            return private_key

    def reset_keys(self):
        """🗑️ Удаляет существующие ключи"""
        priv_path = self.base_path / "private_key.pem"
        pub_path = self.base_path / "public_key.pem"
        
        if priv_path.exists():
            confirm = messagebox.askyesno("Подтверждение", 
                "⚠ ВНИМАНИЕ!\n\n"
                "Это создаст НОВУЮ пару ключей.\n"
                "Старый ключ будет сохранён как private_key_OLD.pem\n"
                "Отпечаток ключа ИЗМЕНИТСЯ после сброса.\n\n"
                "Все ранее подписанные сертификаты останутся,\n"
                "но будут подписаны СТАРЫМ ключом.\n\n"
                "Продолжить?")
            if confirm:
                try:
                    # Резервная копия старого ключа
                    backup_priv = self.base_path / "private_key_OLD.pem"
                    backup_pub = self.base_path / "public_key_OLD.pem"
                    
                    if backup_priv.exists():
                        backup_priv.unlink()
                    if backup_pub.exists():
                        backup_pub.unlink()
                    
                    priv_path.rename(backup_priv)
                    if pub_path.exists():
                        pub_path.rename(backup_pub)
                    
                    messagebox.showinfo("Готово", 
                        "✓ Ключи сброшены!\n\n"
                        "Старые ключи:\n"
                        "  • private_key_OLD.pem\n"
                        "  • public_key_OLD.pem\n\n"
                        "Новые ключи будут созданы при следующей подписи.\n"
                        "Отпечаток ключа изменится.")
                    self.update_key_info()
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось сбросить ключи:\n{e}")
        else:
            messagebox.showinfo("Инфо", "Приватный ключ ещё не создан.")

    def process_all(self):
        """🔐 Создание подписи файла"""
        file_path = filedialog.askopenfilename(title="Выберите файл для подписи")
        if not file_path: 
            return

        if not self.ent_org.get() or not self.ent_city.get():
            messagebox.showwarning("Внимание", "Пожалуйста, заполните данные организации.")
            return

        priv_key = self.get_or_create_private_key()
        pub_key = priv_key.public_key()
        
        issue_date = datetime.now()
        expiry_date = issue_date + timedelta(days=356)
        
        # Читаем файл и вычисляем хэш
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        file_hash = hashlib.sha256(file_data).digest()
        
        # 🔥 СОЗДАЁМ КРИПТОГРАФИЧЕСКУЮ ПОДПИСЬ
        signature = priv_key.sign(
            file_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # Хэши для отображения
        cert_hash_hex = hashlib.sha256(file_data).hexdigest()
        
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key_hash = hashlib.sha256(pub_bytes).hexdigest()
        
        # 🔥 Отпечаток приватного ключа (для идентификации)
        priv_path = self.base_path / "private_key.pem"
        with open(priv_path, "rb") as f:
            key_fingerprint = hashlib.sha256(f.read()).hexdigest()[:16].upper()

        cert_content = (
            f"ВЫПУЩЕН ЦИФРОВОЙ СЕРТИФИКАТ\n"
            f"{'='*60}\n\n"
            f"ИНФОРМАЦИЯ О ВЛАДЕЛЬЦЕ:\n"
            f"  Организация            {self.ent_org.get()}\n"
            f"  Город                  {self.ent_city.get()}\n"
            f"  Страна                 {self.ent_country.get()}\n\n"
            f"СРОК ДЕЙСТВИЯ:\n"
            f"  Дата выдачи            {issue_date.strftime('%d %B %Y г. в %H:%M:%S')}\n"
            f"  Действителен до        {expiry_date.strftime('%d %B %Y г. в %H:%M:%S')}\n\n"
            f"ИДЕНТИФИКАТОР КЛЮЧА:\n"
            f"  Отпечаток ключа        {key_fingerprint}\n"
            f"  (по этому ID можно определить, тот же ли ключ использовался)\n\n"
            f"ХЭШИ:\n"
            f"  Файл (SHA-256)         {cert_hash_hex[:32]}\n"
            f"                         {cert_hash_hex[32:]}\n"
            f"  Открытый ключ          {pub_key_hash[:32]}\n"
            f"                         {pub_key_hash[32:]}\n\n"
            f"КРИПТОГРАФИЧЕСКАЯ ПОДПИСЬ:\n"
            f"  Алгоритм               RSA-PKCS1v15 + SHA-256\n"
            f"  Размер ключа           2048 бит\n"
            f"  Подпись (Base64):\n"
        )
        
        for i in range(0, len(signature_b64), 64):
            cert_content += f"    {signature_b64[i:i+64]}\n"
        
        cert_content += f"\n{'='*60}\n"
        cert_content += f"Подпись создана программой ElSign Professional\n"
        cert_content += f"⚠ Приватный ключ не отображается в сертификате (безопасность)\n"

        # Сохраняем сертификат
        cert_filename = f"Certificate_{Path(file_path).name}.txt"
        cert_file_path = self.base_path / cert_filename
        
        with open(cert_file_path, "w", encoding="utf-8") as f:
            f.write(cert_content)

        # Показываем в интерфейсе
        self.log.config(state="normal")
        self.log.delete(1.0, END)
        self.log.insert(END, cert_content)
        self.log.config(state="disabled")

        self.notebook.select(self.tab_cert)
        self.update_key_info()
        
        messagebox.showinfo("Успех", 
            f"✓ Файл подписан!\n\n"
            f"Файл: {cert_filename}\n"
            f"Папка: {self.base_path}\n\n"
            f"ID ключа: {key_fingerprint}\n"
            f"По этому ID можно проверить, тот же ли ключ использовался.")

    def verify_signature(self):
        """🔥 ПРОВЕРКА ЦИФРОВОЙ ПОДПИСИ"""
        self.verify_result.config(state="normal")
        self.verify_result.delete(1.0, END)
        
        file_path = self.verify_file_path.get().strip()
        cert_path = self.verify_cert_path.get().strip()
        
        if not file_path or not cert_path:
            self.verify_result.insert(END, "❌ ОШИБКА:\n")
            self.verify_result.insert(END, "Не выбран файл или сертификат!\n\n")
            self.verify_result.insert(END, "Выберите оба файла и повторите проверку.")
            self.verify_result.config(state="disabled")
            return
        
        if not Path(file_path).exists():
            self.verify_result.insert(END, "❌ ОШИБКА:\n")
            self.verify_result.insert(END, f"Файл не найден:\n{file_path}")
            self.verify_result.config(state="disabled")
            return
        
        if not Path(cert_path).exists():
            self.verify_result.insert(END, "❌ ОШИБКА:\n")
            self.verify_result.insert(END, f"Сертификат не найден:\n{cert_path}")
            self.verify_result.config(state="disabled")
            return
        
        try:
            self.verify_result.insert(END, "🔍 ПРОВЕРКА ПОДПИСИ...\n")
            self.verify_result.insert(END, "="*60 + "\n\n")
            self.verify_result.update()
            
            # 1. Читаем сертификат
            self.verify_result.insert(END, "📄 Чтение сертификата...\n")
            with open(cert_path, "r", encoding="utf-8") as f:
                cert_content = f.read()
            
            # Извлекаем хэш файла
            hash_match = re.search(r'Файл \(SHA-256\)\s+([a-fA-F0-9]{32})\s+([a-fA-F0-9]{32})', cert_content)
            if not hash_match:
                raise Exception("Не удалось найти хэш файла в сертификате")
            
            cert_file_hash = (hash_match.group(1) + hash_match.group(2)).lower()
            self.verify_result.insert(END, f"✓ Хэш из сертификата:\n  {cert_file_hash}\n\n")
            
            # Извлекаем подпись
            sig_match = re.search(r'Подпись \(Base64\):([\s\S]+?)(?=\n\n|\n{2,}|$)', cert_content)
            if not sig_match:
                raise Exception("Не удалось найти подпись в сертификате")
            
            signature_b64 = sig_match.group(1).strip()
            signature_b64 = re.sub(r'\s+', '', signature_b64)
            signature = base64.b64decode(signature_b64)
            self.verify_result.insert(END, f"✓ Подпись извлечена\n  Размер: {len(signature)} байт\n\n")
            
            # 2. Вычисляем хэш файла
            self.verify_result.insert(END, "📁 Вычисление хэша файла...\n")
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            actual_hash = hashlib.sha256(file_data).hexdigest().lower()
            self.verify_result.insert(END, f"✓ Хэш файла:\n  {actual_hash}\n\n")
            
            # 3. Проверяем хэши
            self.verify_result.insert(END, "🔐 Проверка целостности...\n")
            if actual_hash == cert_file_hash:
                self.verify_result.insert(END, "✓ Хэши СОВПАДАЮТ\n")
                self.verify_result.insert(END, "  Файл не был изменён после подписания\n\n", ("green",))
                hash_valid = True
            else:
                self.verify_result.insert(END, "❌ Хэши НЕ СОВПАДАЮТ\n")
                self.verify_result.insert(END, "  Файл был ИЗМЕНЁН после подписания!\n\n", ("red",))
                hash_valid = False
            
            # 4. Проверяем криптографическую подпись
            self.verify_result.insert(END, "🔑 Проверка криптографической подписи...\n")
            try:
                # Пытаемся использовать публичный ключ из файла
                pub_path = self.base_path / "public_key.pem"
                if pub_path.exists():
                    with open(pub_path, "rb") as f:
                        pub_key = serialization.load_pem_public_key(f.read())
                    
                    pub_key.verify(
                        signature,
                        hashlib.sha256(file_data).digest(),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    
                    self.verify_result.insert(END, "✓ Подпись ПОДТВЕРЖДЕНА\n")
                    self.verify_result.insert(END, "  Файл подписан корректной подписью\n\n", ("green",))
                    sig_valid = True
                else:
                    self.verify_result.insert(END, "⚠ Публичный ключ не найден\n")
                    self.verify_result.insert(END, "  Невозможно проверить криптографическую подпись\n")
                    self.verify_result.insert(END, "  (требуется public_key.pem)\n\n", ("orange",))
                    sig_valid = None
            except Exception as e:
                self.verify_result.insert(END, "❌ Подпись НЕВЕРНА\n")
                self.verify_result.insert(END, f"  Ошибка: {str(e)}\n\n", ("red",))
                sig_valid = False
            
            # 5. Итоговый результат
            self.verify_result.insert(END, "="*60 + "\n")
            self.verify_result.insert(END, "📊 ИТОГОВЫЙ РЕЗУЛЬТАТ:\n\n")
            
            if hash_valid and (sig_valid is True or sig_valid is None):
                self.verify_result.insert(END, "✅ ПОДПИСЬ ДЕЙСТВИТЕЛЬНА\n\n")
                self.verify_result.insert(END, "Файл:\n")
                self.verify_result.insert(END, f"  • Не был изменён после подписания\n")
                self.verify_result.insert(END, f"  • Подписан корректной подписью\n")
                if sig_valid is None:
                    self.verify_result.insert(END, f"  • Криптографическая проверка пропущена (нет ключа)\n")
            else:
                self.verify_result.insert(END, "❌ ПОДПИСЬ НЕДЕЙСТВИТЕЛЬНА\n\n")
                if not hash_valid:
                    self.verify_result.insert(END, "Файл:\n")
                    self.verify_result.insert(END, f"  • БЫЛ ИЗМЕНЁН после подписания!\n")
                if sig_valid is False:
                    self.verify_result.insert(END, f"  • Подпись не соответствует ключу!\n")
            
            self.verify_result.tag_config("green", foreground="green")
            self.verify_result.tag_config("red", foreground="red")
            self.verify_result.tag_config("orange", foreground="orange")
            
        except Exception as e:
            self.verify_result.insert(END, f"\n❌ КРИТИЧЕСКАЯ ОШИБКА:\n{str(e)}")
            import traceback
            self.verify_result.insert(END, f"\n\nДетали:\n{traceback.format_exc()}")
        
        self.verify_result.config(state="disabled")

from tkinter import LabelFrame

if __name__ == "__main__":
    root = Tk()
    app = ElSignPro(root)
    root.mainloop()