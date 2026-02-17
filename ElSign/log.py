import json
import os
from datetime import datetime
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Цифровая подпись с логгированием")
        self.root.geometry("450x550")

        Label(root, text="Страна:").pack(pady=2)
        self.entry_country = Entry(root, width=40)
        self.entry_country.insert(0, "Россия") # Пример значения по умолчанию
        self.entry_country.pack()

        Label(root, text="Город:").pack(pady=2)
        self.entry_city = Entry(root, width=40)
        self.entry_city.pack()

        Label(root, text="Название организации:").pack(pady=2)
        self.entry_org = Entry(root, width=40)
        self.entry_org.pack()

        Label(root, text="--- Управление ---").pack(pady=10)
        Button(root, text="1. Сгенерировать ключи", command=self.generate_keys, bg="#eee").pack(fill='x', padx=50, pady=2)
        Button(root, text="2. Подписать файл", command=self.sign_file, bg="#d1ffd1").pack(fill='x', padx=50, pady=2)
        Button(root, text="3. Проверить и создать отчет", command=self.verify_file, bg="#d1e7ff").pack(fill='x', padx=50, pady=2)

        self.status_label = Label(root, text="Статус: Готов к работе", fg="blue", font=("Arial", 10, "bold"))
        self.status_label.pack(pady=20)

    def save_report(self, file_name, result):
        """Создает или дополняет файл отчета verification_report.txt"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_data = (
            f"--- Отчет от {timestamp} ---\n"
            f"Файл: {file_name}\n"
            f"Организация: {self.entry_org.get()}\n"
            f"Местоположение: {self.entry_city.get()}, {self.entry_country.get()}\n"
            f"РЕЗУЛЬТАТ: {result}\n"
            f"{'='*30}\n\n"
        )
        with open("verification_report.txt", "a", encoding="utf-8") as f:
            f.write(report_data)

    def get_metadata(self):
        data = {
            "country": self.entry_country.get(),
            "city": self.entry_city.get(),
            "org": self.entry_org.get()
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')

    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        messagebox.showinfo("Успех", "Новые ключи RSA созданы!")

    def sign_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path: return

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None)

            combined_data = file_data + self.get_metadata()
            signature = private_key.sign(
                combined_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            with open(file_path + ".sig", "wb") as f:
                f.write(signature)
            self.status_label.config(text="Статус: Успешно подписано", fg="green")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def verify_file(self):
        file_path = filedialog.askopenfilename(title="Выберите исходный файл")
        if not file_path: return
        sig_path = filedialog.askopenfilename(title="Выберите .sig подпись")
        if not sig_path: return

        file_name = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            with open(sig_path, "rb") as f:
                signature = f.read()
            with open("public_key.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            combined_data = file_data + self.get_metadata()
            public_key.verify(
                signature, combined_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            
            self.status_label.config(text="Статус: ПОДПИСЬ ВЕРНА", fg="green")
            self.save_report(file_name, "УСПЕШНО (Подпись подлинная)")
            messagebox.showinfo("Результат", "Подпись верна. Отчет обновлен.")

        except InvalidSignature:
            self.status_label.config(text="Статус: ОШИБКА ПОДПИСИ", fg="red")
            self.save_report(file_name, "ОТКЛОНЕНО (Данные изменены или неверные ключи)")
            messagebox.showerror("Ошибка", "Подпись не совпадает!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Критический сбой: {e}")

if __name__ == "__main__":
    root = Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()