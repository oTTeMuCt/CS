import customtkinter as ctk
import re

class PlayfairCipher:
    def __init__(self):
        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def prepare_text(self, text, decrypt=False):
        text = text.upper().replace("J", "I")
        text = re.sub(r'[^A-Z]', '', text)
        
        if decrypt:
            return text

        prepared = ""
        i = 0
        while i < len(text):
            a = text[i]
            if i + 1 < len(text):
                b = text[i+1]
                if a == b:
                    prepared += a + 'X'
                    i += 1
                else:
                    prepared += a + b
                    i += 2
            else:
                prepared += a + 'X'
                i += 1
        return prepared

    def generate_matrix(self, key):
        key = key.upper().replace("J", "I")
        key = re.sub(r'[^A-Z]', '', key)
        matrix_flat = []
        for char in key + self.alphabet:
            if char not in matrix_flat:
                matrix_flat.append(char)
        return [matrix_flat[i:i+5] for i in range(0, 25, 5)]

    def find_position(self, matrix, char):
        for r, row in enumerate(matrix):
            if char in row:
                return r, row.index(char)
        return 0, 0

    def process(self, text, key, mode='encrypt'):
        if not key: return "ОШИБКА: Введите ключ"
        matrix = self.generate_matrix(key)
        prepared = self.prepare_text(text, decrypt=(mode == 'decrypt'))
        if not prepared: return ""
        
        result = []
        shift = 1 if mode == 'encrypt' else -1
        
        for i in range(0, len(prepared), 2):
            if i + 1 >= len(prepared): break
            r1, c1 = self.find_position(matrix, prepared[i])
            r2, c2 = self.find_position(matrix, prepared[i+1])
            
            if r1 == r2:
                result.append(matrix[r1][(c1 + shift) % 5])
                result.append(matrix[r2][(c2 + shift) % 5])
            elif c1 == c2:
                result.append(matrix[(r1 + shift) % 5][c1])
                result.append(matrix[(r2 + shift) % 5][c2])
            else:
                result.append(matrix[r1][c2])
                result.append(matrix[r2][c1])
        
        res_str = "".join(result)
        return " ".join([res_str[i:i+2] for i in range(0, len(res_str), 2)])

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.cipher = PlayfairCipher()
        self.title("Playfair Cipher Pro v2.0")
        self.geometry("650x550")
        ctk.set_appearance_mode("dark")

        # Ключ
        self.key_label = ctk.CTkLabel(self, text="КЛЮЧЕВОЕ СЛОВО:", font=("Arial", 13, "bold"))
        self.key_label.pack(pady=(15, 0))
        self.entry_key = ctk.CTkEntry(self, width=300, placeholder_text="Напр: SECRET")
        self.entry_key.pack(pady=10)
        self.entry_key.insert(0, "WHEATSON")

        # Вкладки
        self.tabview = ctk.CTkTabview(self, width=600)
        self.tabview.pack(padx=20, pady=10, expand=True, fill="both")
        
        self.tab_enc = self.tabview.add("Шифрование")
        self.tab_dec = self.tabview.add("Расшифровка")
        self.tab_help = self.tabview.add("Инструкция")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_help_tab()

    def setup_encrypt_tab(self):
        ctk.CTkLabel(self.tab_enc, text="Введите обычный текст:").pack(pady=5)
        self.input_enc = ctk.CTkTextbox(self.tab_enc, height=100)
        self.input_enc.pack(fill="x", padx=20)
        self.btn_enc = ctk.CTkButton(self.tab_enc, text="ЗАШИФРОВАТЬ", command=self.do_encrypt)
        self.btn_enc.pack(pady=15)
        ctk.CTkLabel(self.tab_enc, text="Результат (биграммы):").pack(pady=5)
        self.output_enc = ctk.CTkTextbox(self.tab_enc, height=100)
        self.output_enc.pack(fill="x", padx=20)

    def setup_decrypt_tab(self):
        ctk.CTkLabel(self.tab_dec, text="Введите зашифрованный текст (биграммы):").pack(pady=5)
        self.input_dec = ctk.CTkTextbox(self.tab_dec, height=100)
        self.input_dec.pack(fill="x", padx=20)
        self.btn_dec = ctk.CTkButton(self.tab_dec, text="РАСШИФРОВАТЬ", command=self.do_decrypt, fg_color="#2b8a3e")
        self.btn_dec.pack(pady=15)
        ctk.CTkLabel(self.tab_dec, text="Восстановленный текст:").pack(pady=5)
        self.output_dec = ctk.CTkTextbox(self.tab_dec, height=100)
        self.output_dec.pack(fill="x", padx=20)

    def setup_help_tab(self):
        help_text = (
            "КАК ПОЛЬЗОВАТЬСЯ ПРОГРАММОЙ:\n\n"
            "1. УСТАНОВИТЕ КЛЮЧ: В верхнем поле введите любое латинское слово.\n"
            "   Оно сформирует секретную матрицу 5x5.\n\n"
            "2. ШИФРОВАНИЕ:\n"
            "   • Перейдите на вкладку 'Шифрование'.\n"
            "   • Введите текст на английском языке.\n"
            "   • Нажмите кнопку. Результат разделится на пары букв (биграммы).\n\n"
            "3. РАСШИФРОВКА:\n"
            "   • Скопируйте зашифрованные пары букв.\n"
            "   • Вставьте их во вкладку 'Расшифровка'.\n"
            "   • Убедитесь, что ключ тот же самый, что и при шифровании!\n\n"
            "ОСОБЕННОСТИ ШИФРА:\n"
            "• Буква 'J' всегда заменяется на 'I'.\n"
            "• Если в паре две одинаковые буквы, между ними вставится 'X'.\n"
            "• Пробелы и цифры игнорируются."
        )
        label = ctk.CTkLabel(self.tab_help, text=help_text, justify="left", font=("Arial", 12))
        label.pack(padx=20, pady=20, anchor="nw")

    def do_encrypt(self):
        res = self.cipher.process(self.input_enc.get("1.0", "end-1c"), self.entry_key.get(), 'encrypt')
        self.output_enc.delete("1.0", "end"); self.output_enc.insert("1.0", res)

    def do_decrypt(self):
        res = self.cipher.process(self.input_dec.get("1.0", "end-1c"), self.entry_key.get(), 'decrypt')
        self.output_dec.delete("1.0", "end"); self.output_dec.insert("1.0", res)

if __name__ == "__main__":
    app = App()
    app.mainloop()