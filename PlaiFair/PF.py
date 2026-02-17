import customtkinter as ctk
import re

class PlayfairCipher:
    def __init__(self):
        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def prepare_text(self, text, decrypt=False):
        # Очистка текста: только буквы, J -> I
        text = text.upper().replace("J", "I")
        text = re.sub(r'[^A-Z]', '', text)
        
        if decrypt:
            return text

        # Подготовка для шифрования (вставка X между одинаковыми буквами)
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
        matrix = self.generate_matrix(key)
        prepared = self.prepare_text(text, decrypt=(mode == 'decrypt'))
        result = []
        
        # Направление сдвига: +1 для шифрования, -1 для расшифровки
        shift = 1 if mode == 'encrypt' else -1
        
        for i in range(0, len(prepared), 2):
            if i + 1 >= len(prepared): break
            
            r1, c1 = self.find_position(matrix, prepared[i])
            r2, c2 = self.find_position(matrix, prepared[i+1])
            
            if r1 == r2: # Одна строка
                result.append(matrix[r1][(c1 + shift) % 5])
                result.append(matrix[r2][(c2 + shift) % 5])
            elif c1 == c2: # Один столбец
                result.append(matrix[(r1 + shift) % 5][c1])
                result.append(matrix[(r2 + shift) % 5][c2])
            else: # Прямоугольник
                result.append(matrix[r1][c2])
                result.append(matrix[r2][c1])
        
        # Форматирование вывода по 2 буквы
        res_str = "".join(result)
        if mode == 'decrypt':
            # При расшифровке можно убрать лишние X, но обычно оставляют как есть
            return " ".join([res_str[i:i+2] for i in range(0, len(res_str), 2)])
        else:
            return " ".join([res_str[i:i+2] for i in range(0, len(res_str), 2)])

# --- GUI ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.cipher = PlayfairCipher()
        self.title("Playfair Cipher - Tabs Edition")
        self.geometry("600x500")
        ctk.set_appearance_mode("dark")

        # Поле для ключа (общее)
        self.key_label = ctk.CTkLabel(self, text="Ключевое слово (Общее):", font=("Arial", 14, "bold"))
        self.key_label.pack(pady=(10, 0))
        self.entry_key = ctk.CTkEntry(self, width=250, placeholder_text="Введите ключ...")
        self.entry_key.pack(pady=10)
        self.entry_key.insert(0, "WHEATSON")

        # Создание вкладок
        self.tabview = ctk.CTkTabview(self, width=550)
        self.tabview.pack(padx=20, pady=10, expand=True, fill="both")
        
        self.tab_enc = self.tabview.add("Шифрование")
        self.tab_dec = self.tabview.add("Расшифровка")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

    def setup_encrypt_tab(self):
        ctk.CTkLabel(self.tab_enc, text="Исходный текст:").pack(pady=5)
        self.input_enc = ctk.CTkTextbox(self.tab_enc, height=80)
        self.input_enc.pack(fill="x", padx=20)

        self.btn_enc = ctk.CTkButton(self.tab_enc, text="Зашифровать →", command=self.do_encrypt)
        self.btn_enc.pack(pady=15)

        ctk.CTkLabel(self.tab_enc, text="Результат (Биграммы):").pack(pady=5)
        self.output_enc = ctk.CTkTextbox(self.tab_enc, height=80)
        self.output_enc.pack(fill="x", padx=20)

    def setup_decrypt_tab(self):
        ctk.CTkLabel(self.tab_dec, text="Зашифрованный текст:").pack(pady=5)
        self.input_dec = ctk.CTkTextbox(self.tab_dec, height=80)
        self.input_dec.pack(fill="x", padx=20)

        self.btn_dec = ctk.CTkButton(self.tab_dec, text="← Расшифровать", command=self.do_decrypt, fg_color="green", hover_color="darkgreen")
        self.btn_dec.pack(pady=15)

        ctk.CTkLabel(self.tab_dec, text="Результат:").pack(pady=5)
        self.output_dec = ctk.CTkTextbox(self.tab_dec, height=80)
        self.output_dec.pack(fill="x", padx=20)

    def do_encrypt(self):
        key = self.entry_key.get()
        text = self.input_enc.get("1.0", "end-1c")
        res = self.cipher.process(text, key, 'encrypt')
        self.output_enc.delete("1.0", "end")
        self.output_enc.insert("1.0", res)

    def do_decrypt(self):
        key = self.entry_key.get()
        text = self.input_dec.get("1.0", "end-1c")
        res = self.cipher.process(text, key, 'decrypt')
        self.output_dec.delete("1.0", "end")
        self.output_dec.insert("1.0", res)

if __name__ == "__main__":
    app = App()
    app.mainloop()
    