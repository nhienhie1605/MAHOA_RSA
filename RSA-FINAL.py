import tkinter as tk
from tkinter import ttk, messagebox, filedialog, PhotoImage
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

class VotingApp:
    def __init__(self, root):
        '''Khởi tạo giao diện chính cho hệ thống'''
        self.root = root
        self.root.title("Hệ thống Bỏ phiếu Trực tuyến")
        self.root.geometry("600x650")
        self.candidates = []
        self.vote_counts = {}  # Initialize vote counts dictionary
        self.result_labels = {}  # To store labels for updating vote counts
        self.style = ttk.Style()
        self.style.theme_use("default")
        self.style.configure("TNotebook.Tab", padding=[10, 4])
        self.style.map("TNotebook.Tab", 
                       background=[("selected", "#8BC34A")], 
                       foreground=[("selected", "white")])
        self.setup_ui()

    def setup_ui(self):
        '''Thiết lập các tab của giao diện'''
        self.main_notebook = ttk.Notebook(self.root)
        self.main_notebook.pack(expand=True, fill="both")
        # Tạo tab chính
        self.vote_tab = tk.Frame(self.main_notebook)
        self.count_tab = ttk.Frame(self.main_notebook)
        self.info_tab = tk.Frame(self.main_notebook)
        self.main_notebook.add(self.vote_tab, text="THẺ BỎ PHIẾU      ")
        self.main_notebook.add(self.count_tab, text="THẺ KIỂM PHIẾU    ")
        self.main_notebook.add(self.info_tab, text="Thông tin chương trình")

        self.style.configure("TNotebook.Tab", font=("Giaothong2", 11,))
        # Tạo sub-tab trong THẺ BỎ PHIẾU
        self.vote_notebook = ttk.Notebook(self.vote_tab)
        self.vote_notebook.pack(expand=True, fill="both")
        self.vote_key_tab = ttk.Frame(self.vote_notebook)
        self.vote_sign_tab = ttk.Frame(self.vote_notebook)
        self.vote_encrypt_tab = ttk.Frame(self.vote_notebook)
        self.vote_notebook.add(self.vote_key_tab,       text="🔑 Sinh khóa bỏ phiếu    ")
        self.vote_notebook.add(self.vote_sign_tab,      text="🦱 Thực hiện ký số         ")
        self.vote_notebook.add(self.vote_encrypt_tab,   text="🔐 Mã hóa bình chọn       ")
        # Tạo sub-tab trong THẺ KIỂM PHIẾU
        self.count_notebook = ttk.Notebook(self.count_tab)
        self.count_notebook.pack(expand=True, fill="both")
        self.count_key_tab = ttk.Frame(self.count_notebook)
        self.count_decrypt_tab = ttk.Frame(self.count_notebook)
        self.count_verify_tab = ttk.Frame(self.count_notebook)
        self.count_result_tab = ttk.Frame(self.count_notebook)  # New sub-tab
        self.count_notebook.add(self.count_key_tab,       text="🔑 Sinh khóa kiểm phiếu")
        self.count_notebook.add(self.count_decrypt_tab,   text="🔓 Giải mã bình chọn       ")
        self.count_notebook.add(self.count_verify_tab,    text="🔍 Xác thực ký số           ")
        self.count_notebook.add(self.count_result_tab,    text="📊 Kết quả bình chọn       ")  # Add new sub-tab
        # Thiết lập giao diện và chức năng
        self.setup_vote_key_tab()
        self.setup_vote_sign_tab()
        self.setup_vote_encrypt_tab()
        self.setup_count_key_tab()
        self.setup_count_decrypt_tab()
        self.setup_count_verify_tab()
        self.setup_count_result_tab()  # Call the new setup method
        self.setup_info_tab()

    def create_file_selector(self, parent, label_text, filetypes, var):
        '''Thiết lập khung chọn file'''
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=5)
        ttk.Label(frame, text=label_text).pack(side="left", padx=5)
        entry = ttk.Entry(frame, textvariable=var, state="readonly")
        entry.pack(side="left", fill="x", expand=True, padx=5)
        return ttk.Button(frame, text="Chọn", command=lambda: self.select_file(var, filetypes, label_text))

    def select_file(self, var, filetypes, title):
        '''Thiết lập chọn file, kiểm tra định dạng và cập nhật đường dẫn'''
        file_path = filedialog.askopenfilename(filetypes=filetypes, title=title)
        if file_path and file_path.endswith(filetypes[0][1][1:]):
            var.set(file_path)
        else:
            messagebox.showerror("Lỗi", f"Vui lòng chọn file {filetypes[0][1][1:]}.")

    def generate_keys(self, pub_key_label, pri_key_label,key_size_var, prefix=""):
        '''Hàm sinh cặp khóa RSA và lưu vào file'''
        key_size_str = key_size_var.get()
        try:
            # Lấy kích thước khóa và tạo cặp khóa RSA
            key_size = int(key_size_str.split()[0])
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            public_key = private_key.public_key()
            # Chuyển đổi khóa sang định dạng PEM.
            private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption())
            public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_filename = f"{prefix}pubkey.pub"
            pri_key_filename = f"{prefix}prikey.pri"
            pub_key_file = filedialog.asksaveasfilename(defaultextension=".pub",
                                                        filetypes=[("Public Key", "*.pub"), ("All files", "*.*")],
                                                        title="Lưu khóa công khai",
                                                        initialfile=pub_key_filename)
            pri_key_file = filedialog.asksaveasfilename(defaultextension=".pri",
                                                        filetypes=[("Private Key", "*.pri"), ("All files", "*.*")],
                                                        title="Lưu khóa bí mật",
                                                        initialfile=pri_key_filename)
            # Cập nhật giao diện với đường dẫn file khóa
            if pub_key_file and pri_key_file:
                with open(pub_key_file, 'wb') as f: f.write(public_pem)
                with open(pri_key_file, 'wb') as f: f.write(private_pem)
                pub_key_label.config(text=f"Khóa công khai: {pub_key_file}")
                pri_key_label.config(text=f"Khóa bí mật: {pri_key_file}")
                messagebox.showinfo("Thành công", "Đã sinh và lưu khóa thành công!")
            else:
                messagebox.showinfo("Hủy", "Hủy lưu khóa.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Đã có lỗi xảy ra: {str(e)}")

    def update_candidate_list(self):
        '''Hàm cập nhật danh sách bình chọn hiển thị'''
        for widget in self.candidate_frame.winfo_children(): 
            widget.destroy()
        candidates = self.candidates if self.candidates else ["Bình chọn A", "Bình chọn B"]
        for i, cand in enumerate(candidates, 1):
            ttk.Radiobutton(self.candidate_frame, text=f"{i}. {cand}", 
                            variable=self.candidate_var, 
                            value=cand, command=lambda: self.vote_ticket.set(self.candidate_var.get())
                            ).pack(anchor="w", padx=5)
        # Cập nhật vote_counts và giao diện Kết quả bình chọn khi danh sách ứng viên thay đổi
        self.vote_counts = {cand: 0 for cand in candidates}
        # Cập nhật lại giao diện Kết quả bình chọn
        for widget in self.count_result_tab.winfo_children():
            widget.destroy()
        frame = ttk.Frame(self.count_result_tab)
        frame.pack(pady=10, padx=50, fill="both", expand=True)
        result_frame = ttk.LabelFrame(frame, text="Kết quả bình chọn:")
        result_frame.pack(fill="x", pady=10)
        self.result_labels = {}
        for cand in self.vote_counts:
            label = ttk.Label(result_frame, text=f"{cand}: {self.vote_counts[cand]} phiếu")
            label.pack(anchor="w", padx=10, pady=2)
            self.result_labels[cand] = label

    def export_vote(self):
        '''Hàm xuất file phiếu bình chọn'''
        if not (content := self.vote_ticket.get()): 
            return messagebox.showwarning("Cảnh báo", "Phiếu bình chọn trống! Vui lòng bình chọn.")
        file = filedialog.asksaveasfilename(defaultextension=".txt", 
                                            filetypes=[("Text files", "*.txt")], 
                                            initialfile="vote_result.txt")
        if file:
            with open(file, "w", encoding="utf-8") as f: f.write(content)
            messagebox.showinfo("Thành công", f"Kết quả lưu tại: {file}")

    def hash_file(self):
        '''Hàm băm SHA-256'''
        if not (path := self.vote_file_path.get()): 
            return messagebox.showwarning("Cảnh báo", "Chọn file kết quả trước!")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().encode("utf-8")
        digest = hashes.Hash(hashes.SHA256())
        digest.update(content)
        self.vote_hash = digest.finalize()
        self.hash_result_var.set(self.vote_hash.hex())

    def sign_vote(self):
        '''Hàm thực hiện ký số'''
        if not hasattr(self, "vote_hash"): 
            return messagebox.showwarning("Cảnh báo", "Băm nội dung trước!")
        if not hasattr(self, "private_key"): 
            return messagebox.showwarning("Cảnh báo", "Chọn khóa bí mật trước!")
        signature = self.private_key.sign(self.vote_hash, 
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          hashes.SHA256())
        file = filedialog.asksaveasfilename(defaultextension=".sig", 
                                            filetypes=[("Signature files", "*.sig")], 
                                            initialfile="signature.sig")
        if file:
            with open(file, "w") as f: f.write(signature.hex())
            messagebox.showinfo("Thành công", f"Chữ ký lưu tại: {file}")

    def encrypt_vote(self):
        '''Hàm mã hóa bình chọn'''
        if not all([self.vote_result_file_path.get(), hasattr(self, "check_public_key")]): 
            return messagebox.showwarning("Cảnh báo", "Chọn đầy đủ file và khóa!")
        with open(self.vote_result_file_path.get(), "r", encoding="utf-8") as f: 
            vote_content = f.read().encode("utf-8")
        encrypted = self.check_public_key.encrypt(vote_content, 
                                                  padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))
        file = filedialog.asksaveasfilename(defaultextension=".enc", 
                                            filetypes=[("Encrypted files", "*.enc")], 
                                            initialfile="encrypted_vote.enc")
        if file:
            with open(file, "w") as f:
                f.write(f"{base64.b64encode(encrypted).decode()}")
            messagebox.showinfo("Thành công", f"File mã hóa lưu tại: {file}")

    def create_candidate_entries(self):
        '''Hàm tạo ô nhập nội dung bình chọn theo số lượng xác định trước'''
        try:
            num = int(self.num_candidates_var.get())
            if num <= 0: 
                raise ValueError
            for widget in self.candidate_entries_frame.winfo_children(): 
                widget.destroy()
            self.candidate_entries = [tk.StringVar() for _ in range(num)]
            for i, var in enumerate(self.candidate_entries, 1):
                frame = ttk.Frame(self.candidate_entries_frame)
                frame.pack(fill="x", pady=2)
                ttk.Label(frame, text=f"Bình chọn {i}:").pack(side="left", padx=5)
                ttk.Entry(frame, textvariable=var).pack(side="left", fill="x", expand=True, padx=5)
            self.save_button.pack(pady=5)
            self.edit_frame.pack(fill="x", pady=5)
            self.edit_frame.pack_forget()
        except ValueError:
            messagebox.showerror("Lỗi", "Nhập số lượng bình chọn hợp lệ!")

    def save_candidates(self):
        '''Hàm lưu các bình chọn đã được tạo'''
        self.candidates = [entry.get() for entry in self.candidate_entries if entry.get()]
        if len(self.candidates) != len(self.candidate_entries): 
            return messagebox.showwarning("Cảnh báo", "Nhập đầy đủ nội dung bình chọn!")
        messagebox.showinfo("Thành công", "Danh sách bình chọn đã lưu!")
        self.update_candidate_list()
        # Reset vote counts and update Kết quả bình chọn tab
        self.vote_counts = {cand: 0 for cand in self.candidates}
        for widget in self.count_result_tab.winfo_children():
            widget.destroy()
        frame = ttk.Frame(self.count_result_tab)
        frame.pack(pady=10, padx=50, fill="both", expand=True)
        result_frame = ttk.LabelFrame(frame, text="Kết quả bình chọn:")
        result_frame.pack(fill="x", pady=10)
        self.result_labels = {}
        for cand in self.vote_counts:
            label = ttk.Label(result_frame, text=f"{cand}: {self.vote_counts[cand]} phiếu")
            label.pack(anchor="w", padx=10, pady=2)
            self.result_labels[cand] = label
        self.save_button.pack_forget()
        self.edit_frame.pack_forget()
        if self.candidate_entries:  
            self.edit_frame.pack(fill="x", pady=5)
        else:
            self.edit_frame.pack_forget()

    def delete_candidates(self):
        '''Hàm xóa các bình chọn đã tạo'''
        self.num_candidates_var.set("")
        for widget in self.candidate_entries_frame.winfo_children():
            widget.destroy()
        self.candidate_entries.clear()
        self.candidates.clear()
        self.save_button.pack_forget()
        self.edit_frame.pack_forget()
        # Reset vote counts and update Kết quả bình chọn tab
        self.update_candidate_list()  # This will reset to default candidates

    def decrypt_vote(self):
        '''Hàm giải mã bình chọn'''
        if not all([self.encrypted_file_path.get(), hasattr(self, "check_private_key")]): 
            return messagebox.showwarning("Cảnh báo", "Chọn đầy đủ file và khóa!")
        with open(self.encrypted_file_path.get(), "r") as f:
            enc_vote = f.read().strip()
        decrypted = self.check_private_key.decrypt(base64.b64decode(enc_vote), 
                                                   padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), 
                                                                algorithm=hashes.SHA256(), 
                                                                label=None))
        file = filedialog.asksaveasfilename(defaultextension=".txt", 
                                            filetypes=[("Text files", "*.txt")], 
                                            initialfile="decrypted_vote.txt")
        if file:
            with open(file, "w", encoding="utf-8") as f: f.write(decrypted.decode())
            messagebox.showinfo("Thành công", f"File giải mã lưu tại: {file}")

    def verify_signature(self):
        '''Hàm xác thực ký số'''
        if not all([self.decrypted_file_path.get(), self.signature_file_path_verify.get(), hasattr(self, "vote_public_key")]): 
            return messagebox.showwarning("Cảnh báo", "Chọn đầy đủ file và khóa!")
        with open(self.decrypted_file_path.get(), "r", encoding="utf-8") as f: 
            content = f.read().encode("utf-8")
        with open(self.signature_file_path_verify.get(), "r") as f: 
            signature = bytes.fromhex(f.read())
        digest = hashes.Hash(hashes.SHA256())
        digest.update(content)
        try:
            self.vote_public_key.verify(signature, digest.finalize(), 
                                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                                                    salt_length=padding.PSS.MAX_LENGTH), 
                                        hashes.SHA256())
            messagebox.showinfo("Kết quả", "Xác thực thành công!")
            # Nếu xác thực thành công, cập nhật số lượng bình chọn
            with open(self.decrypted_file_path.get(), "r", encoding="utf-8") as f:
                vote = f.read().strip()
                # Kiểm tra xem vote có nằm trong danh sách ứng viên không
                if vote in self.vote_counts:
                    self.vote_counts[vote] += 1
                    # Cập nhật giao diện
                    self.result_labels[vote].config(text=f"{vote}: {self.vote_counts[vote]} phiếu")
        except:
            messagebox.showerror("Kết quả", "Xác thực không thành công!")
            # Nếu xác thực không thành công, không cập nhật số lượng bình chọn

    def setup_vote_key_tab(self):
        '''Thiết lập sub-tab sinh khóa bỏ phiếu'''
        frame = ttk.Frame(self.vote_key_tab)
        frame.pack(pady=5, padx=50, fill="both", expand=True)

        # Tải ảnh và đặt vào đầu box
        image = PhotoImage(file="image.png") 
        img_label = tk.Label(frame, image=image)
        img_label.image = image
        img_label.pack(side="top", pady=10)

        key_size_frame = ttk.LabelFrame(frame, text="1. Thông tin cặp khóa dùng để Bỏ phiếu: ")
        key_size_frame.pack(fill="x", pady=5)
        pub_label = ttk.Label(key_size_frame, text="Chọn kích thước khóa: ")
        pub_label.pack(anchor="w", padx=10)
        self.vote_key_size_var = tk.StringVar(value="")

        ttk.Combobox(key_size_frame, textvariable=self.vote_key_size_var, values=["1024 bit", "2048 bit"], 
                     state="readonly", justify="center").pack(pady=5)
        
        tk.Button(key_size_frame, text="  Sinh khóa  ", command=lambda: self.generate_keys(pub_label, pri_label,self.vote_key_size_var,"vote_"),
                  bg="grey", fg="white").pack(pady=5)
        
        pub_label = ttk.Label(key_size_frame, text="Khóa công khai: Chưa có")
        pri_label = ttk.Label(key_size_frame, text="Khóa bí mật: Chưa có")
        pub_label.pack(anchor="w", padx=10)
        pri_label.pack(anchor="w", padx=10)

        self.candidate_frame = ttk.LabelFrame(frame, text="2. Danh sách bình chọn: ")
        self.candidate_frame.pack(fill="x", pady=10)
        self.candidate_var = tk.StringVar()
        self.update_candidate_list()

        vote_frame = ttk.LabelFrame(frame, text="3. Nội dung bình chọn: ")
        vote_frame.pack(fill="x", pady=10)
        self.vote_ticket = tk.StringVar()

        tk.Entry(vote_frame, textvariable=self.vote_ticket, 
                 state="readonly", bg="white").pack(fill="x", padx=5, pady=5)
        
        tk.Button(vote_frame, text="  Xuất nội dung bình chọn  ", command=self.export_vote,
                  bg="grey", fg="white").pack(pady=5)

    def setup_vote_sign_tab(self):
        '''Thiết lập sub-tab thực hiện ký số'''
        frame = ttk.Frame(self.vote_sign_tab)
        frame.pack(pady=10, padx=50, fill="both", expand=True)

        self.vote_file_path = tk.StringVar()
        self.create_file_selector(frame, "Tập tin: ", [("Text files", "*.txt")],
                                  self.vote_file_path).pack(side="left", padx=5)
    
        hash_frame = ttk.Frame(frame)
        hash_frame.pack(fill="x", pady=5)
        ttk.Label(hash_frame, text="Kết quả băm: ").pack(side="left", padx=5)

        self.hash_result_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.hash_result_var, 
                 state="readonly", bg="white").pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(hash_frame, text="Băm", command=self.hash_file).pack(side="left", padx=5)

        private_key_path = tk.StringVar()
        private_key_path.trace("w", lambda *args: setattr(self, "private_key", 
                                                          serialization.load_pem_private_key(open(private_key_path.get(), "rb").read(), None) 
                                                          if private_key_path.get() else None))

        self.create_file_selector(frame, "Khóa cá nhân bỏ phiếu: ", [("Private Key", "*.pri")], 
                                  private_key_path,).pack(side="left", padx=5)
        
        tk.Button(frame, text="   Thực hiện ký số   ", command=self.sign_vote,
                  bg="grey", fg="white").pack(pady=10)

    def setup_vote_encrypt_tab(self):
        '''Thiết lập sub-tab mã hóa bình chọn'''
        frame = ttk.Frame(self.vote_encrypt_tab)
        frame.pack(pady=10, padx=50, fill="both", expand=True)

        self.vote_result_file_path = tk.StringVar()
        self.signature_file_path = tk.StringVar()
        check_public_key_path = tk.StringVar()

        self.create_file_selector(frame, "Tập tin:", [("Text files", "*.txt")], 
                                  self.vote_result_file_path).pack(side="left", padx=5)
        
        self.create_file_selector(frame, "Khóa công khai kiểm phiếu: ", [("Public Key", "*.pub")],     
                                  check_public_key_path).pack(side="left", padx=5)
        
        check_public_key_path.trace("w", lambda *args: setattr(self, "check_public_key", 
                                                               serialization.load_pem_public_key(open(check_public_key_path.get(), "rb").read()) 
                                                               if check_public_key_path.get() else None))
        
        tk.Button(frame, text="   Mã hóa   ", command=self.encrypt_vote,
                  bg="grey", fg="white").pack(pady=10)

    def setup_count_key_tab(self):
        '''Thiết lập sub-tab sinh khóa kiểm phiếu'''
        frame = ttk.Frame(self.count_key_tab)
        frame.pack(pady=5, padx=50, fill="both", expand=True)

        key_size_frame = ttk.LabelFrame(frame, text="1. Thông tin cặp khóa dùng để Kiểm phiếu: ")
        key_size_frame.pack(fill="x", pady=5)
        pub_label = ttk.Label(key_size_frame, text="Chọn kích thước khóa: ")
        pub_label.pack(anchor="w", padx=10)
        self.count_key_size_var = tk.StringVar(value="")

        ttk.Combobox(key_size_frame, textvariable=self.count_key_size_var, values=["4096 bit"], 
                     state="readonly", justify="center").pack(pady=5)

        tk.Button(key_size_frame, text="  Sinh khóa  ", command=lambda: self.generate_keys(pub_label, pri_label,self.count_key_size_var, "check_"),
                  bg="grey", fg="white").pack(pady=5)
        
        pub_label = ttk.Label(key_size_frame, text="Khóa công khai: Chưa có")
        pri_label = ttk.Label(key_size_frame, text="Khóa bí mật: Chưa có")
        pub_label.pack(anchor="w", padx=10)
        pri_label.pack(anchor="w", padx=10)

        num_frame = ttk.LabelFrame(frame, text="2. Số lượng bình chọn: ")
        num_frame.pack(fill="both", pady=5)
        self.num_candidates_var = tk.StringVar()
        ttk.Entry(num_frame, textvariable=self.num_candidates_var, 
                  justify="center").pack(pady=5)
        tk.Button(num_frame, text="   Tạo danh sách bình chọn   ", 
                   command=self.create_candidate_entries,
                   bg="grey", fg="white").pack(pady=5)

        candidate_frame = ttk.LabelFrame(frame, text="3. Danh sách bình chọn: ")
        candidate_frame.pack(fill="x", pady=5)
        self.candidate_entries_frame = ttk.Frame(candidate_frame)
        self.candidate_entries_frame.pack(fill="x", padx=5, pady=5)
        self.candidate_entries = []
        self.save_button = tk.Button(candidate_frame, text="  Lưu danh sách   ", 
                                      command=self.save_candidates,
                                      bg="grey", fg="white")
        self.edit_frame = ttk.Frame(candidate_frame)
        tk.Button(self.edit_frame, text="   Xóa danh sách   ",
                   command=self.delete_candidates,
                   bg="grey", fg="white").pack(side="left", padx=10)

    def setup_count_decrypt_tab(self):
        '''Thiết lập sub-tab giải mã bình chọn'''
        frame = ttk.Frame(self.count_decrypt_tab)
        frame.pack(pady=10, padx=50, fill="both", expand=True)

        self.encrypted_file_path = tk.StringVar()
        self.signature_file_path_decrypt = tk.StringVar()
        check_private_key_path = tk.StringVar()
        self.create_file_selector(frame, "Tập tin: ", [("Encrypted files", "*.enc")], 
                                  self.encrypted_file_path).pack(side="left", padx=5)
        self.create_file_selector(frame, "Khóa cá nhân kiểm phiếu: ", [("Private Key", "*.pri")], 
                                  check_private_key_path).pack(side="left", padx=5)

        check_private_key_path.trace("w", lambda *args: setattr(self, "check_private_key",
                                                                serialization.load_pem_private_key(open(check_private_key_path.get(), "rb").read(), None)
                                                                if check_private_key_path.get() else None))
        tk.Button(frame, text="  Giải mã  ", command=self.decrypt_vote,
                  bg="grey", fg="white").pack(pady=10)

    def setup_count_verify_tab(self):
        '''Thiết lập sub-tab xác thực ký số'''
        frame = ttk.Frame(self.count_verify_tab)
        frame.pack(pady=10, padx=50, fill="both", expand=True)

        self.decrypted_file_path = tk.StringVar()
        self.signature_file_path_verify = tk.StringVar()
        vote_public_key_path = tk.StringVar()
        self.create_file_selector(frame, "Tập tin: ", [("Text files", "*.txt")],
                                  self.decrypted_file_path).pack(side="left", padx=5)
        self.create_file_selector(frame, "Chữ ký số: ", [("Signature files", "*.sig")],
                                  self.signature_file_path_verify).pack(side="left", padx=5)
        self.create_file_selector(frame, "Khóa công khai bỏ phiếu: ", [("Public Key", "*.pub")],
                                  vote_public_key_path).pack(side="left", padx=5)
        vote_public_key_path.trace("w", lambda *args: setattr(self, "vote_public_key",
                                                              serialization.load_pem_public_key(open(vote_public_key_path.get(), "rb").read())
                                                              if vote_public_key_path.get() else None))

        tk.Button(frame, text="   Xác thực ký số   ", command=self.verify_signature,
                  bg="grey", fg="white").pack(pady=10)

    def setup_count_result_tab(self):
        '''Thiết lập sub-tab kết quả bình chọn'''
        frame = ttk.Frame(self.count_result_tab)
        frame.pack(pady=10, padx=50, fill="both", expand=True)

        # Khung hiển thị kết quả bình chọn
        result_frame = ttk.LabelFrame(frame, text="Kết quả bình chọn:")
        result_frame.pack(fill="x", pady=10)

        # Khởi tạo vote_counts nếu chưa có
        if not self.vote_counts:
            candidates = self.candidates if self.candidates else ["Bình chọn A", "Bình chọn B"]
            self.vote_counts = {cand: 0 for cand in candidates}

        # Hiển thị số lượng bình chọn cho từng ứng viên
        for cand in self.vote_counts:
            label = ttk.Label(result_frame, text=f"{cand}: {self.vote_counts[cand]} phiếu")
            label.pack(anchor="w", padx=10, pady=2)
            self.result_labels[cand] = label  # Lưu label để cập nhật sau

    def setup_info_tab(self):
        '''Thiết lập tab Thông tin chương trình'''
        frame = tk.Frame(self.info_tab)
        frame.pack(pady=5, padx=40, fill="both", expand=True)
        t = ("Chương trình này ứng dụng Thuật toán mã hóa bất đối xứng RSA với cơ chế\n"
            "hai cặp khóa kết hợp chữ ký số để mã hóa và giải mã các phiếu bình chọn, \n"
            "đảm bảo an toàn, bảo mật và tiện lợi.\n"
            "\n"
            "Chương trình là thành quả của các bạn Nguyễn Quốc, Mỹ Dung, Diêu Ly,\n"
            "Ngọc Mai, Yến Nhi đã dành thời gian và công sức nghiên cứu, phát triển\n"
            "nhằm mang lại một hệ thống bảo mật và minh bạch trong bình chọn.\n"
            "\n"
            "Nhóm tác giả hy vọng rằng ứng dụng này sẽ góp phần nâng cao tính bảo mật\n"
            "và tiện lợi cho người dùng.")
        pub_label = tk.Label(frame, text=t, justify="left", font=("Times New Roman", 11, "italic")).pack(anchor="w", padx=10, pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = VotingApp(root)
    root.update_idletasks()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    position_x = (screen_width//2) - (600//2)
    position_y = (screen_height//2) - (650//2) - 50
    root.geometry(f"{600}x{650}+{position_x}+{position_y}")
    root.mainloop()