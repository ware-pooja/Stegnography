import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os
from stego_core import hide_text, extract_text

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Steganography Tool - Hide & Reveal Secrets")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables
        self.input_image_path = tk.StringVar()
        self.output_image_path = tk.StringVar()
        self.message = tk.StringVar()
        self.password = tk.StringVar()
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main notebook (tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Hide Tab
        self.hide_frame = ttk.Frame(notebook)
        notebook.add(self.hide_frame, text="📤 Hide Message")
        self.setup_hide_tab()
        
        # Extract Tab  
        self.extract_frame = ttk.Frame(notebook)
        notebook.add(self.extract_frame, text="🔍 Extract Message")
        self.setup_extract_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, 
                            relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_hide_tab(self):
        # Input image selection
        ttk.Label(self.hide_frame, text="Input Image:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=20, pady=5)
        
        img_frame = ttk.Frame(self.hide_frame)
        img_frame.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Entry(img_frame, textvariable=self.input_image_path, state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(img_frame, text="📁 Browse", command=self.browse_input_image).pack(side=tk.RIGHT, padx=(5,0))
        
        # Preview
        self.preview_label = ttk.Label(self.hide_frame, text="No image selected")
        self.preview_label.pack(pady=10)
        
        # Message input
        ttk.Label(self.hide_frame, text="Secret Message:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=20, pady=(20,5))
        msg_entry = scrolledtext.ScrolledText(self.hide_frame, height=4, wrap=tk.WORD)
        msg_entry.pack(fill=tk.X, padx=20, pady=5)
        msg_entry.insert('1.0', "Enter your secret message here...")
        self.message_entry = msg_entry
        
        # Password
        ttk.Label(self.hide_frame, text="Password:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=20, pady=(10,5))
        pass_frame = ttk.Frame(self.hide_frame)
        pass_frame.pack(fill=tk.X, padx=20, pady=5)
        ttk.Entry(pass_frame, textvariable=self.password, show="*", width=30).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(pass_frame, text="👁 Show", command=self.toggle_password).pack(side=tk.RIGHT, padx=(5,0))
        
        # Output image
        ttk.Label(self.hide_frame, text="Output Image:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=20, pady=(20,5))
        out_frame = ttk.Frame(self.hide_frame)
        out_frame.pack(fill=tk.X, padx=20, pady=5)
        ttk.Entry(out_frame, textvariable=self.output_image_path, state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(out_frame, text="📁 Browse", command=self.browse_output_image).pack(side=tk.RIGHT, padx=(5,0))
        
        # Capacity check
        self.capacity_label = ttk.Label(self.hide_frame, text="", foreground="blue")
        self.capacity_label.pack(anchor='w', padx=20, pady=5)
        
        # Hide button
        ttk.Button(self.hide_frame, text="🚀 HIDE MESSAGE", command=self.hide_message,
                  style="Accent.TButton").pack(pady=20)
    
    def setup_extract_tab(self):
        # Input image for extraction
        ttk.Label(self.extract_frame, text="Image with Hidden Message:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=20, pady=5)
        
        ext_img_frame = ttk.Frame(self.extract_frame)
        ext_img_frame.pack(fill=tk.X, padx=20, pady=5)
        self.extract_image_path = tk.StringVar()
        ttk.Entry(ext_img_frame, textvariable=self.extract_image_path, state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(ext_img_frame, text="📁 Browse", command=self.browse_extract_image).pack(side=tk.RIGHT, padx=(5,0))
        
        # Password for extraction
        ttk.Label(self.extract_frame, text="Password:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=20, pady=(20,5))
        ttk.Entry(self.extract_frame, textvariable=self.password, show="*").pack(fill=tk.X, padx=20, pady=5)
        
        # Extract button
        ttk.Button(self.extract_frame, text="🔓 EXTRACT MESSAGE", command=self.extract_message,
                  style="Accent.TButton").pack(pady=30)
        
        # Results
        ttk.Label(self.extract_frame, text="Extracted Message:", font=('Arial', 10, 'bold')).pack(anchor='w', padx=20, pady=(30,5))
        self.result_text = scrolledtext.ScrolledText(self.extract_frame, height=8, state=tk.DISABLED, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
    
    def browse_input_image(self):
        filename = filedialog.askopenfilename(
            title="Select input image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")]
        )
        if filename:
            self.input_image_path.set(filename)
            self.update_preview(filename)
            self.check_capacity()
            self.set_output_path()
    
    def browse_output_image(self):
        filename = filedialog.asksaveasfilename(
            title="Save stego image as",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if filename:
            self.output_image_path.set(filename)
    
    def browse_extract_image(self):
        filename = filedialog.askopenfilename(
            title="Select image with hidden message",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if filename:
            self.extract_image_path.set(filename)
    
    def update_preview(self, image_path):
        try:
            img = Image.open(image_path)
            img.thumbnail((200, 200), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self.preview_label.configure(image=photo, text="")
            self.preview_label.image = photo
        except Exception as e:
            self.preview_label.configure(image="", text="Invalid image")
    
    def check_capacity(self):
        try:
            message = self.message_entry.get('1.0', tk.END).strip()
            if not message or message.startswith("Enter"):
                self.capacity_label.config(text="")
                return
            
            img_path = self.input_image_path.get()
            if not os.path.exists(img_path):
                return
            
            img = Image.open(img_path)
            capacity = img.width * img.height * 3 // 8  # bytes
            
            encrypted_size = len(xor_encrypt(message, "default")) + 5
            if encrypted_size > capacity:
                self.capacity_label.config(text=f"❌ Message too long! Capacity: {capacity} chars", foreground="red")
            else:
                self.capacity_label.config(text=f"✅ Capacity OK: {encrypted_size}/{capacity} chars", foreground="green")
        except:
            pass
    
    def set_output_path(self):
        if self.input_image_path.get():
            base, ext = os.path.splitext(self.input_image_path.get())
            suggested = f"{base}_stego.png"
            self.output_image_path.set(suggested)
    
    def toggle_password(self):
        entry = self.hide_frame.winfo_children()[8].winfo_children()[0]  # Password entry
        if self.password.get():
            entry.config(show="") 
        else:
            entry.config(show="*")
    
    def hide_message(self):
        try:
            message = self.message_entry.get('1.0', tk.END).strip()
            if not message or message.startswith("Enter"):
                messagebox.showerror("Error", "Please enter a message!")
                return
            
            password = self.password.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password!")
                return
            
            input_path = self.input_image_path.get()
            output_path = self.output_image_path.get()
            
            if not input_path:
                messagebox.showerror("Error", "Please select input image!")
                return
            
            if not output_path:
                messagebox.showerror("Error", "Please select output location!")
                return
            
            self.status_var.set("Hiding message...")
            self.root.update()
            
            hide_text(input_path, message, password, output_path)
            
            self.status_var.set("✅ Message hidden successfully!")
            messagebox.showinfo("Success", f"Message hidden in:\n{output_path}")
            
        except Exception as e:
            self.status_var.set("Error occurred")
            messagebox.showerror("Error", str(e))
    
    def extract_message(self):
        try:
            password = self.password.get()
            if not password:
                messagebox.showerror("Error", "Please enter password!")
                return
            
            image_path = self.extract_image_path.get()
            if not image_path:
                messagebox.showerror("Error", "Please select image!")
                return
            
            self.status_var.set("Extracting message...")
            self.root.update()
            
            message = extract_text(image_path, password)
            
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', message)
            self.result_text.config(state=tk.DISABLED)
            
            self.status_var.set("✅ Message extracted!")
            
        except Exception as e:
            self.status_var.set("Extraction failed")
            messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
