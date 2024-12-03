import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
import hashlib
import io
import pyperclip
from PIL import Image, ImageTk
import customtkinter as ctk  # Modern UI library
from datetime import datetime
import os
import argparse

class ModernFileViewer(ctk.CTk):
    VersionInt = 101

    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("Secure Image Package Viewer - Made By Dennis https://github.com/taldb")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        
        self.public_key_path = None
        self.current_file_path = None
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create main frame
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)
        
        # Left sidebar
        sidebar = ctk.CTkFrame(main_frame, width=200)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        
        # Buttons in sidebar
        self.open_btn = ctk.CTkButton(
            sidebar, 
            text="Open File",
            command=self.open_file_gui
        )
        self.open_btn.pack(pady=(20, 10), padx=20)
        
        self.copy_btn = ctk.CTkButton(
            sidebar,
            text="Copy Metadata",
            command=self.copy_metadata  # Call the method here
        )
        self.copy_btn.pack(pady=10, padx=20)
        

        self.create_btn = ctk.CTkButton(
            sidebar,
            text="Create File",
            command=self.create_file_gui  # Call the new method to create a file
        )
        self.create_btn.pack(pady=10, padx=20)

        self.extract_image_btn = ctk.CTkButton(
            sidebar,
            text="Extract Image",
            command=self.extract_image
        )
        self.extract_image_btn.pack(pady=10, padx=20)  # Add this button to sidebar


        # Status indicator
        self.status_label = ctk.CTkLabel(
            sidebar,
            text="Status: Ready",
            text_color="white"
        )
        self.status_label.pack(pady=(20, 10))
        
        # Main content area
        content = ctk.CTkFrame(main_frame)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)
        
        # Image display area
        self.image_frame = ctk.CTkFrame(content)
        self.image_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 20))
        self.image_label = ctk.CTkLabel(self.image_frame, text="")
        self.image_label.pack(expand=True, fill="both")
        
        # Tabbed interface for metadata and headers
        self.tab_view = ctk.CTkTabview(content)
        self.tab_view.grid(row=1, column=0, sticky="nsew")
        
        # Headers tab
        headers_tab = self.tab_view.add("Headers")
        self.headers_text = ctk.CTkTextbox(headers_tab, height=200)
        self.headers_text.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Metadata tab
        metadata_tab = self.tab_view.add("Metadata")
        self.metadata_tree = ttk.Treeview(metadata_tab, show="tree")
        self.metadata_tree.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Dark mode style for Treeview
        self.apply_dark_mode_to_treeview()
        
        # Add right-click context menu for Treeview
        self.create_treeview_context_menu()

        # Verification tab
        verify_tab = self.tab_view.add("Verification")
        self.verify_text = ctk.CTkTextbox(verify_tab, height=200)
        self.verify_text.pack(expand=True, fill="both", padx=10, pady=10)


        # Bind keyboard shortcuts
        self.bind("<Control-c>", self.copy_metadata)  # Ctrl + C to copy metadata
        self.bind("<Control-o>", self.open_file_gui)  # Ctrl + O to open a file
        self.bind("<Control-s>", self.create_file_gui)  # Ctrl + S to create a file
        self.bind("<Control-e>", self.extract_image)  # Ctrl + E to extract the image



    def apply_dark_mode_to_treeview(self):
        style = ttk.Style()
        
        # Set the Treeview style for dark mode
        style.configure("Treeview",
                        background="#2e2e2e",  # Dark background
                        foreground="#ffffff",  # White text
                        fieldbackground="#2e2e2e",  # Background of fields
                        font=('Arial', 10),
                        rowheight=25)
        
        # Style for treeview headings
        style.configure("Treeview.Heading",
                        background="#3e3e3e",  # Slightly lighter background for headers
                        foreground="#ffffff",  # White text for headings
                        font=('Arial', 10, 'bold'))
        
        # Add focus behavior to the treeview
        style.map("Treeview", background=[('selected', '#1e1e1e')])  # Selected item color

    def create_treeview_context_menu(self):
        # Right-click context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy Metadata", command=self.copy_metadata)

        # Bind right-click event to Treeview
        self.metadata_tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        # Show the context menu at the mouse position
        self.context_menu.post(event.x_root, event.y_root)


    def open_file_gui(self, event=None):
        try:
            file_path = filedialog.askopenfilename(
                title="Select SVPK File",
                filetypes=[("Secure Image Package Files", "*.svpk")]
            )
            if not file_path:
                return
                
            self.current_file_path = file_path
            
            # Get public key
            self.public_key_path = filedialog.askopenfilename(
                title="Select Public Key",
                filetypes=[("PEM Files", "*.pem")]
            )
            
            if not self.public_key_path:
                return
                
            self.process_file(file_path)
            self.status_label.configure(text="Status: File loaded", text_color="green")
            
        except Exception as e:
            self.status_label.configure(text="Status: Error", text_color="red")
            messagebox.showerror("Error", str(e))

    def copy_metadata(self, event=None):
        if not self.current_file_path:
            messagebox.showwarning("Warning", "No file loaded")
            return
        
        # Implementation for copying metadata to clipboard
        selected_item = self.metadata_tree.selection()  # Get selected item in Treeview
        if selected_item:
            text = self.metadata_tree.item(selected_item[0], "text")
            pyperclip.copy(text)  # Copy the text of the selected item
            messagebox.showinfo("Info", "Metadata copied to clipboard.")
        else:
            messagebox.showwarning("Warning", "No metadata item selected.")

    def extract_metadata_from_tree(self, tree_items):
        metadata = {}
        for item in tree_items:
            text = self.metadata_tree.item(item, "text")
            if ':' in text:
                key, value = text.split(":", 1)
                metadata[key.strip()] = value.strip()
        return metadata

    def process_file(self, file_path):
        with open(self.public_key_path, 'rb') as public_file:
            public_key = RSA.import_key(public_file.read())

        with open(file_path, 'rb') as f:
            # Read header section
            f.readline()  # Skip [HEADER]
            version = str(f.readline().decode().split(": ")[1].strip())
            image_size = int(f.readline().decode().split(": ")[1].strip())
            image_type = f.readline().decode().split(": ")[1].strip()
            metadata_size = int(f.readline().decode().split(": ")[1].strip())
            signature_size_base64 = int(f.readline().decode().split(": ")[1].strip())
            imagehash_size = int(f.readline().decode().split(": ")[1].strip())
            f.readline()  # Skip [END_HEADER]
            
            # Read image data
            f.readline()  # Skip [IMAGEDATA]
            image_data = f.read(image_size)
            f.readline()  # Skip the newline after image data
            f.readline()  # Skip [ENDIMAGEDATA]
            
            # Read metadata
            f.readline()  # Skip [METADATA]
            metadata_json = f.read(metadata_size)
            f.readline()  # Skip [END_METADATA]
            
            # Read signature
            f.readline()  # Skip [SIGNATURE]
            signature_base64 = f.read(signature_size_base64).decode('utf-8').strip()
            signature = base64.b64decode(signature_base64)
            f.readline()  # Skip [END_SIGNATURE]

            # Read Image Hash
            f.readline()  # Skip [IMAGEHASH]
            imagehash_ext = f.read(imagehash_size).decode('utf-8').strip()
            f.readline()  # Skip [END_IMAGEHASH]

        # Store image data for later use
        self.image_data = image_data

        # Verify signature
        metadata_hash = SHA1.new(metadata_json)
        signature_valid = False
        try:
            pkcs1_15.new(public_key).verify(metadata_hash, signature)
            signature_valid = True
        except (ValueError, TypeError):
            signature_valid = False

        # Verify image hash
        calculated_image_hash = self.calculate_image_hash(image_data)
        hash_valid = imagehash_ext == calculated_image_hash

        # Update UI elements
        # Update headers text
        headers_info = f"""Version: {version}
Image Type: {image_type}
Image Size: {image_size} bytes
Metadata Size: {metadata_size} bytes
Signature Size: {signature_size_base64} bytes
Image Hash Size: {imagehash_size} bytes
Image Hash: {imagehash_ext}"""
        
        self.headers_text.configure(state="normal")
        self.verify_text.configure(state="normal")


        self.headers_text.delete("1.0", tk.END)
        self.headers_text.insert("1.0", headers_info)

        # Update metadata tree
        metadata = json.loads(metadata_json.decode('utf-8'))
        self.update_metadata_tree(metadata)

        # Update verification status
        self.update_verification_status(signature_valid, hash_valid)

        self.headers_text.configure(state="disabled")
        self.verify_text.configure(state="disabled")


        # Display image
        image = Image.open(io.BytesIO(image_data))
        # Calculate aspect ratio for resizing
        display_size = (800, 600)
        image.thumbnail(display_size, Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        self.image_label.configure(image=photo)
        self.image_label.image = photo

    def calculate_image_hash(self, image_data):
        sha1 = hashlib.sha1()
        sha1.update(image_data)
        return sha1.hexdigest()

    def update_metadata_tree(self, metadata):
        # Clear existing items
        for item in self.metadata_tree.get_children():
            self.metadata_tree.delete(item)

        def add_node(parent, key, value):
            if isinstance(value, dict):
                node = self.metadata_tree.insert(parent, 'end', text=key, open=True)
                for k, v in value.items():
                    add_node(node, k, v)
            elif isinstance(value, list):
                node = self.metadata_tree.insert(parent, 'end', text=key, open=True)
                for i, item in enumerate(value):
                    add_node(node, f"Item {i+1}", item)
            else:
                self.metadata_tree.insert(parent, 'end', text=f"{key}: {value}")

        for key, value in metadata.items():
            add_node('', key, value)

    def update_verification_status(self, signature_valid, hash_valid):
        status_text = f"""
        Metadata Signature Verification: {"✓ Valid" if signature_valid else "✗ Invalid"}
        Image Hash Verification: {"✓ Valid" if hash_valid else "✗ Invalid"}
        Checked at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        self.verify_text.delete("1.0", tk.END)
        self.verify_text.insert("1.0", status_text)


    def extract_image(self, event=None):
        if not self.image_data:
            messagebox.showwarning("Warning", "No image data found. Please load a valid SVPK file.")
            return
        
        # Ask user where to save the image
        save_path = filedialog.asksaveasfilename(
            defaultextension=".jpg", 
            filetypes=[("JPEG", "*.jpg"), ("PNG", "*.png")],
            title="Save Image"
        )
        
        if not save_path:
            return  # If the user cancels the save dialog, do nothing
        
        try:
            # Save the extracted image to the selected path
            image = Image.open(io.BytesIO(self.image_data))
            image.save(save_path)
            messagebox.showinfo("Info", f"Image successfully saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save image: {str(e)}")


    def create_file_gui(self, event=None):
        # Step 1: File dialogs to select image, metadata, public key, and private key
        image_path = filedialog.askopenfilename(title="Select Image File", filetypes=[("Image Files", "*.jpg;*.png;*.jpeg")])
        if not image_path:
            return
        
        metadata_path = filedialog.askopenfilename(title="Select Metadata JSON", filetypes=[("JSON Files", "*.json")])
        if not metadata_path:
            return
        
        public_key_path = filedialog.askopenfilename(title="Select Public Key (PEM)", filetypes=[("PEM Files", "*.pem")])
        if not public_key_path:
            return
        
        private_key_path = filedialog.askopenfilename(title="Select Private Key (PEM)", filetypes=[("PEM Files", "*.pem")])
        if not private_key_path:
            return
        
        output_file = filedialog.asksaveasfilename(title="Save Output File", defaultextension=".svpk", filetypes=[("Secure Image Package Files", "*.svpk")])
        if not output_file:
            return

        # Step 2: Call the function to create the custom file
        self.create_custom_file(public_key_path, private_key_path, image_path, output_file, metadata_path)
        self.status_label.configure(text="Status: File created successfully", text_color="green")
        

        
    def create_custom_file(self, public_key_path, private_key_path, image_path, output_file, metadata_path):
        # Calculate image hash
        def calculate_image_hash(image_data):
            sha1 = hashlib.sha1()
            sha1.update(image_data)
            return sha1.hexdigest()

        # Load image data
        with open(image_path, 'rb') as f:
            image_data = f.read()

        original_image_hash = calculate_image_hash(image_data)

        # Load metadata
        with open(metadata_path, 'r') as metadata_file:
            metadata = json.load(metadata_file)
        metadata_json = json.dumps(metadata).encode()

        # Load public and private keys
        with open(public_key_path, 'rb') as public_file:
            public_key = RSA.import_key(public_file.read())

        with open(private_key_path, 'rb') as private_file:
            private_key = RSA.import_key(private_file.read())

        # Create metadata hash and sign it
        metadata_hash = SHA1.new(metadata_json)
        signature = pkcs1_15.new(private_key).sign(metadata_hash)
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        signature_size_base64 = len(signature_base64)
        imagehash_size = len(original_image_hash)

        # Write the custom file
        with open(output_file, 'wb') as f:
            f.write(f"[HEADER]\n".encode())
            f.write(f"Version: {str(self.VersionInt)}\n".encode())
            f.write(f"Image Size: {len(image_data)}\n".encode())
            f.write(f"Image Type: jpg\n".encode())
            f.write(f"Metadata Size: {len(metadata_json)}\n".encode())
            f.write(f"Signature Size: {signature_size_base64}\n".encode())
            f.write(f"Imagehash Size: {imagehash_size}\n".encode())
            f.write(f"[END_HEADER]\n".encode())

            f.write(f"[IMAGEDATA,type:jpg]\n".encode())
            f.write(image_data)
            f.write(f"\n[ENDIMAGEDATA]\n".encode())
            
            f.write(f"[METADATA]\n".encode())
            f.write(metadata_json)
            f.write(f"[END_METADATA]\n".encode())

            f.write(f"[SIGNATURE]\n".encode())
            f.write(signature_base64.encode('utf-8'))
            f.write(f"[END_SIGNATURE]\n".encode())

            f.write(f"[IMAGEHASH]\n".encode())
            f.write(original_image_hash.encode('utf-8'))
            f.write(f"[END_IMAGEHASH]\n".encode())
            
        messagebox.showinfo("Success", "File created successfully.")


if __name__ == "__main__":
    app = ModernFileViewer()
    app.mainloop()
