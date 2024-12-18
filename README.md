
# Secure Image Package Viewer

## Overview
The **Secure Image Package Viewer** is a modern graphical application built with Python and CustomTkinter. It allows users to Package an image with its data (metadata in json format),and after extract their image with hash verification for the image itself and for the metadata. it can also view and manage secure image packages (SVPK files). The app ensures image and metadata integrity using cryptographic verification techniques, making it suitable for handling secure or authenticated image files.
#### *the SVPK file extension is sometimes used by "Synthesizer V", so dont confuse between the two files!.

<img src="https://raw.githubusercontent.com/taldb/SVPK_File/refs/heads/main/images/1.png" alt="Main app GUI" width="500" height="300"/>
<img src="https://raw.githubusercontent.com/taldb/SVPK_File/refs/heads/main/images/2.png" alt="Main app GUI" width="500" height="300"/>
<img src="https://raw.githubusercontent.com/taldb/SVPK_File/refs/heads/main/images/3.png" alt="Main app GUI" width="500" height="300"/>

##### (Version 1.0.1)


### Why I Created This Program

I created this application as part of a project to build a DIY Street View backpack. The goal was to develop a way to securely store images alongside the device's sensor data (such as GPS and orientation) in a single file. This program ensures that the image data and metadata are securely packaged and cryptographically verified. If any corruption occurs during storage or transmission, the application will notify me through hash verification, ensuring data integrity throughout the process.


---

## Features

1. **Open and View Secure Image Packages**:
   - Load `.svpk` files and their corresponding public keys to view images, headers, and metadata.

2. **Cryptographic Verification**:
   - Validate metadata integrity and image authenticity using RSA signatures and SHA-1 hashes.

3. **Metadata and Header Management**:
   - Copy metadata to the clipboard.
   - Browse headers and metadata with an intuitive tabbed interface.

4. **Extract Images**:
   - Export images embedded within secure packages to standard formats like `.jpg` or `.png`.

5. **Create Secure Image Packages**:
   - Combine an image, metadata, public/private key pair, and cryptographic signature into a secure `.svpk` file.

6. **Modern UI**:
   - Uses the dark-mode-friendly **CustomTkinter** library for a sleek and user-friendly interface.

---

## Installation

### Prerequisites

- Python 3.7 or higher
- `pip` package manager

### Dependencies

Install the required libraries:

```bash
pip install tkinter customtkinter pycryptodome pillow pyperclip
```

---

## How to Use

### Opening and Viewing SVPK Files

1. Click **Open File** to select a `.svpk` file.
2. Provide the corresponding **public key** in PEM format.
3. View the loaded image, metadata, and headers in the main interface.

### Verifying Image Packages

The app automatically verifies:
- **Metadata Signature**: Ensures the metadata has not been tampered with.
- **Image Hash**: Confirms the image data matches the original hash.

Results are displayed in the **Verification** tab.

### Extracting Images

1. Load a valid `.svpk` file.
2. Click **Extract Image** to save the image locally.

### Creating Secure Image Packages

1. Click **Create File** and follow the prompts to select:
   - **Image File**
   - **Metadata (JSON)**
   - **Public Key (PEM)**
   - **Private Key (PEM)**
   - **Output File Path**
2. A `.svpk` file is created with all components cryptographically secured.

---

## Keyboard Shortcuts

- **Ctrl + O**: Open a file
- **Ctrl + C**: Copy metadata
- **Ctrl + S**: Create a svpk file
- **Ctrl + E**: Extract the embedded image

---

## File Structure

A typical `.svpk` file contains the following sections:

1. **Headers**:
   - Version, image size/type, metadata size, signature size, and image hash size.
2. **Image Data**:
   - Binary image data in JPEG/PNG format.
3. **Metadata**:
   - JSON-formatted metadata, optionally nested.
4. **Signature**:
   - RSA signature of the metadata hash.
5. **Image Hash**:
   - SHA-1 hash of the image data.

### Example in-file:
```[HEADER]
Version: 101
Image Size:--Bytes Length--
Image Type: jpg
Metadata Size:--Metadata Char Length--
Signature Size:--Signature Char Length--
Imagehash Size:--Image Hash Char Length--
[END_HEADER]

[IMAGEDATA,type:jpg]
--Binary Data--
[ENDIMAGEDATA]

[METADATA]
--Metadata--
[END_METADATA]

[SIGNATURE]
--Base64 Encoded Signature--
[END_SIGNATURE]

[IMAGEHASH]
--SHA-1 Hash--
[END_IMAGEHASH]
```

---

## Development

### Tools and Technologies

- **GUI Framework**: CustomTkinter
- **Cryptography**: PyCryptodome
- **Image Handling**: Pillow
- **Clipboard Management**: Pyperclip

### TODO

- Add support for additional cryptographic algorithms.
- Improve metadata visualization.
- Enable batch processing of multiple files.
- Make a way to encrypt a picture (you could only view it using a PEM file)
- Add console commands (to make tasks without a UI)
---

### More

- Use the files in the 'test' directory, make sure to use them with their correct PEM key files (are in the same directory).
- use generateKeys to create a pair of Keys for the Hashing and encryption .

---


## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Contact

For inquiries, email me!
