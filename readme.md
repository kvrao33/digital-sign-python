
# Digital Signature Tool

## Overview

This is a Python-based Digital Signature Tool built using `tkinter` for the graphical user interface (GUI) and `rsa` library for RSA encryption and signature generation. The tool allows you to:
1. **Generate RSA public/private key pairs**.
2. **Sign a message** using a private key.
3. **Verify the authenticity of a signed message** using the public key.

## How Digital Signatures Work

A **digital signature** is a cryptographic technique used to validate the authenticity and integrity of a message. It is widely used in ensuring data security. The process works as follows:

1. **Hashing the Message**: The message is hashed using a cryptographic hashing algorithm (e.g., SHA-256).
2. **Signing the Hash**: The hash is signed with a private key using an asymmetric encryption algorithm like RSA.
3. **Verification**: To verify the signature, the recipient hashes the message again and then checks the signature using the sender's public key. If the hashes match, the signature is valid, confirming both the integrity of the message and the identity of the sender.

### Steps:
- **Sign a message**: Use your **private key** to sign a hashed message.
- **Verify the message**: Use the **public key** to verify the signature, ensuring that the message wasn't tampered with and was sent by the claimed sender.

## Dependencies

This project requires the following Python libraries:

1. **rsa**: A Python library for RSA encryption and decryption.
2. **tkinter**: A built-in Python library for creating graphical user interfaces (GUI). Typically comes pre-installed with Python.

### Install Dependencies

To run this tool, you need to install the `rsa` library. You can install it using `pip` by running the following command in your terminal or command prompt:

```bash
pip install rsa
```

`tkinter` should already be installed as it comes bundled with Python.

## How to Use the Code

Follow these steps to run and use the Digital Signature Tool:

### Step 1: Install Python and Dependencies

1. Install **Python** (if not already installed). You can download Python from [python.org](https://www.python.org/downloads/).
   
2. Install the required dependencies (as shown above) using `pip`:
   ```bash
   pip install rsa
   ```

### Step 2: Download or Clone the Project

Download or clone this project to your local machine.

### Step 3: Run the Script

1. Save the provided Python code in a file named `digital_signature_tool.py`.

2. Open a terminal or command prompt, navigate to the directory where the file is saved, and run the script:

   ```bash
   python digital_signature_tool.py
   ```

3. This will open the GUI application where you can:
   - **Generate RSA keys** (public and private).
   - **Sign messages** using a private key.
   - **Verify signatures** using a public key.

### Step 4: Use the GUI

- **Generate Keys**: Click the "Generate Keys" button to generate a pair of public and private keys.
  - The public key will be saved to `public_key.pem`.
  - The private key will be saved to `private_key.pem`.

- **Sign a Message**:
  - Enter the message you want to sign in the "Enter Message" box.
  - Browse to your private key file or enter the file path.
  - Click "Perform Action" and select "Sign" to generate the digital signature for the message.
  - The generated signature will be shown in the "Signature (Hex)" box.

- **Verify a Signature**:
  - Enter or paste the message in the "Enter Message" box.
  - Enter or browse for the public key file.
  - Paste the signature in the "Signature (Hex)" box.
  - Click "Perform Action" and select "Verify" to check if the signature is valid for the given message.

### Step 5: Viewing the Signature

- The generated signature is in **hexadecimal** format. This ensures that the signature can be easily stored and transferred as a string.
- When verifying a signature, you need to input the signature in the same hex format.

## Key Concepts

- **Private Key**: Used to sign messages. It is kept secret by the sender.
- **Public Key**: Used by the recipient to verify the signature. It can be shared publicly.
- **Digital Signature**: A secure and verifiable way to ensure that a message was sent by the stated sender and that its contents haven't been altered.

## Troubleshooting

1. **File Not Found Error**:
   - Ensure that the correct file paths are entered for both the private and public keys.
   - If the file doesn't exist or is invalid, the tool will show an error message.

2. **Invalid Signature Format**:
   - Make sure the signature is pasted in hexadecimal format when verifying.

3. **Key File Parsing Issues**:
   - If you encounter warnings or errors when selecting a key file, verify that the file is a valid PEM-formatted RSA key. You can generate one using the "Generate Keys" option.

## Example Use Cases

- **Email Authentication**: Sign an email with your private key, and the recipient can verify it using your public key.
- **Document Verification**: Attach a signature to a document to ensure it hasn’t been altered.
- **Software Updates**: Verify that a software update comes from a trusted source.

## Conclusion

This tool provides an easy-to-use interface for working with digital signatures, allowing you to sign and verify messages securely using RSA encryption. With this tool, you can ensure the authenticity and integrity of your communications and documents.

## License

This project is open-source and free to use. Feel free to modify it according to your needs.

