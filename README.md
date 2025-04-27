# PacCrypt WebApp

**PacCrypt** is a web-based application designed to provide secure encoding, encryption, and password generation. It allows users to easily encrypt and decrypt text and files, with both basic and advanced encryption options. It also features a password generator and a simple Pac-Man game as an Easter egg!

## Features

- **Basic and Advanced Encryption**: Choose between simple encryption (Caesar Cipher) or more secure AES-GCM encryption.
- **File Encryption/Decryption**: Encrypt or decrypt files with a password.
- **Password Generator**: Generate secure random passwords with customizable length and complexity.
- **Pac-Man Game**: A fun Easter egg! Play a Pac-Man game when you type "pacman" in the text area.
- **Copy to Clipboard**: Copy generated passwords or encrypted results with one click.
- **Responsive Design**: Fully responsive web design that works across different screen sizes.

## Installation

### Prerequisites

- **Python 3.7+**
- **Nginx** (for reverse proxy and SSL configuration for hosting)

Official PacCrypt website: paccrypt.unnaturalll.dev

### Steps to Set Up Locally:

1. Clone the repository:
   git clone https://github.com/TySP-Dev/PacCrypt.git
   cd paccrypt-webapp

2. Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3. Install the required Python dependencies:
   pip install -r requirements.txt

4. Run the Flask app:
   python app.py

5. Open http://127.0.0.1:5000 to access the app locally.

## Usage

### Encryption and Decryption

#### For text encryption/decryption:

-- Select the encryption type (Basic or Advanced).

-- Choose whether to Encrypt or Decrypt.

-- Enter text in the Input Text area.

-- Enter a password (if using advanced encryption).

-- Click submit.

#### For file encryption/decryption:

-- Select encryption type **Advanced.**

-- Choose whether to Encrypt or Decrypt.

-- Upload a file.

-- Enter a password for encryption/decryption.

-- Click submit.

### Password Generation:

Click the Generate button to create a random password, then use the Copy button to copy it to your clipboard.

### Pac-Man Game (Easter Egg):

Type the word "pacman" in the input box to unlock the Pac-Man game!

### Contributing:

Feel free to open an issue or submit a pull request for improvements, bug fixes, or new features!

### License

This project is open source and available under the MIT License.
