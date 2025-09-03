Password Hash Cracker 🔓
A powerful and efficient password hash cracking tool written in Python, designed for cybersecurity professionals, penetration testers, and educational purposes.
Features ✨
Multiple Algorithm Support: MD5, SHA1, SHA256, SHA512, and NTLM hashing algorithms

Smart Detection: Auto-detects hash algorithm based on length

User-Friendly Interface: Color-coded output and interactive mode

Performance Metrics: Real-time speed tracking and progress updates

Robust Error Handling: Comprehensive validation and helpful error messages

Flexible Usage: Both command-line arguments and interactive input modes

Installation 🛠️
Clone the repository:

bash
git clone https://github.com/yourusername/password-hash-cracker.git
cd password-hash-cracker
Install required dependencies:

bash
pip install colorama
Usage 🚀
Command Line Mode:
bash
python hash_cracker.py <target_hash> <wordlist_path> [--algorithm ALGORITHM]
Examples:
bash
# Crack MD5 hash with auto-detection
python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt

# Crack SHA256 hash with specified algorithm
python hash_cracker.py 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 wordlist.txt --algorithm sha256
Interactive Mode:
Run without arguments for interactive input:

bash
python hash_cracker.py
Supported Algorithms 🔐
Algorithm	Hash Length	Example
MD5	32 chars	5f4dcc3b5aa765d61d8327deb882cf99
SHA1	40 chars	a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
SHA256	64 chars	9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
SHA512	128 chars	ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
NTLM	32 chars	8846f7eaee8fb117ad06bdd830b7586c
Example Output 📊
Successful Crack:
text
==================================================
CRACK SUCCESSFUL! Password found: 'password'
==================================================
Passwords tested: 256,123
Time elapsed: 1.76 seconds
Speed: 145,678 passwords/sec
==================================================
Hash Not Found:
text
==================================================
PASSWORD NOT FOUND
==================================================
Passwords tested: 1,434,265
Time elapsed: 13.21 seconds
Speed: 108,567 passwords/sec
Ethical Considerations ⚖️
This tool is intended for:

Educational purposes and cybersecurity training

Password recovery for authorized systems

Security testing with proper permissions

Digital forensics investigations

⚠️ Important: Always ensure you have proper authorization before using this tool on any system. Unauthorized access to computer systems is illegal and unethical.

Contributing 🤝
Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

License 📄
This project is licensed under the MIT License - see the LICENSE file for details.

Disclaimer 🛡️
This tool is provided for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this program.

Happy ethical hacking! 🔒✨
