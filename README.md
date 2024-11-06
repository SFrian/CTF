# CTF Preparation Guide

This repository is a comprehensive guide to prepare for Capture the Flag (CTF) challenges across various fields, including Web Exploitation, Digital Forensics, Cryptography, Reverse Engineering, and Binary Exploitation. Each section lists tools and resources for learning and practicing skills required for CTF competitions.

---

## Table of Contents
- [Web Exploitation](#web-exploitation)
- [Digital Forensics](#digital-forensics)
- [Cryptography](#cryptography)
- [Reverse Engineering](#reverse-engineering)
- [Binary Exploitation](#binary-exploitation)
- [Additional Resources](#additional-resources)

---

## Web Exploitation

Tools and resources for web vulnerability testing, including common CTF vulnerabilities such as SQL injection, XSS, and directory brute-forcing.

### Tools
- **[Burp Suite](https://portswigger.net/burp)** - Web vulnerability scanner for testing SQL injection, XSS, and other web exploits.
- **[OWASP ZAP](https://www.zaproxy.org/)** - Another web application security scanner.
- **Nikto** - Web server scanner to detect configuration issues and common vulnerabilities.
- **Gobuster** - Directory/file brute-forcing tool to find hidden resources on a server.

### Resources
- **[PortSwigger Labs](https://portswigger.net/web-security)** - Practice labs for common web exploits.
- **[OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)** - Comprehensive testing guide for web security.

---

## Digital Forensics

Tools and resources to analyze files, recover data, and investigate digital evidence for CTF forensics challenges.

### Tools
- **[Autopsy](https://www.sleuthkit.org/autopsy/)** - GUI tool for digital forensics, ideal for disk image analysis.
- **[FTK Imager](https://accessdata.com/products-services/forensic-toolkit-ftk)** - Tool for creating disk images and analyzing file structures.
- **Wireshark** - Network packet analyzer, helpful for inspecting pcap files.
- **Binwalk** - Firmware analysis tool for extracting files and embedded resources.

### Resources
- **[CyberDefenders](https://cyberdefenders.org/)** - Platform for digital forensics challenges.
- **[Forensics Wiki](https://forensicswiki.xyz/)** - Guide to forensics tools, techniques, and CTF practices.

---

## Cryptography

Essential tools and guides for solving cryptography challenges, from basic ciphers to hash cracking.

### Tools
- **[CyberChef](https://gchq.github.io/CyberChef/)** - Web-based tool for encryption, decryption, and data transformations.
- **[Hashcat](https://hashcat.net/hashcat/)** / **John the Ripper** - Powerful tools for password and hash cracking.
- **Python** - A scripting language for writing custom cryptographic scripts, including libraries like `pycryptodome`.

### Resources
- **[CryptoPals](https://cryptopals.com/)** - Practice challenges covering cryptography concepts.
- **[OverTheWire: Krypton](https://overthewire.org/wargames/krypton/)** - CTF exercises focusing on cryptography.

---

## Reverse Engineering

Tools and resources for disassembling, decompiling, and analyzing binaries for reverse engineering tasks.

### Tools
- **[Ghidra](https://ghidra-sre.org/)** - Open-source tool for disassembly, decompilation, and reverse engineering.
- **IDA Free** - Powerful reverse engineering tool with analysis and decompilation features.
- **[Radare2](https://rada.re/n/)** - Open-source reverse engineering framework for binary analysis.
- **x64dbg** - Debugger for Windows, commonly used for reverse engineering tasks.

### Resources
- **[Binary Exploitation on CTF 101](https://ctf101.org/binary-exploitation/)** - Introductory resource for binary exploitation.
- **[Reverse Engineering on OpenSecurityTraining](https://opensecuritytraining.info/IntroReverseEngineering.html)** - Free courses on reverse engineering fundamentals.

---

## Binary Exploitation

Tools and guides for understanding and exploiting binary programs, often through buffer overflows, ROP chains, and shellcoding.

### Tools
- **pwntools** - Python library for rapid exploit development.
- **GDB** (with **Pwndbg** or **GEF** plugins) - Debugger with plugins tailored for CTF binary exploitation.
- **ROPgadget** - Tool for finding ROP (Return Oriented Programming) gadgets in binaries.
- **Patchelf** - Utility for modifying ELF binaries, useful for various binary exploitation tasks.

### Resources
- **[pwn.college](https://pwn.college/)** - Practical CTF-style challenges for binary exploitation.
- **[ROP Emporium](https://ropemporium.com/)** - Training exercises for Return Oriented Programming.

---

## Additional Resources

- **[CTFtime](https://ctftime.org/)** - Calendar for upcoming CTF events, along with write-ups and practice materials.
- **[Hack The Box](https://www.hackthebox.eu/)** - Platform offering a wide range of hands-on labs covering all fields of cybersecurity.
- **Docker** - Recommended for setting up isolated environments for CTF challenges.

---

## Notes
This guide is optimized for users of [Kali Linux](https://www.kali.org/), which includes many of the tools mentioned above. Additional tools can be installed as needed.

Happy hacking and good luck with your CTF challenges!
