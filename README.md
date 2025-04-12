# Steganography-password
 
 encrypts passwords with AES and hides them in a PNG image using LSB steganography.
- i tried to use Steganography to store my password encrypted in pngs...purely for fun lol


# Warning!!!
DO NOT RELY ON THIS, I DO NOT KNOW IF THIS IS SECURE.
Use at own risk.

The author is not responsible for any data loss, security breaches, or misuse of this software.  
It is your responsibility to ensure the safe handling of encryption keys and stored passwords.

Do not use this tool for storing sensitive information in production or real-world environments unless you fully understand the risks and limitations.


## Test
You can test it with the existing output.png by using the encryption key: **x9mPqT7kRwY2nF5v**



## Setup 
```
git clone https://github.com/preaches/Steganography-password/
cd /Steganography-password/
java SteganoPassword.java
```


## Features

- AES encryption (128/192/256-bit)
- LSB steganography to hide passwords in images
- Console-based menu for storing/retrieving passwords


## Prerequisites

- JDK 11+
- IntelliJ IDEA


## NOTES
- i will probably make it "passwordmanager"-like in the future
- i want to add more file-types, just for fun
- add UI (console based is annoying sometimes)
