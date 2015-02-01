# About

This project aims to help you when you have a faulty Firefox/Thunderbird installation or a corrupted filesystem (like in my case) to recover passwords from signons.sqlite and key3.db.
See file pswRecover4Moz.txt for full explanations!  

# Features  
* recover Passwords!!!
* some decryption function integrated (SHA1,DES3-EDE,...)
* minimal ASN.1 parser

# Requirements

Software:  
- gcc compiler (or other ANSI C/C++ compilers and linkers)
- libnss (optional,automatically installed w/ most of Mozilla products)
- sqlite3 library (libsqlite3.so)

# Installation and First Steps
* Clone this repository:  
    git clone https://github.com/philsmd/pswRecovery4Moz.git  
* Build pswRecovery4Moz:  
    cd pswRecovery4Moz 
    gcc pswRecovery4Moz.c -m32 -ldl -o pswRecovery4Moz 
* Check help:  
    ./pswRecovery4Moz -h 
* Use whatever functionality you need (see options and pswRecovery4Moz.txt)

# Hacking

* Improve posix compatibility
* Simplify the code
* Performance improvements
* Testing
* and,and,and

# Credits and Contributors 
Credits go to the main developers of OpenSSL (for some inspirations on SHA1 and DES3 decryption) and to Stephen Henson for his key3 research.
  
* Stephen Henson (DRH consultancy)
* OpenSSL team

Did I miss somebody? Please help me to complete the list if you think I missed somebody here!

# License

This project is lincensed under the **GNU GENERAL PUBLIC LICENSE version 3**.  
