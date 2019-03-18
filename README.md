# Jabber PRT Processor

PRT decryption and rename tool. 
This tool will take collected PRTs, decrypt them (if needed), get user's login and rename original PRT.


## Getting Started

After pulling the repo you need to put the 'prt_processor.py' to the directory with collected PRTs and private key. The key itself should be named 'private_key.pem'. Within the same directory sub-directories 'processed' and 'decrypted' should be created.

Required structure:
.
├──root_directory
    ├── prt_processor.py                   
    ├── PRT_1.zip.enc                     #
    ├── PRT_1.zip.esk                     #
    ├── ...                               # Encrypted Jabber Problem Reports and keys
    ├── PRT_N.zip.enc                     # 
    ├── PRT_N.zip.esk                     #    
    ├── private_key.pem                   # Private key
    ├── processed                         
    ├── decrypted
    └── README.md

After script run PRTs could be found in 'processed' directory.
