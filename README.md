# SystemSecurity-DD2497
This started as a four-people project for the system security course but ended with me as the sole contributor in almost everything. The project tries to safeguard the Minix microkernel from buffer overflows by implementing stuck and heap randomization and implement a File System Encryption scheme to secure critical files in a per user basis.

# Features
- ASLR to counter common buffer overflows
- Implemented File System Encryption
- Expanded the FS encryption scheme to handle different users
- Encryption is achieved by using AES_XTS_256 and CMAC to guarantee integrity and thwart certain maleability attacks
