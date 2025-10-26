# cryptography-algorithms

## Commands

* gcc fisier.c -o output
* ./output

### For Salsa generating the key:
* ./salsa20 -g

### Encrypting and Decrypting:

* ./salsa20 -e video.mp4 -o encrypted.bin -k key.txt
* ./salsa20 -d encrypted.bin -o output.mp4 -k key.txt

* ./chacha20 -e video.mp4 -o encrypted2.bin -k key.txt
* ./chacha20 -d encrypted2.bin -o output2.mp4 -k key.txt

### For RSA:
* gcc rsa.c -o rsa -lgmp
* ./rsa -e text.txt -o ciphertext.txt -k key.txt
* ./rsa -d ciphertext.txt -o decrypted.txt -k key.txt  
