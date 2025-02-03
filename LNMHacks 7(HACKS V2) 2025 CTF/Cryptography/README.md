## CRYPTOGRAPHY

### 1) Operation LockDown 

 ![image](https://github.com/user-attachments/assets/085200e7-fc11-4e3f-a5d9-4d16186d5132)


In `Readme.txt`

![image](https://github.com/user-attachments/assets/29bcd7e9-363c-439e-bc60-e35c80832c2b)


![image](https://github.com/user-attachments/assets/c862585c-4473-4e5f-9399-cf9ae1ab5bc7)


password for Step1.zip : `Butterfly3`

Another `Readme.txt` inside and also has `THEFLAG.zip` , `wordlist.zip`

![image](https://github.com/user-attachments/assets/2ea09732-047b-44b3-9f29-ca3da94c733d)

![image](https://github.com/user-attachments/assets/f160cd8e-294f-494a-b8df-4a6a6e313d30)


password for **wordlist.zip** : `Password@123`

using the given wordlist **password.lst , again bruteforced with john and got** 

password for **`THEFLAG.zip`** : `p455w0rdn01f0und`

![image](https://github.com/user-attachments/assets/0d0343de-349e-41e2-8c86-2ce29b351c44)


second part found in another pdf file which was extracted using `binwalk -e combined.png`

or use `aprisolve.com`

![image](https://github.com/user-attachments/assets/656c3647-7faa-4185-9084-657fb2e933b9)


`hacks{HASH__cr4ck1ng}`

----

### 2) 1's & 0's

I was sent this file. Please help me decrypt the text and find the flag.

given 20 lines of binary code.  
Look at each bit position across all rows in `column by column`  
If at least one column has 1, we take 1, otherwise, we take 0.  
Form the final binary string.  
Convert it into text using ASCII decoding.  
Print the final flag.  
Eg :  
   ![image](https://github.com/user-attachments/assets/7c829312-64b8-4d99-93c9-97926f7de01e)

Python code to get flag  

```
cipher = ['01101000011000000100000001100001011100000101101100101001001000000101010001000100000000000000010000011000000100000100001000110000010001000100000000010000001101000100101100111100', '00001000010000000110000000100001010000010101101000100001001100000011010001000100000100000100010001000111000100000100010101010011010101000100001000110000001000000100001100111000', '01100000001000000100000001100001010100010110001101100001001100000101010100000000000100000000110001010010000100000100111001010011000001000110001000010000001001000100101001111100', '01101000000000000100000100100001010000010001101000101001001000000011010101000001001000000010011001010010000101000000000001110001000001000011001000010001001001000110100101110100', '01101000001000010100000000100000010100100101101100100001001000000001010001000110000100000100010000010100001100000000100101010000010001000111000000010001001000000110100000111000', '01101000010000000100000100100011010100010001101100001001001100000000010001000001000000000100110001000001000100000000010101110000000001000101000000010000001001000100001100111000', '00101000000000010100000100100001010100110101101100100001001000000011010101000110001100000000010000010110000100000100100001010010010001000001000000010010001000000110101100110001', '00101000001000010100000100100001011100100110101001100001001000000000010101010000000000000100010001000000000100000001110100010001010101000101001000010001001001000110000100011000', '01101000001000000100000000101001010100100001101000100001001100000010010001001011000100000000010001011100001100000000110101110001010001000100000000010001001001000100001100110000', '00100000000000010110000100101000010100010100101001010001001100000000000001000000000100000100000001000110000100000100011101010011010101000101001000010000001101000100001101111100', '00100000011000000100000101100001010100100001101001000001001000000011010001001100000100000000000001011000001100000100100001110001010101000101000000010001001001000110000100111000', '01101000010000000100000100100001011100000010000000000001001000000010010101000001000100000010100001010000001100000001110000010001000101000110000000010000000000000100101101011100', '00100000000000000100001101100001010100110101100101100001001100000100000101001111000100000110010001010110000100000100111000110001010001000100000000010000001100000110101101111101', '00100000000000000110000100000011010100110010101001100001001000000010010000000000000000000000011001000000001000000001010001110001010001000100001000010000001001000100101101111100', '01101000000000000110000000100001011100110100101001001001000100000010010100010001000100000100010000010010000101000000010001110010010100000111000000000001001001000100101100011100', '00101000000000000110000000100001010100010000101001101001001000000111010101001101000100000000011001011110000101000100010101010000010001000111000000010000001101000110001100110100', '01101000001000000100000001100000010100010000001001100001001000000111010101000110001100000010110000011000000100000100110100010000010001000011000000010000001001000100101100111000', '01100000001000000100000000000011010100100000101000100001001100000001010001001100001100000100010001010100000100000100110001010001000001000100001000010000001101000110001001010000', '01101000010000000100000100101011010100100011100101000001001100000011010101000100001100000110010001011000001100000101110001010000010101000100001000000001000001000110001100111100', '01101000001000000110000000100001010100110000101001100001001000000010010001000100001100000000010001001000001100000001100101010001001101000111000000010001001001000010101101011000']
from Crypto.Util.number import *
flag = ""
for i in range(len(cipher[0])):
   f = "0"
   for j in range(20):
       if cipher[j][i]=="1":
           f = "1"
   flag += f
print(long_to_bytes(int(flag, 2)).decode())
```

`hacks{y0u_0n_4_str34k}`

----

### 3)Digital Fortress

![image](https://github.com/user-attachments/assets/2317516f-c6c2-4564-b5a6-cb2f59c4ca1a)  

which was in given pdf
Write up :-
 The key mentioned in the challenge riddle points to 3, and by applying Rail Fence decryption you can find the phrase.  
 Adding appropriate spaces between the words you get another riddle which points to the country Peru.  
 ![image](https://github.com/user-attachments/assets/8a583cdb-710a-4d05-9830-5478feb2448f)  
 `hacks{peru}`

 ----

### 4)Lost Code of Atlas  
The Vanguards found this written on a piece of paper: lovectf.lnmhacks And this: 0CE4A410E54BA0C19B4D992922E938B2    
To decrypt : https://www.devglan.com/online-tools/aes-encryption-decryption
![Screenshot 2025-01-31 013412](https://github.com/user-attachments/assets/f8534cb0-dbaf-4dc2-a021-32a44f48b93f)


This is a AES encryption. And the key is lovectf.lnmhacks
 `hacks{anel_cif}`

 ----

 ### 5)Someone Corrupted my Image    
 Someone painted over this image. I need to decrypt this data ASAP!! Please help me decrypt this!

![image](https://github.com/user-attachments/assets/f379c71c-eba2-4e5d-96fb-fa9e359dfb40)  

In this question, the last two characters of the key are hidden. The task is to first find the correct key using the ciphertext. Then use it to find the Initialisation Vector which is the flag.

The following script can be used to find the flag.
```
from Crypto.Cipher import AES
import binascii
import string
import itertools

# given
bKEY = "lnmhacks87AB$$"

# use null bytes to minimize effect on output
IV = "\x00"*16


def encrypt(message, passphrase):
   aes = AES.new(passphrase, AES.MODE_CBC, IV)
   return aes.encrypt(message)


def decrypt(cipher, passphrase):
   aes = AES.new(passphrase, AES.MODE_CBC, IV)
   return aes.decrypt(cipher)


pt = "The message is protected by AES!"
ct = "0400000000000000000000000000bf9a1fd124436d6d503d7fe7bca2fbd3d6b1454906b0e413b54f29ae59804256c825"


# find the key using the plaintext and ciphertext we know, since the IV has no effect on the decryption of the second block
for i in itertools.product(string.printable, repeat=2):
   eKEY = ''.join(i)
   KEY = bKEY + eKEY
   ptc = decrypt(binascii.unhexlify(ct), KEY)
   if ptc[16] == pt[16] and ptc[30] == pt[30] and ptc[31] == pt[31]:
       print "Got KEY: " + str(KEY)
       fKEY = KEY
       pt2 = binascii.hexlify(decrypt(binascii.unhexlify(ct), fKEY))[32:]
       print "Decrypting with CT mostly zeroes gives: " + pt2
       print "Should be: " + binascii.hexlify(pt[16:])

       # we can now recover the rest of the ciphertext ct by XOR(pt[i], decrypted[i], since we chose ct 00 in all the positions we are going to recover
       
       answer = ""
       for i in range(13):
           pi = pt[17+i]  # letters from the plaintext
           pti = pt2[2*i+2:2*i+4]  # 2 hex letters from decryption of second block
           answer += "%02X" % (ord(pi) ^ int(pti, 16))
       rct = ct[0:2] + answer.lower() + ct[28:]
       print "Which means CT was: " + rct


# now we can decrypt the recovered ct and xor against the pt to recover the IV
wpt = decrypt(binascii.unhexlify(rct), fKEY)
IV = ""
for i in range(16):
   p = ord(pt[i]) ^ ord(wpt[i])
   IV += "%02X" % p
IV = binascii.unhexlify(IV)


# sanity check:
aes = AES.new(fKEY, AES.MODE_CBC, IV)
print "Sanity check: " + aes.decrypt(binascii.unhexlify(rct))


# We won!
print "The IV is: " + IV
```

 `hacks{1V_H1dd3n}`

 
