## REVERSE ENGINERRING

### 1) 100% Discount
![image](https://github.com/user-attachments/assets/86e07178-fc49-402a-ad93-210701e28fee)


Analyzed with GHIDRA tool 

![image](https://github.com/user-attachments/assets/429e2b68-abf8-4e9d-a4e7-6f5afe10a47e)


Python snippet to decrypt this:

```python
x = "BKIAYQ^CXONuELuREXYW"
key = 0x2a
f = ''.join([chr(ord(c) ^ key) for c in x])
print(f)

```

`hacks{tired_of_xors}`

----

### 2) Basic Reverse
![image](https://github.com/user-attachments/assets/767feb6f-e09c-4c18-ab57-2cbb5f85e8ea)


Analyzed with ghidra , 

in `rev_this` file , it contains `_hacks_{w1{1wq8]8lle<,T}`

![image](https://github.com/user-attachments/assets/9e8ca92d-0497-49b6-8f38-80d25e827955)


**Walkthrough of Decryption**

1. **First 8 Characters**:
    - `_hacks_{` is directly taken as it is.
2. **Decrypting Modified Middle Characters** (`w1{1wq8]8lle<`):
    - Apply the reverse logic based on even/odd indices:
        - Even → Subtract 5.
        - Odd → Add 2.
    - Process each character accordingly.
3. **Last Character** (`T`):
    - Add it directly to the decrypted flag.
4. **Combine Everything**:
    - Result is the fully reconstructed flag.

```python
def decrypt_flag(encrypted_text):
    # Extract parts of the encrypted text
    first_part = encrypted_text[:8]  # First 8 characters (unchanged)
    modified_part = encrypted_text[8:23]  # Middle part to decrypt
    last_character = encrypted_text[-1]  # Include 'T'

    # Start building the decrypted flag
    decrypted_flag = first_part

    # Decrypt the modified middle part
    for i, char in enumerate(modified_part):
        if i % 2 == 0:  # Even index in modified part -> 5 was added
            decrypted_flag += chr(ord(char) - 5)
        else:           # Odd index in modified part -> 2 was subtracted
            decrypted_flag += chr(ord(char) + 2)

    # Append the last character (T)
    decrypted_flag += last_character

    return decrypted_flag

# Encrypted text in flag.txt
encrypted_text = "_hacks_{w1{1wq8]8lle<,T}"
decrypted_flag = decrypt_flag(encrypted_text)
print("Decrypted Flag:", decrypted_flag)

```

`hacks{r3v3rs3_3ngg7.O}`

----
### 3) Gnireenigne Esrever

![image](https://github.com/user-attachments/assets/fb030ddf-d9bf-416e-a39e-89262efd599a)


We Got 1st BLOOD 🩸for this challenge

step 1 : r2 -AA binfile             //flag(to know detail r2 documentation)

![image](https://github.com/user-attachments/assets/a9bdf74d-2a52-458a-91a0-27021c3f732a)


step 2: afl            // analyze list of fn

![image](https://github.com/user-attachments/assets/fe46754e-c41e-4b91-9368-b9335135fb00)


step 3: pdf @ sym.main

![image](https://github.com/user-attachments/assets/67e098f4-519c-4485-9a06-a81e745083ab)


![image](https://github.com/user-attachments/assets/716e249c-465b-4a85-9b55-800d79bed084)


at  memory of the  obj.ENCRYPTED_FLAG which was `;s1r0%6-`

step 4: pdf @ sym.transform_input   // at this function it is XOR 

![image](https://github.com/user-attachments/assets/0cdad8c2-b566-4cd5-913f-f34724b23381)


 bruteforce xor key from 1 to 16 bytes using dcode

![image](https://github.com/user-attachments/assets/48f63133-ecda-48cb-9424-711225aef548)


`hacks{x0rlsfun}`
