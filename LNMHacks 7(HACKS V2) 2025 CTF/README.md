# LNMHacks 7(HACKS V2) 2025 CTF

## by Ex0rcists
![image](https://github.com/user-attachments/assets/cc7f784a-31c9-427c-bbcc-8afca79d9864)

![image](https://github.com/user-attachments/assets/8a84b6f0-c078-4f17-b601-6173799045a2)




## WEB

**1)CVE-2011-2202
Exploit this :** http://43.204.215.29/

![image](https://github.com/user-attachments/assets/c2390e0e-4832-4796-bc95-3514b67f1d44)


**Analysis of the Challenge:**

1. The PHP snippet given in the challenge processes the query parameter `shroom`:
    
    ```php
    php
    CopyEdit
    $color = isset($_GET['shroom']) ? $_GET['shroom'] : 'death_cap';
    if ($shroom) {
        $data = include 'data/' . $shroom . '.php';
    }
    
    ```
    
    - Input is directly concatenated with the `include` statement (`'data/' . $shroom . '.php'`), potentially allowing path traversal or remote file inclusion.
2. The current mitigation checks if `shroom` references files in the `data/` directory with a `.php` extension, but lacks robust input sanitization.

**Vulnerability Overview (CVE-2011-2202):**

CVE-2011-2202 is a **PHP remote file inclusion (RFI)** vulnerability due to improper input validation in certain versions of PHP (specifically 5.2.x and others). It allows attackers to manipulate file paths and include remote or local files using crafted `include` statements.

**Path Traversal**

?shroom=../../../../../../../etc/passwd%00

- `%00` is a null byte that might terminate strings in older PHP versions to bypass the `.php` extension constraint.

![image](https://github.com/user-attachments/assets/da4a10e8-3fec-42a0-959b-66c9c970225c)


![image](https://github.com/user-attachments/assets/944b19ee-1642-49b5-a511-8c4573f1fb67)


![image](https://github.com/user-attachments/assets/f917da11-033d-41e8-bbee-4aff3674e8e3)


at `source code`

1)First part of the flag: hacks{WH

2)<!--second part of the flag: OO_t -→

at `css file` 

3)Here's part 3: h3_U1_1 */

at `robots.txt`  

4)Part 4  of the flag: s_4m4zin

 This is an apache server (I guess)... can you *Access* the next flag?

at `.htaccess` 

5)Part 5: g_R1ght_

You know just use the flag created so far, and find something good

at `hacks{WHOO_th3_U1_1s_4m4zing_R1ght_` path

6)"HAHAHAHA Final Part: gu7$?}\00\00")

Combined all 6 parts 

`hacks{WHOO_th3_U1_1s_4m4zing_R1ght_gu7$?}`

## BINARY EXPLOITATION

![image](https://github.com/user-attachments/assets/16a552db-31cb-4824-a64d-bb6c6f95cc64)


tool : https://github.com/pwndbg/pwndbg

using pwngdb tool, To know the starting address BSS stack .

`info file`

![image](https://github.com/user-attachments/assets/be604d2e-b4a5-4a1b-8de6-83e700da3ba0)


To know the stored name at 1140 ,

`info function`

![image](https://github.com/user-attachments/assets/070c0cab-000a-46eb-97ba-bb893e4181cc)


`hacks{4010+frame_dummy}`

## REVERSE ENGINERRING

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

## OSINT

![image](https://github.com/user-attachments/assets/8a4a1da4-0ce9-405b-bdfd-c259791728e8)


![image](https://github.com/user-attachments/assets/9f30c743-f09a-4cff-a053-55d582b6d33a)

To identify the country in this image , Given to gpt and analyze with  Architecture and Landscape and Road Markings and Signage.

1. Architecture and Landscape:

The structures in the background resemble modern architectural styles found in large public facilities, potentially an airport or a major transport hub.

The landscaping includes neatly trimmed trees and well-maintained flower beds, which are typical in affluent or highly organized regions.

1. Road Markings and Signage:

The road markings, including the arrows and yellow borders, suggest adherence to international traffic standards, common in many countries.

The black-and-yellow curbs indicate a parking or entry zone, often seen in the Middle East and South Asia.
Given these details, this location is consistent with infrastructure in countries like United Arab Emirates (UAE), Qatar, or Saudi Arabia. Based on the modern design and greenery, UAE (possibly near Dubai or Abu Dhabi) seems most probable.

Upon further analysis of the image and its features, the country is most likely Oman.

`hacks{Oman}`

![image](https://github.com/user-attachments/assets/c6cad6fc-dfd9-465b-b102-ac0288085018)


If you zoom this given image , name mentioned `Paris,lle-de-France`

![image](https://github.com/user-attachments/assets/79a83af7-efe5-4da4-bcf0-8ade4ccaa7bd)


![image](https://github.com/user-attachments/assets/c3efe4cd-df4f-4109-8319-e087ca7901a0)


`hacks{Gare_de_l’Est}`

## GENERAL

![image](https://github.com/user-attachments/assets/6a4a80a6-a679-49ee-be36-450a332a1033)


https://deobfuscate.io/

Deobfuscated javascript

![image](https://github.com/user-attachments/assets/a54731b2-b05f-41b2-99af-053bcadaf157)


again deobfuscated with this https://obf-io.deobfuscate.io/ to get flag

![image](https://github.com/user-attachments/assets/776d3168-349c-402f-8f43-852f9d2fd501)


## CRYPTOGRAPHY

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

## FORENSICS

![image](https://github.com/user-attachments/assets/8df9a5a1-4018-40d4-88e3-74ae48289ac9)


Exported two objects at HTTP 

![image](https://github.com/user-attachments/assets/86a7a0c9-5325-43f1-993b-3eecdf810858)


it was two jpeg file

![image](https://github.com/user-attachments/assets/8726cb8b-cf48-4768-ac58-adb03daa4696)


![image](https://github.com/user-attachments/assets/42ec68e3-4c9c-41f5-b54e-b25bfeafb82e)


`hacks{sh4rk_b1t3$_p4ck37$}`

![image](https://github.com/user-attachments/assets/7326e76e-6523-44a7-9129-35e694a59475)


After extracted the tar file

it has 2 files, `randomfile` and `file`

using HxD editor

found the given random file is `jpg` file based on `magic bytes`(jpg end hex value) which is FF D9

![image](https://github.com/user-attachments/assets/cc8def45-eea2-40e7-9765-02a489da66dc)


But starting hex value not there, add to it 

![image](https://github.com/user-attachments/assets/24ebd42c-6924-4ca8-9c01-b41c601ee25e)


insert  `FF D8 F E0 00 10 4A 46 49 46` at start, the hex values which also given in end of `file` which they given and save file with extension `.jpg`

![image](https://github.com/user-attachments/assets/4473e2c6-a99d-41d7-9eae-eef81abef957)


but this is fake flag,

![image](https://github.com/user-attachments/assets/a3aadd2c-7066-4475-8c53-67d952ffc82b)


using `stegseek` tool , 

![image](https://github.com/user-attachments/assets/b6abc6d2-6f7f-4a99-a691-ca385d6f032b)


`hacks{4re_y0u_4_ch1ll_guy}`

![image](https://github.com/user-attachments/assets/63186bd7-426f-4774-9446-6ae01e37567e)


it has nothing in given ppt

![image](https://github.com/user-attachments/assets/d0709194-27f5-4b27-9b0e-7cac3787fdad)


but the MACRO was hint,

Macros are **sequences of commands or actions that you can record and save in PowerPoint, and then run whenever you need to perform the same task again**

basically  **PPT file (PowerPoint presentation) is essentially a zipped file**, meaning it contains a collection of smaller files compressed together within a single package, allowing for efficient storage and sharing; technically, a .pptx file is a zipped folder with XML-based data representing the presentation elements like text, images, and formatting

so, changed extension as zip and viewed at macro at `file.zip\ppt\slideMasters\_rels` 

![image](https://github.com/user-attachments/assets/0a2af7da-10c3-4b81-aac6-ccf34f00708f)


but, there are 1000 folders , but if you looked at size,

![image](https://github.com/user-attachments/assets/744e8d19-4dd3-45bc-84bd-bccbaa61489f)

last folder is different from all , so opened it and got hex values in `macro.vba` file

`68 61 63 6b 73 7b 79 30 75 5f 66 30 75 6e 44 5f 4d 33 7d`

converted to strings

`hacks{y0u_f0unD_M3}`

## STEGANOGRAPHY

![image](https://github.com/user-attachments/assets/7abb22a4-83db-4a1b-9e89-77ff14438fb8)

`strings landscape.jpg`

![image](https://github.com/user-attachments/assets/cc6a3c2d-5939-4ad6-b877-5d1b5e94b119)


`base64` encoding found at center

![image](https://github.com/user-attachments/assets/8bac3388-8059-4481-82d5-746caeef8d7b)


***Moscow Standard Time(MSK) is 2 hours and 30 minutes behind India Standard Time***

19:30 + 02:30 = 22:00

`hacks{2200}`
