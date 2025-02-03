## by Ex0rcists

## WEB

**1)CVE-2011-2202
Exploit this :** http://43.204.215.29/

![image.png](attachment:0304a847-d2a5-40af-a5c1-9cc55614e22a:image.png)

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

![image.png](attachment:eec2e9ee-dda4-450d-892c-bcda424ee557:image.png)

![image.png](attachment:67e8baf3-0dc5-4e82-a8a4-222d017b3428:image.png)

![image.png](attachment:2ea2dbe6-192e-4800-9a71-76544a961475:image.png)

at `source code`

1)First part of the flag: hacks{WH

2)<!--second part of the flag: OO_t -→

at `css file` 

3)Here's part 3: h3_U1_1 */

at `robots.txt`  

4)Part 4  of the flag: s_4m4zin

# This is an apache server (I guess)... can you *Access* the next flag?

at `.htaccess` 

5)Part 5: g_R1ght_

You know just use the flag created so far, and find something good

at `hacks{WHOO_th3_U1_1s_4m4zing_R1ght_` path

6)"HAHAHAHA Final Part: gu7$?}\00\00")

Combined all 6 parts 

`hacks{WHOO_th3_U1_1s_4m4zing_R1ght_gu7$?}`

## BINARY EXPLOITATION

![image.png](attachment:77744418-6135-4427-8771-779eb829aa6e:image.png)

tool : https://github.com/pwndbg/pwndbg

using pwngdb tool, To know the starting address BSS stack .

`info file`

![image.png](attachment:799e7621-fe77-4247-bbe2-103dff0d6630:image.png)

To know the stored name at 1140 ,

`info function`

![image.png](attachment:cfb83dfe-ed66-4620-b34e-170f2f3714d6:image.png)

`hacks{4010+frame_dummy}`

## REVERSE ENGINERRING

![image.png](attachment:0743a5ae-3bb7-475c-9b4d-081bea339f54:image.png)

Analyzed with GHIDRA tool 

![image.png](attachment:b84bf5b1-f2ed-4fd4-b0ff-a9c22833bf0c:image.png)

Python snippet to decrypt this:

```python
x = "BKIAYQ^CXONuELuREXYW"
key = 0x2a
f = ''.join([chr(ord(c) ^ key) for c in x])
print(f)

```

`hacks{tired_of_xors}`

![image.png](attachment:3bf71916-983d-40ed-89df-8f857c8a45d0:image.png)

Analyzed with ghidra , 

in `rev_this` file , it contains `_hacks_{w1{1wq8]8lle<,T}`

![image.png](attachment:6c4f2ab1-672b-4a7e-9b3f-0814eda21c0f:image.png)

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

![image.png](attachment:7d9725c5-3c75-45b7-8907-eb3324aff636:image.png)

`hacks{r3v3rs3_3ngg7.O}`

![image.png](attachment:061a9f59-dd80-4a80-b66b-7e2a78be8605:image.png)

We Got 1st BLOOD 🩸for this challenge

step 1 : r2 -AA binfile             //flag(to know detail r2 documentation)

![image.png](attachment:f2d86310-e27c-446f-8b77-9b5bc8ea0855:image.png)

step 2: afl            // analyze list of fn

![image.png](attachment:64583a4b-64dd-4dbe-abce-3fb7dc96164a:image.png)

step 3: pdf @ sym.main

![image.png](attachment:1ce332ef-476c-4385-a4e9-d404e65a8859:image.png)

![image.png](attachment:03cdaece-1180-4bee-af12-478297d4c6da:image.png)

at  memory of the  obj.ENCRYPTED_FLAG which was `;s1r0%6-`

step 4: pdf @ sym.transform_input   // at this function it is XOR 

![image.png](attachment:0c0b7a6d-fcfa-4b7d-884a-18385212af5c:image.png)

 bruteforce xor key from 1 to 16 bytes using dcode

![image.png](attachment:9f6ca37f-cde2-4b0b-980e-21cd77775c4e:image.png)

`hacks{x0rlsfun}`

## OSINT

![image.png](attachment:63d4f5bb-ac0c-46c2-81c5-cc63810098af:image.png)

![Screenshot_2025-01-24_053440.png](attachment:c5604191-0f98-4ac8-a276-a6ab7239df65:Screenshot_2025-01-24_053440.png)

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

![image.png](attachment:eed9fbc9-4e89-41b2-8e0f-15914ea25302:image.png)

If you zoom this given image , name mentioned `Paris,lle-de-France`

![image.png](attachment:03b0e3ae-c299-4fd7-8fad-566cd873eacd:image.png)

![image.png](attachment:d26f5a51-956c-45f1-81c8-851ffdb82eb3:image.png)

`hacks{Gare_de_l’Est}`

## GENERAL

![image.png](attachment:8105efd5-f3d2-499e-b5cb-95b7785fe9f2:image.png)

https://deobfuscate.io/

Deobfuscated javascript

![image.png](attachment:601ab9cc-d61f-4739-9e8e-ddf3e892bf1d:image.png)

again deobfuscated with this https://obf-io.deobfuscate.io/ to get flag

![image.png](attachment:6822cec8-1605-4a80-9e02-70af43649784:image.png)

## CRYPTOGRAPHY

![image.png](attachment:1143f20e-da8d-4df8-b739-1e417853fba9:image.png)

In `Readme.txt`

![image.png](attachment:e4da21c1-1b9f-43c8-bd68-9aedbdf9ff71:image.png)

![image.png](attachment:9e3a4a2e-84b1-462a-a3f1-f5a0e7acc636:image.png)

password for Step1.zip : `Butterfly3`

Another `Readme.txt` inside and also has `THEFLAG.zip` , `wordlist.zip`

![image.png](attachment:4af3eaea-ca08-4a4a-be6d-d7c6b87860c0:image.png)

![image.png](attachment:8fa82bf4-f8b4-4560-a715-f0da606eaa62:image.png)

password for **wordlist.zip** : `Password@123`

using the given wordlist **password.lst , again bruteforced with john and got** 

password for **`THEFLAG.zip`** : `p455w0rdn01f0und`

![combined.png](attachment:51051db6-69cd-4d29-9230-8a549499eccb:3b777553-275e-4369-8969-cfb041b3eda0.png)

second part found in another pdf file which was extracted using `binwalk -e combined.png`

or use `aprisolve.com`

![image.png](attachment:bb3be5e2-d87b-47a8-b9e8-547c80d5acf7:image.png)

`hacks{HASH__cr4ck1ng}`

## FORENSICS

![image.png](attachment:1cef77b0-7579-40a2-8b5f-555f9146a288:image.png)

Exported two objects at HTTP 

![image.png](attachment:b28b0567-f15d-44b6-914b-8bff08f9a884:image.png)

it was two jpeg file

![image.png](attachment:db0d1712-1563-460c-8526-de0bb44e00ce:image.png)

![image.png](attachment:8d0641f3-d5b0-4b33-b6ca-75a38e17b771:image.png)

`hacks{sh4rk_b1t3$_p4ck37$}`

![image.png](attachment:ad6d8571-37cb-4a93-b765-f50c36d5d55d:image.png)

After extracted the tar file

it has 2 files, `randomfile` and `file`

using HxD editor

found the given random file is `jpg` file based on `magic bytes`(jpg end hex value) which is FF D9

![image.png](attachment:5a91621a-a285-42ea-85c9-61abf4e9c2f9:image.png)

But starting hex value not there, add to it 

![image.png](attachment:da8d3953-39bc-4e09-a952-39f5735760e2:image.png)

insert  `FF D8 F E0 00 10 4A 46 49 46` at start, the hex values which also given in end of `file` which they given and save file with extension `.jpg`

![image.png](attachment:19e6ebe1-b5d0-48d5-bf07-f5f1bf98f852:image.png)

but this is fake flag,

![Untitled2.jpg](attachment:0d093c62-7698-4e0a-a1dc-ebc73cc08ba8:Untitled2.jpg)

using `stegseek` tool , 

![image.png](attachment:5f871276-3aea-4e5c-a175-722d5e0d5e47:image.png)

`hacks{4re_y0u_4_ch1ll_guy}`

![image.png](attachment:254c0ce8-1c19-42c0-b3c4-2362f43b8893:image.png)

it has nothing in given ppt

![image.png](attachment:4d072ee4-308c-4d93-a73c-785241054acd:image.png)

but the MACRO was hint,

Macros are **sequences of commands or actions that you can record and save in PowerPoint, and then run whenever you need to perform the same task again**

basically  **PPT file (PowerPoint presentation) is essentially a zipped file**, meaning it contains a collection of smaller files compressed together within a single package, allowing for efficient storage and sharing; technically, a .pptx file is a zipped folder with XML-based data representing the presentation elements like text, images, and formatting

so, changed extension as zip and viewed at macro at `file.zip\ppt\slideMasters\_rels` 

![image.png](attachment:ce770dff-ff44-4c8e-80b2-3637ec148de5:image.png)

but, there are 1000 folders , but if you looked at size,

![image.png](attachment:bf2e0f85-edea-4538-9f90-432a7442a2c9:image.png)

last folder is different from all , so opened it and got hex values in `macro.vba` file

`68 61 63 6b 73 7b 79 30 75 5f 66 30 75 6e 44 5f 4d 33 7d`

converted to strings

`hacks{y0u_f0unD_M3}`

## STEGANOGRAPHY

![image.png](attachment:ac3ff271-06e7-44cd-acc9-7aea133d6be8:image.png)

`strings landscape.jpg`

![image.png](attachment:7e3e578c-69c7-4f6c-a1f0-dd13c62e719a:image.png)

`base64` encoding found at center

![image.png](attachment:4098fb50-e96d-470e-8446-4c634f3dab7f:image.png)

***Moscow Standard Time(MSK) is 2 hours and 30 minutes behind India Standard Time***

19:30 + 02:30 = 22:00

`hacks{2200}`
