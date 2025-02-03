## WEB

### 1)CVE-2011-2202
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

----

### 2) What is this weird site?

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
