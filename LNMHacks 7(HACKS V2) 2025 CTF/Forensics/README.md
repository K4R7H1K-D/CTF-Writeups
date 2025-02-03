## FORENSICS

![image](https://github.com/user-attachments/assets/8df9a5a1-4018-40d4-88e3-74ae48289ac9)


Exported two objects at HTTP 

![image](https://github.com/user-attachments/assets/86a7a0c9-5325-43f1-993b-3eecdf810858)


it was two jpeg file

![image](https://github.com/user-attachments/assets/8726cb8b-cf48-4768-ac58-adb03daa4696)


![image](https://github.com/user-attachments/assets/42ec68e3-4c9c-41f5-b54e-b25bfeafb82e)


`hacks{sh4rk_b1t3$_p4ck37$}`

----

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

----

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
