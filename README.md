Fileinfo_CRC32_SHA_Entropy_MASM
===============================

First project on GitHub, use at your own risk!

New:
  - Now with clipboard functionality
  - Now with three Hash functions: MD5, SHA1 and SHA256.
  - New memory allocation
  - Much faster due to parallel processing via Multithreading. 
  - Can calculate CRC32 and Hashes for arbitrary huge file sizes. For files > 2GByte entropy/frequency table generation will be skipped. 
  - Now precise size results!
  - Fixed minor CR-LF bug!

Purpose: 

  Get some fileinfos like:
  - CRC32
  - Shannon Entropy (the more unoredered the file the higher, maximum is 8)
  - SHA1-Hash (via Crypto-API)
  - SHA 256 Hash (via Crypto-API)
  - MD5 Hash (via Crypto-API) --> Insecure but still widely used, thus included!
  - Size of the files in Byte, KByte and MByte
  - Frequency table (use /f)
  - Type "CRC32 /?" for help.
  - Approx. comp. gives a feeling about how far the file can be compressed. Not very accurate though!
  
Syntax:
    CRC32 filename.ext [/f] [/1] [/2] [/5]
    /f for freq. table, /1 or /2 or /5 to copy SHA1, SHA256 or MD5 to clipboard!

Examples:
  - crc32 "Test File.ext" /f /2
  -> Will analyze and hash the file >>Test File.ext<<, give out the frequency table and copy the SHA256 to the clipboard.
  - crc32 TestFile.ext /f 
  -> Quotes are only needed for filenames with space characters. 
  - crc32 TestFile.ext
  -> Analyze the file without showing the frequency table.
  --> TIP: Use the Tab-Key to complete long filenames or paths! You can press it several times if needed.
     
Info:  
  - Written in Assembler 32 Bit, MASM, Marcus Roming.
  
To do: 
  - Info about packers, file headers etc.
  
Tested under Win7-64 and Win7-32.         

Hash values of current executable (V. 1.34), determined by the program itself of course:


CRC32 (HEX)  :  CD9E2A02

MD5   (HEX)  :  a46789f5823883e00928ed0e9e873cc1

SHA 1 (HEX)  :  c7a82bf9b647e6b5af50cc4a2c45040794f09f9c

SHA256(HEX)  :  c7ed07278bd6f85221bc9c3a332c1ad2c4fdbf85b19a15e12b87569b5d3a7ebf

File length  :  9728 Byte

File length  :  9.5 KByte

File length  :  0.00927 MByte

Freq. table  :  Use /f !

Entropy      :  5.751391

Approx. comp.:  6994 Byte


