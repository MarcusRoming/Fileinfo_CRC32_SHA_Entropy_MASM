Fileinfo_CRC32_SHA_Entropy_MASM
===============================

First project on GitHub, use at your own risk!

New:
  - Fixed bug that prevented hash creation on some systems due to user rights restrictions
  - Fixed a minor bug with broader console windows (missing CR_LF)
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
  - Written in Assembler 32 Bit, MASM, Marcus Roming. No guarantee whatsoever.
  
To do: 
  - Info about packers, file headers etc.
  
Tested under Win7-64 and Win7-32.         

Hash values of current executable (V. 1.38), determined by the program itself of course:

CRC32 (HEX)  :  170EE652

MD5   (HEX)  :  3ead4b325c6aef616da15fe723ac45fd

SHA 1 (HEX)  :  7f455425df14abc9a6094525f10a74fa403effc8

SHA256(HEX)  :  86297d6cf473080ec1b7b5a296e17b5ab945ae801c7f5a856654dc78f1fdf4a6

File length  :  10240 Byte

File length  :  10 KByte

File length  :  0.00976 MByte

Freq. table  :  Use /f !

Entropy      :  5.65884

Approx. comp.:  7243 Byte


