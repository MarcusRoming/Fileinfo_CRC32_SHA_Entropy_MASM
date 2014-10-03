Fileinfo_CRC32_SHA_Entropy_MASM
===============================

First project on GitHub, use at your own risk!

New:
  - Now with three Hash functions: MD5, SHA1 and SHA256.
  - New memory allocation
  - Much faster due to parallel processing via Multithreading. 
  - Can calculate CRC32 and Hashes for arbitrary huge file sizes. For files > 2GByte entropy/frequency table generation will be skipped. 
  - Now precise size results!

Purpose: 

  Get some fileinfos like:
  - CRC32
  - Shannon Entropy
  - SHA1-Hash (via Crypto-API)
  - SHA 256 Hash (via Crypto-API)
  - MD5 Hash (via Crypto-API) --> Insecure but still widely used, thus included!
  - Size of the files (currently rounded, needs improvement)
  - Frequency table (use /f)
  - Type "CRC32 /?" for help.
  
Syntax:
  - crc32 "Test File.ext" /f
  -> Will analyze and hash the file >>Test File.ext<< and give out the frequency table.
  - crc32 TestFile.ext /f 
  -> Quotes are only needed for filenames with space characters. 
  - crc32 TestFile.ext
  -> Analyze the file without showing the frequency table.
  --> TIP: Use the Tab-Key to complete long filenames! You can press it several times if needed.
     
Info:  
  - Written in Assembler 32 Bit, MASM
  
To do: 
  - Add MD5 ?
  - Info about packers, file headers etc.
  - Clipboard commandline switches, to copy hash value to clipboard (/S1 /S256) with MASM lib SetClipboardText
  - Use "ALIGN" to speed up the program!
  
Tested under Win7-64 and Win7-32.         

--------------------------------------------------------------------------------------------------------------------------------------------------
Hash values of current executable, determined by the program itself of course:

>crc32 crc32.exe

CRC32 (HEX)  :  E801FBC7
MD5   (HEX)  :  11c7cfeeca9e85b4e9339bf4b93676fd
SHA 1 (HEX)  :  c1d1e99f4a9312e92506df7d1b49ed986ebebfef
SHA256(HEX)  :  019cfc8e706921946453f77b4585f5fffb1c18a3ee27b9739979d7aed83ddff9
File length  :  8704 Byte
File length  :  8.5 KByte
File length  :  0.00830 MByte
Freq. table  :  Use /f !
Entropy      :  5.195062
Approx. comp.:  5652 Byte
