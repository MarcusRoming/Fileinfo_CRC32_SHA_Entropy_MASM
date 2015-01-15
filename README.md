Fileinfo_CRC32_SHA_Entropy_MASM
===============================

First project on GitHub, use at your own risk!

New:
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
  - crc32 "Test File.ext" /f
  -> Will analyze and hash the file >>Test File.ext<< and give out the frequency table.
  - crc32 TestFile.ext /f 
  -> Quotes are only needed for filenames with space characters. 
  - crc32 TestFile.ext
  -> Analyze the file without showing the frequency table.
  --> TIP: Use the Tab-Key to complete long filenames! You can press it several times if needed.
     
Info:  
  - Written in Assembler 32 Bit, MASM, Marcus Roming.
  
To do: 
  - Info about packers, file headers etc.
  - Clipboard commandline switches, to copy hash value to clipboard (/S1 /S256) with MASM lib SetClipboardText
  
Tested under Win7-64 and Win7-32.         

Hash values of current executable, determined by the program itself of course:

CRC32 (HEX)  :  E60C5B4B
MD5   (HEX)  :  f3523887337f47c40118cf8efc6c096b
SHA 1 (HEX)  :  f10c1ad5cf0a638b912a88bdb06d405dee110629
SHA256(HEX)  :  bb621e507c922498c036cec6ea8506baac3a028d3edbc79bdf45ef519159fd7e
File length  :  8704 Byte
File length  :  8.5 KByte
File length  :  0.00830 MByte
Freq. table  :  Use /f !
Entropy      :  5.179952
Approx. comp.:  5636 Byte

