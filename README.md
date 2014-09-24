Fileinfo_CRC32_SHA_Entropy_MASM
===============================

First project

New:
  - New Hash (SHA 256)
  - New memory allocation
  - Much faster due to parallel processing via Multithreading. 
  - Can calculate CRC32 and Hashes for arbitrary huge file sizes. For files > 2GByte entropy/frequency table generation will be skipped. 

Purpose: 

  Get some fileinfos like:
  - CRC32
  - Shannon Entropy
  - SHA1-Hash (via Crypto-API)
  - SHA 256 Hash (via Crypto-API)
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
  - Precise results for KByte, MByte sizes
  - Info about packers, file headers etc.
  - Take care to close all handles, ressources properly
  
Tested under Win7-64 and Win7-32.
