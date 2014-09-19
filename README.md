Fileinfo_CRC32_SHA_Entropy_MASM
===============================

First project

New:
  - New Hash (SHA 256)
  - New memory allocation
  - Much faster due to parallel processing via Multithreading

Purpose: 

  Get some fileinfos like:
  - CRC32
  - Shannon Entropy
  - SHA1-Hash (via Crypto-API)
  - SHA 256 Hash (via Crypto-API)
  - Size of the files (currently rounded, needs improvement)
  - Frequency table (use /f)
  - Type "CRC32 /?" for help.
  
Info:  
  - Written in Assembler 32 Bit, MASM
  
To do: 
  - Precise results for KByte, MByte sizes
  - Files larger than 4 GByte  
  - Info about packers, file headers etc.
  - Take care to close all handles, ressources properly
  
Tested under Win7-64 and Win7-32.
