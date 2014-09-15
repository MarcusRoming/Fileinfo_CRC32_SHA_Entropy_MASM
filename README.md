Fileinfo_CRC32_SHA_Entropy_MASM
===============================

First project

Purpose: Get some fileinfos like:
  - CRC32
  - Shannon Entropy
  - SHA1-Hash (via Crypto-API)
  - SHA 256 Hash (via Crypto-API)
  - Size of the files (currently rounded, needs improvement)
  - Frequency table (use /f)
  - Type "CRC32 /?" for help.
  - Written in Assembler 32 Bit, MASM
  
To do: 
  - Faster processing (currently on my pc about 60 MByte/s)
  - Precise results for KByte, MByte sizes
  - Files larger than 4 GByte  
  
Tested under Win7-64 and Win7-32.
