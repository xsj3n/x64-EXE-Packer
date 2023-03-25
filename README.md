# x64-EXE-Packer
## A software packer for 64 bit Windows exes. An exploratory project.
Orginally, the primary purpose of software packers was to compress a binary, yet in such a way that the binary is still able to function. These days, encryption is also used on binaries to make reverse engineering it more difficult. This is a technique used by developers to protect the code they write, and by malware developers to protect the payloads they write. The binary is obviously unable to run whilst encrypted & compressed, so an intermediary binary is needed to "unpack" the binary. The binary that unpacks the encrypted/compressed binary and runs it in memory is referred to as the "stub". The portion that encrypts/compresses the payload and embeds it innto the stub is the "packer". 


The goal is to have a stub decrypt an exe image from one of it's sections and then run the image in memory. The packer itself is being written in unsafe rust & the stub is written in C++.

A custom cipher is also being written for the encryption/decryption routines in assembly, just to make the analysis of the packed bins more difficult. It'll make inserting dead control structures & file bumping bytes into the binaries easier later down the road.

Progress: +Stub: Done
          +Packer: Mostly Done
          +Cipher: Done, I think, but needs more testing before implementation



## Sources
https://bidouillesecurity.com/tutorial-writing-a-pe-packer-part-1/
https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
https://jb05s.github.io/Introduction-to-Windows-Demystifying-Windows-System-Architecture-and-Memory-Management/
