# x64-EXE-Packer
## A software packer for 64 bit Windows executables. An exploratory project.

Progress:
- [x] Stub 
- [x] Packer
- [x] Custom Cipher
- [ ] Junk Code Generator?
- [ ] File Bumper?
- [ ] Dynamic bytecode additions for static signature evasion? 
- [ ] Polish & Tidy

The stub, packer, and encryption routine are all ironed out on the logic side:

- The encryption routine is a 64-bit block cipher which uses a 128-bit key, which does 7 rounds of encryption using bitwise rotates and xors. It's not great, but hopefully unique enough to throw analyst off. 
- The stub looks for ".xss" section within itself, and extracts PE data from it.
- The packer copies the stub, appends a .xss section to the end of it, and then appends the targeted file for packing at the end of the new stub, after encrypting it.

Currently polishing up by adding cmdline arguements & cutting unused/debug content out.
Working out feature implementations to move towards this being a red team operations tool for encoding payloads


## Sources
https://bidouillesecurity.com/tutorial-writing-a-pe-packer-part-1/
https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
https://jb05s.github.io/Introduction-to-Windows-Demystifying-Windows-System-Architecture-and-Memory-Management/
