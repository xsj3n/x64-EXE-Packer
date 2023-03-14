# x64-EXE-Packer
## A software packer for 64 bit Windows exes. An exploratory project.
The goal is to have a stub file decrypt an exe image from one of it's sections and then running the image that was contained within written in C++.

As of now, a working stub which is nothing more than a loader at the moment has been added, as well as a rust program to pack the data into the stub.

Working on the encryption routine for the packer next.


## Sources
https://bidouillesecurity.com/tutorial-writing-a-pe-packer-part-1/
https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
https://jb05s.github.io/Introduction-to-Windows-Demystifying-Windows-System-Architecture-and-Memory-Management/
