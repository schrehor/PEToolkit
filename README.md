# PEToolkit

A small Windows PE header inspector and editor written in C.

Reads PE32 and PE32+ headers and can set or clear the DLL characteristic in a separate output file. The input file is kept unchanged.

## Build target

Windows x64 or x86. Visual Studio with the v145 C/C++ toolset and Windows SDK.

Open `PEToolkit.slnx` and build Debug or Release for x64 or Win32.

## Usage

```powershell
.\x64\Release\PEToolkit.exe .\input.exe
.\x64\Release\PEToolkit.exe .\input.exe --set-dll .\output.dll
.\x64\Release\PEToolkit.exe .\input.dll --clear-dll .\output.exe
```

The first command prints header information. The other commands create a copy with the requested DLL flag; existing output files are refused.

Changing the flag does not adapt the entry point or turn a DLL into a working executable.
