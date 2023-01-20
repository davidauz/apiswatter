# apiswatter
I couldn't find a trainer spy so I wrote my own.

## Name
Api Swatter: logs API calls to a file.

## Description
It's a console application built with MingW.

Can work on any running process, or load an executable from disk.

It tracks calls to functions to a log file.


## Installation
Install MingW and use the provided Makefile to compile from source.

Otherwise, grab a release and run it in a cmd prompt.  No installation needed.

## Usage
Example usage for a running process:
```
apiswatter.exe -a notepad.exe -f c:\devel\log.txt -r
```
Example usage for a program to be launched:
```
apiswatter.exe -e c:\windows\notepad.exe -r
```
Help:
```
apiswatter.exe -h
```
You'll get a log file like this:

```
GetModuleHandle says `KERNELBASE` sits at `0x00007FF8B6F00000`
GetProcAddress says `CreateRemoteThread` sits at `0x00007FF8B7006570`
GetProcAddress says `InitializeConditionVariable` sits at `0x00007FF8B94F9E60`
GetProcAddress says `SleepConditionVariableCS` sits at `0x00007FF8B6F6C7F0`
GetProcAddress says `RtlQueryFeatureConfiguration` sits at `0x00007FF8B94ECB70`
WriteProcessMemory writing `11` bytes at `0x00007FF7FD0B1900`:
41 41 41 41 41 41 41 41 41 41 00 
...
```
and so on.

## License
Nolicense

## Project status
At present logs calls to the following functions:

* GetModuleHandleA
* GetProcAddress
* CreateRemoteThread
* WriteProcessMemory

