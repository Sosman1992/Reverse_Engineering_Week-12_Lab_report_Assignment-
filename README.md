# Week 12 - Detecting DLL Injection 

The Week's Assignment and Lab focuses on how malware loaders inject evil threads into legitimate programs, often using library loading as an attack vector. and also observing library injection in action.
---

# ANSWERS TO THE QUESTIONS

## 1) What happens when you run the malware executable?

When the EXE is executed without any inputs from the command line, a message box appears with the title 'Practical Malware Analysis 0' and the phrase 'Press OK to reboot.' I clicked it, but nothing happened. Every minute, the identical message box with the title 'Practical Malware Analysis X' displays, with X corresponds to an incremented counter.


![img1](https://user-images.githubusercontent.com/66968869/232326972-d7d4d96e-c04c-4e4b-a489-f6a97170bd5b.png)



## 2) What process is being injected?
When you run strings against the EXE, you get 'explorer.exe' and 'Lab12-01.dll'. In Process Explorer, searching for the handle 'Lab' yields only one result: 'explorer.exe'.



## 3) How can you make the malware stop the pop-ups?

Restarting the computer stops the malware. It doesn't have a persistence mechanism.


## 4) How does this malware operate?

The EXE starts by loading 
[psapi.dll](http://msdn.microsoft.com/en-us/library/windows/desktop/ms684884%28v=vs.85%29.aspx), and getting the process addresses for 
[EnumProcessModules](http://msdn.microsoft.com/en-us/library/windows/desktop/ms682631%28v=vs.85%29.aspx), 
[GetModuleBaseNameA](http://msdn.microsoft.com/en-us/library/windows/desktop/ms683196%28v=vs.85%29.aspx), 
and [EnumProcesses](http://msdn.microsoft.com/en-us/library/windows/desktop/ms682629%28v=vs.85%29.aspx). 
Then, it iterates through the processes looking for `explorer.exe`.

When the EXE discovers `explorer.exe`, it performs DLL injection, forcing the target to load `Lab12-01.dll` into a new thread from disk.

![img3](https://user-images.githubusercontent.com/66968869/232327548-9e98a120-b6ac-46f4-9658-3a35c1ae2c7c.png)


The DLL just creates a parent thread, that launches a child thread once per minute, which shows the message box. This will happen until stopped.


# SOLUTION TO THE questions that followed, including a relevant Ghidra screenshot and explanation which backs up the answer. 
## STEPS
After downloading the file from the website, I extracted the downloaded zip file to my Desktop and provided with two files named `Lab12-01.exe` and `Lab12-02.dll`.

I then proceeded to Ghidra to see how best I can decompile and analyze this executable file. First and foremost after launching Ghidra, from the `Symbol Tree` pane I searched for the actual main function which is basically the entry point of the program and double click it to launch. Ghidra launched the program and looking at this in the Decompiler window pane it can be seen that the decompiler try to infer the signature of the main function, nontheless the C language standard defines exactly how `main` function signature looks like, I went on to make changes on how the main function should look like in a C program by right clicking on the function signature and hit edit function and typed `int main (int argc, **argv)` which differ from `undefined8 main(void)` when the program opened in the Decompiler window pane. From the statement `iVar1 = validate_key((ulong)local_14), I deduce that local_14 is an integer variable that is used for holding entered key by a user and this value is then casted to long data type with a  function named (ulong) and then passed as a function to the function called `validate_key` and then stored in a variable called iVar1. I then double click the function `validate_key` to have a look at the actions it performs whenever it is called , upon opening it, I saw that it has a data type of `bool` and takes an integer value as its signature namely `iParam1` equivalent of `iVar1` in main function, it then return a true or false to be stored in iVar. However in C language syntax  1 is used to represent true and 0 is used to represent false which is assigned as the value of iVar variable with the statement `return (ulong) (iParm1 % 0x4c7 == 0)` in the validate_key function. Since I know that iParm1 is equivalent to entered value by the user, but   0x4c7  is  a hexadecimal number literal, hence converting it to decimal implies 1223 as its equivalence. 


## ANSWERs
1) Prove of the presence of a loader in the Lab12.exe and also the loader is using DLL injection is shown below:
   It appears that the loader is using DLL injection to load a DLL named `s_Lab12-01.dll`. Image is shown 

From the above snippet of code from GHIDRA it can be seen that, the loader first creates the path to the DLL with the "GetCurrentDirectoryA" function that takes two argument. And it is able to achieve by this by concatenating the directory path, a separator string, and the DLL filename with the use of "lstrcatA" function.

![dll](https://user-images.githubusercontent.com/66968869/232346140-a557752d-8d56-44da-9eef-eafae3cc01c0.png)

With the help of `VirtualAllocEx()` memory is then allocated a target process in this case named "path_to_DLL", and with the help of `WriteProcessMemory()` the DLL path to the allocated memory is written to the allocated memory. This leads to the creation of a remote thread in the "path_to_DLL" using the `CreateRemoteThread()` function. The address of this remote thread is also obtained using GetProcAddress() which retrieves the address of the LoadLibraryA() function from the kernel32.dll module. The argument passed to LoadLibraryA() is the address of the memory location containing the DLL path.

![loader](https://user-images.githubusercontent.com/66968869/232346151-d0b4a438-810b-4d39-a2d8-a05d3fabcccc.png)

In conclusion, since the loader is involved in the creation of DLL path from the code and also using VirtualAllocEx() to allocate memory in the target process strongly suggests that it is using DLL injection to load the "s_Lab12-01.dll" DLL. In addition, DLL injection technique is normally seen to use functions including but not limited to "LoadLibrary,CreateRemoteThread,WriteProcessMemory" functions for carrying out its operation.


2) The process that will be used for the DLL injection is selected by the `EnumProcesses` function which then uses the `psapi.dll` function to enumerate all running processes on the system. This function populates the local_1120 array with the process IDs of all running processes on the system.

The loader then iterates over the local_1120 array, and for each process ID, it checks if the process is valid by calling the function FUN_00401000 with the process ID as an argument. If the process is valid, it opens a handle to the process using the OpenProcess function with the PROCESS_VM_OPERATION and PROCESS_VM_WRITE access rights.

If the handle to the process is successfully opened, the loader allocates memory in the target process using VirtualAllocEx and writes the path of the DLL to be injected into the allocated memory using WriteProcessMemory. Finally, the loader creates a remote thread in the target process using CreateRemoteThread with the entry point of the LoadLibraryA function and the address of the path of the DLL as arguments.


3)
