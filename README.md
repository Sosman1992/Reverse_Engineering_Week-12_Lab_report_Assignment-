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


