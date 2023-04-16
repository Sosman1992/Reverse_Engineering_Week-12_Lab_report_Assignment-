# Week 12 - Detecting DLL Injection 

The Week's Assignment and Lab focuses on how malware loaders inject evil threads into legitimate programs, often using library loading as an attack vector. and also observing library injection in action.
---

# ANSWERS TO THE QUESTIONS

## 1) What happens when you run the malware executable?

When the EXE is executed without any inputs from the command line, a message box appears with the title 'Practical Malware Analysis 0' and the phrase 'Press OK to reboot.' I clicked it, but nothing happened. Every minute, the identical message box with the title 'Practical Malware Analysis X' displays, with X corresponds to an incremented counter.


![pma12.1_popup](../images/pma12-1_popup.png)

<!--more-->

In Process Explorer the CPU usage for Interrupts is up between 65-85%.


## 2) What process is being injected?
When you run strings against the EXE, you get 'explorer.exe' and 'Lab12-01.dll'. In Process Explorer, searching for the handle 'Lab' yields only one result: 'explorer.exe'.


![pma12.1_handle](../images/pma12-1_handle.png)



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


![pma12.1_inject](../images/pma12-1_inject.png)

The DLL just creates a parent thread, that launches a child thread once per minute, which shows the message box. This will happen until stopped.


# SOLUTION TO THE questions that followed, including a relevant Ghidra screenshot in GHIDRA and explanation which backs up the answer. 
## STEPS
After downloading the file from the website, I extracted the downloaded zip file to my Desktop and provided with a file named `keyg3nme` I run the file `keyg3nme` in my linux terminal using `file command` to ascertain the type of file; from the output it showed that `keyg3nme` is 64-Bit file. In addition also run `strings` command on this executable to see the printable strings contained within this binary and I found out some interesting  strings including but not limited: `Enter your key :`, `Good job mate, now go keygen me`, `nope`.

I then proceeded to Ghidra to see how best I can decompile and analyze this executable file. First and foremost after launching Ghidra, from the `Symbol Tree` pane I searched for the actual main function which is basically the entry point of the program and double click it to launch. Gidra launched the program and looking at this in the Decompiler window pane it can be seen that the decompiler try to infer the signature of the main function, nontheless the C language standard defines exactly how `main` function signature looks like, I went on to make changes on how the main function should look like in a C program by right clicking on the function signature and hit edit function and typed `int main (int argc, **argv)` which differ from `undefined8 main(void)` when the program opened in the Decompiler window pane. From the statement `iVar1 = validate_key((ulong)local_14), I deduce that local_14 is an integer variable that is used for holding entered key by a user and this value is then casted to long data type with a  function named (ulong) and then passed as a function to the function called `validate_key` and then stored in a variable called iVar1. I then double click the function `validate_key` to have a look at the actions it performs whenever it is called , upon opening it, I saw that it has a data type of `bool` and takes an integer value as its signature namely `iParam1` equivalent of `iVar1` in main function, it then return a true or false to be stored in iVar. However in C language syntax  1 is used to represent true and 0 is used to represent false which is assigned as the value of iVar variable with the statement `return (ulong) (iParm1 % 0x4c7 == 0)` in the validate_key function. Since I know that iParm1 is equivalent to entered value by the user, but   0x4c7  is  a hexadecimal number literal, hence converting it to decimal implies 1223 as its equivalence. 

In summary the logic that is being carried by the key_validate function is `(if number_entered % 1223 == 0)` then return 1 if the executed condition is true 0 for false and then stored in the iVar variable. The next statement in the Decompiler pane goes to compare the value in iVar against 1 and if they are equal and equivalent then it prints  (“Good job mate”)  else it prints (`nope`). After it returns 0 to the operating system to signal for the successful operation of the program.

## ANSWERs


