# Inline-Execute-PE
### DISCLAIMER: 
#### This project is complex and failure to understand how it works and adequately test it can result in you crashing Beacons and losing access!  
#### I highly encourage you to read all of the documentation up until the "Design Considerations and Commentary" section!

## Introduction
Inline-Execute-PE is a suite of Beacon Object Files (BOF's) and an accompanying Aggressor script for CobaltStrike that enables Operators to load unmanaged Windows executables into Beacon memory and execute them, retrieving the output and rendering it in the Beacon console.

This enables Operators to use many third party tools (Mimikatz, Dsquery, Sysinternals tools, etc) without needing to drop them to disk, reformat them to position independent code using a tool like Donut, or create a new process to run them.

These executables are mapped into Beacon memory so that they can be ran repeatedly without needing to send them over the network, allocate new memory, and create a new conhost.exe process each time.  

Executables loaded into Beacons are accessible and able to be ran by all CobaltStrike Clients connected to the CobaltStrike Team Server.

Inline-Execute-PE was designed around x64 Beacons and x64 Windows C or C++ executables compiled using Mingw or Visual Studio.  This project does not support x86 executables or x64 executables written in a different language or compiled using a different compiler.

![](Inline-Execute-PE.gif)

## Setup
Clone the repository and optionally run make in order to recompile the BOF's.

Load Inline-Execute-PE.cna into the CobaltStrike client.  Ensure the directory that CobaltStrike is running from is writable by your user; Inline-Execute-PE creates a text file there (petable.txt) in order to ensure availability of the data required by Inline-Execute-PE to function.

## Commands
Inline-Execute-PE comprises of 3 target-facing commands which run BOF's, and 3 internal commands that manipulate the project data-structure:

Target-facing:  
1. peload
2. perun
3. peunload

Internal data-structure:
1. petable
2. peconfig
3. pebroadcast

### peload
peload is the beginning of Inline-Execute-PE. This command is used to load a PE into Beacon memory. It performs the following major actions:  

1. Sends the specified PE over the network to Beacon OR sends the name of the PE to read from disk on the target machine  
2. Creates a structure in Beacon memory to hold various pointers and handles required by Inline-Execute-PE throughout it's lifecycle  
3. Allocates memory in Beacon and writes PE to it with RW protection  
4. XOR encrypts PE in memory using a user-specified key  
5. Allocates another chunk of memory and copies the XOR encrypted PE to it. This is necessary in order to be able to "revert" the PE for subsequent executions  
6. Spawns a conhost.exe child process under Beacon in order to initialize stdin/stdout/stderr  
7. Redirects stdout and stderr to an anonymous pipe so that PE output may be captured  

### perun
perun is the second step in Inline-Execute-PE. It performs the following major actions:  

1. Sends command line arguments over the network to Beacon
2. XOR decrypts PE in memory
3. Fixes the PE's Import Address Table, hooking certain API's related to command line arguments and exiting processes
4. Changes PE memory protection to RWX
5. Run's PE in it's own thread
6. Captures output from PE and returns it to CobaltStrike
7. Reverts PE memory protection to RW
8. Overwrites the PE in memory with the XOR'd copy that was made during peload

### peunload
peunload is called to remove the PE from Beacon memory when an Operator is done with it or wishes to load a different PE. It performs the following major actions:  

1. Closes handles and file pointers created during peload
2. Terminates the conhost.exe process created during peload
3. Zeroes out and then frees both copies of the PE in memory
4. Tries to unload any DLL's loaded by the PE into the Beacon process (optional)

### petable 
petable is used to display information regarding all PE's currently loaded into Beacons.

Each CobaltStrike Client has their own petable; Inline-Execute-PE goes to great lengths to ensure the synchronicity of its data between all connected CobaltStrike Clients so that PE's may be used by all Operators. For more on this, see "Design Considerations and Commentary".

![image](https://user-images.githubusercontent.com/91164728/213904121-a34d41ac-2c9f-43fb-8e37-f5695e9a9363.png)

### peconfig
peconfig is used to configure options pertaining to how Inline-Execute-PE functions.  The two current options that may be altered are:

1. Timeout. This dictates how long perun will wait for the PE to complete execution before terminating it. This exists as a safeguard in the event that incorrect arguments are given to a PE that cause it to never return/finish execution. This setting is 60 seconds by default but may be modified to accommodate longer-running PE's.
2. UnloadLibraries. This option controls whether peunload will try to free DLL's from the Beacon process that were loaded by the PE. This is set to TRUE by default. Some PE's cause issues when DLL's are unloaded from the Beacon process and can cause Beacon to crash, in which case it is better to leave all DLL's loaded by the PE in the Beacon process.  This has been observed when using powershell.exe (perhaps due to it loading the .Net CLR into the Beacon process).

### pebroadcast
pebroadcast can be used to manually broadcast the contents of a Client's petable to all other connected CobaltStrike Clients.

Every other CobaltStrike Client will update their petable with the data broadcasted. This shouldn't ever really be necessary, but the feature exists just in case.

## Usage
Use peload to load a PE into Beacon memory  
![image](https://user-images.githubusercontent.com/91164728/213904908-89d1be5b-6ed3-4fee-a572-afd46c44098e.png)

Alternatively, if there is a PE on the target machine you would like to use without creating a new process, provide the path and the --local switch  
![image](https://user-images.githubusercontent.com/91164728/221037390-d0b9714e-dffc-46f8-88e0-88850cc29073.png)

Call perun, passing any arguments to the loaded PE  
![image](https://user-images.githubusercontent.com/91164728/213904931-77523b46-7f29-417f-8392-61f80e7d0a4a.png)

Double quotes in arguments must be escaped using backslashes  
![image](https://user-images.githubusercontent.com/91164728/213905000-51090151-6d5e-460b-b038-7c05fc9e3f72.png)

If you have identified that a PE causes issues when trying to free DLL's during unload, use peconfig to set unloadlibraries to false  
![image](https://user-images.githubusercontent.com/91164728/213905058-3a6f1106-60ec-48e8-811e-1c7ba20e463a.png)

Once you are done using a PE, call peunload to clean it up from Beacon  
![image](https://user-images.githubusercontent.com/91164728/213905088-cae34b54-2635-44fd-919d-20115db8c29b.png)

A different PE now may be loaded into the Beacon  
![image](https://user-images.githubusercontent.com/91164728/213905113-4ac43712-78c7-4cd4-85b2-abf554552e07.png)

### perun timeout
You must be careful about the command line arguments you pass to the PE; some PE's will crash outright if given wrong arguments, while others will run endlessly causing Beacon to never call back even though the process is still running.

This can be seen with Mimikatz.exe when 'exit' isn't specified at the end of the list of arguments  
![image](https://user-images.githubusercontent.com/91164728/213905249-b8145be1-7ddd-4576-91e3-294e60e26a80.png)

...

![image](https://user-images.githubusercontent.com/91164728/213905258-2d081796-aace-4faf-82c0-1ee68601a281.png)

Inline-Execute-PE will terminate the running PE's thread after the specified timeout value has been reached. This enables Beacon to be able to resume normal communications (Beacon does not call back until the perun BOF has completed execution).  While normal CobaltStrike commands and other BOF's may still be used in this Beacon, Inline-Execute-PE is now disabled; when a running PE is terminated in this manner it seems to break stdout and stderr in the Beacon process, and PE's loaded subsequently do not function properly. 

The PE may (and should) still be unloaded from Beacon memory, however looking at petable will show that this Beacon may no longer have additional PE's loaded into it.  ![image](https://user-images.githubusercontent.com/91164728/213905389-038cdd36-facf-417e-a4aa-d36d289adce5.png)

It is imperative that you test the PE's you wish to run using Inline-Execute-PE, and that you exercise care when giving command line arguments to perun.  Some PE's are more forgiving than others.

## Tips, Tricks, and Observations
The below are in no particular order some observations made during testing and development regarding certain PE's that users might want to load into Beacon.

1. Using peunload on Powershell.exe will usually crash Beacon when UnloadLibraries is TRUE; I believe this has to do with Powershell.exe loading the CLR.
2. Cmd.exe will crash Beacon unless '/c' is used as the first argument. E.g. 'perun /c cd' is ok, 'perun cd' is not.
3. Mimikatz.exe will crash Beacon if it was loaded, used, unloaded, and then loaded again IF UnloadLibraries was TRUE during the first peunload. 
4. Some PE's are programmed to print their help menu's when the PE exits; these won't be displayed because calls to ExitProcess and exit() and the like are hooked and redirected to ExitThread so that the PE doesn't cause our Beacon process to exit.
5. Some PE's aren't very good about freeing memory when they are done with it and rely on that memory being freed when the process exits; because the PE is running inside the Beacon process (and thus the process doesn't exit when PE is done), Beacon can tend to bloat as more PE's are loaded and ran inside of it.  Observe this during testing using something like Process Explorer and be mindful of it during operations.
6. Sysinternal's Psexec doesn't seem to work; while it does run, it complains about the handle to the remote machine being invalid. In practice if one were to want to use something like psexec, it would probably be better achieved using CobaltStrike's socks proxy and an attack-box version of psexec anyways.  
7. Spawning a new beacon to use with Inline-Execute-PE probably isn't a bad idea, especially as you are getting a feel for how different PE's interact and function within the framework. Two is one, one is none.
8. If there is a LOLBIN you want to use without the telemetry of creating a new process, use the --local switch with peload and read it from disk on the target system. This can also be useful to avoid versioning issues.

## IOC's and AV/EDR
IOC's associated with Inline-Execute-PE include but are not limited to:

1. Allocating memory using VirtualAlloc
2. Changing memory protections on allocated memory between RW and RWX
3. Creating a child conhost.exe process
4. Loading DLL's required by the mapped PE
5. Any actions performed by the actual PE; for instance, Mimikatz touching LSASS 

### AV/EDR
I did not give this a full-battery test against an EDR during development, partly due to laziness and partly due to lack of availability of a test environment. It was however tested against latest patch Windows Defender (which is in my experience a pretty good AV product).

Mimikatz.exe is probably the most suspicious and well-known PE that comes to mind as a candidate for use with Inline-Execute-PE.  I found that Windows Defender ability to detect Mimikatz running using Inline-Execute-PE was contingent on the process that Beacon was running in.  

A beacon running in a standalone executable (think beacon.exe with artifact kit so that it is able to execute and run normally past Defender) will be caught when using Mimikatz.exe with Inline-Execute-PE.

A beacon running in a Windows process (injected into Explorer.exe, notepad.exe, etc or  DLL sideloaded into a legitimate process) will NOT be caught when using Mimikatz.exe with Inline-Execute-PE.

In regards to EDR's that perform userland hooking, as I said I haven't tested but I have the following general thoughts:

Being that the PE is running inside of the Beacon process, which you have presumably already unhoooked/refreshed NTDLL inside of, I would think you shouldn't have too many problems with the API calls made by the PE being flagged. The same issues regarding what the PE actually does (touches processes, alters reg keys, etc) still apply.

## Design Considerations and Commentary
A couple months ago I came across [RunPE-In-Memory](https://github.com/aaaddress1/RunPE-In-Memory) and had the thought to try my hand at converting it into a BOF for CobaltStrike. The journey that followed was much more complex and took a lot longer than anticipated. This project was particularly challenging because it isn't a standalone tool in it's own right, it is a tool used to run other tools. This requires a great deal of flexibility and effort towards compatibility with a wide range of PE's and all of the different ways those PE's might accomplish the same task (get arguments, terminate, etc). 

At the outset, Inline-Execute-PE was envisioned as an all-in-one BOF, responsible for loading, executing, and freeing a PE in a Beacon.  About 3 weeks into the project, by which time I had a POC ~75% completed, I found [Pezor](https://github.com/phra/PEzor) which was released ~1.5 years ago and already did almost everything I was trying to do; the major difference being that Pezor called Donut under the hood to turn the PE into shellcode, rather than manually mapping the original PE into memory.  

This discovery was welcome in one regard and disappointing in another; it was phenomenal to have a mature project from which to draw inspiration and help me over some sticking points in my code, but disheartening in that I had effectively been reinventing the wheel without knowing it. After reading up on Pezor and thinking about its design, some tradecraft related matters, and the operational needs of my organization I altered the course of Inline-Execute-PE to what you see today. This decision was driven by several factors which will be discussed below, as will some of the more curious design choices made that may have raised some eyebrows for those who have read this far.

### Inline-Execute-PE vs Pezor
In examining my operational experience I came up with multiple instances and tools where I needed to run the tool repeatedly; with Pezor, an Operator must repeatedly send the PE over the network, create a conhost.exe, allocate new memory in Beacon, etc. which struck me as potentially undesirable when considering AV/EDR. This line of thinking led to the idea to 'load' a PE into Beacon, similarly to how you can load a .PS1 into Beacon for repeated use. The conhost.exe is created when the PE is first loaded and persists while the PE is loaded in memory; similarly, new memory is allocated for the PE once when it is first loaded, and of course you avoid needing to send the PE over the network each time you want to use it. The model that Inline-Execute-PE adopted isn't without it's faults, which I tried to address with varying degrees of success.

### Two Copies of PE
A design choice that should jump out at people is the fact that Inline-Execute-PE maps the PE in Beacon TWICE. This certainly isn't desirable or a choice I made willingly, but was born of necessity. As previously mentioned, Inline-Execute-PE must hook several functions relating to command line arguments in the PE. Because the mapped PE runs inside of the Beacon process, the PE will attempt to use the command line arguments specified in the PROCESS_PARAMETERS section of the PEB; to get around this, when the PE calls one of the various functions that retrieves the command line arguments we must direct the PE to our own custom defined functions where we can provide the intended arguments as passed from CobaltStrike using perun. 

This works well, but during development I noticed something strange with several different PE's. The first time the PE was ran the custom defined function that we provided to the PE's IAT was called properly, however in all subsequent times that the PE was ran and provided different arguments, the PE did not call the custom defined function and as such did not receive the arguments passed from CobaltStrike. I'm not sure what is actually happening under the hood, but I'm led to believe that after the PE has ran once it copies the command line arguments somewhere in memory, and on subsequent runs looks to that location in memory first before calling the hooked functions to retrieve the command line arguments as it did the first time. I corroborated this theory by retrieving the location in memory where a pointer to another pointer to the array of pointers containing the arguments resided, and manually modifying this location in memory to contain the proper pointer on each run. This worked for the __getmainargs and __wgetmainargs functions, but other PE's call alternative functions like __p___argv and __p___argc which this method did not work for.

In order to be able to "reset" the PE to a state where it would actually call the hooked functions in order to fetch arguments, I resorted to making a second copy of the PE in memory during peload.  This copy is also XOR encrypted and sits with RX protections during the entirety of the lifecycle of Inline-Execute-PE, simply being used to overwrite the copy of the PE that is actually executed using perun.  As mentioned, it's not a perfect solution, but it is a blanket solution that covers all PE's without needing to get lost in the weeds trying to come up with a solution for all of the different PE's out there and the different API's they use.

### Conhost.exe
With one of the major selling points of Inline-Execute-PE being that you can run tools without creating new processes, it is a big punch to the gut that I have to... create a new process (conhost.exe) in order to do so. This requirement comes from the fact that the standard streams (stdin/stdout/stderr) are not initialized in Windows programs unless a console is present.  In our case we don't need the console at all; the standard streams are redirected to an anonymous pipe and captured that way, but without the conhost the streams are not initialized and cannot be redirected.

Inline-Execute-PE approaches the conhost problem in the same fashion that Pezor does, it calls AllocConsole and then immediately after hides it from view using ShowWindow. On a Windows 11 VM with 8 GB of RAM I don't ever see the console window flash and then disappear, but mileage will vary on that one depending on the target system.

I spoke with a developer that works on a very advanced Commercial C2 that recently came out with a native equivalent (ok, much more advanced version) of Inline-Execute-PE who told me that they were able to avoid spawning a conhost.exe by "fooling Windows into thinking it had a console".  With this tidbit I spent about a week scouring the internet for documentation on how Windows programs interact with conhost, trying to trace the API calls associated with write functions and the console in WinDBG, and even examining the [Windows Terminal](https://github.com/microsoft/terminal) source code which is surprisingly enough available on Github. While I learned a lot about the PEB and standard stream-related things, I came out the other side of this empty handed.  I suspect the path forward might involve patching certain console-related functions in kernel32 but I don't know.  I'm honestly pretty disappointed that I wasn't able to figure out a solution here, but being self-taught and only a few years into my career it is probably to be expected.

### PE Timeout and Rescue
All those who have ever tried to write a BOF are aware that for all of the advantages that come with them, a huge danger lies in the fact that an error or crash in your BOF can and will kill your Beacon. The danger is amplified in this project by the nature of how much control users have on data passed to Inline-Execute-PE and how few safety measures can easily or reliably be put in place by me, the developer. Users could for example crash their Beacon by loading an x86 PE into an x64 Beacon, or far more commonly by passing improper arguments to the mapped PE as I touched on earlier. While I can't stop users from crashing their Beacons with bad arguments to their PE's, I can try and rescue their Beacon in the case of an endlessly running PE, as in the case of Mimikatz when 'exit' isn't specified.

Ideally I would be able to stop execution of the PE, allowing Beacon to resume normal function, and then immediately let the user try again with the (hopefully) correct arguments this time. In practice I found that terminating the PE seems to break the FILE*'s associated with stdout/stderr, and even unloading the PE entirely and then loading it again fresh doesn't resolve this; they are broken process-wide.

To terminate a PE that continues to run past the 'timeout' option, TerminateThread is called on the handle returned from CreateThread. This doesn't allow the thread to gracefully exit anything, so it makes sense that some things might break.  I tried to mitigate this by implementing [thread hijacking](https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking), with the goal being to suspend the PE thread and redirect it's execution to the ExitThread() API. The hope here was that if it were the thread that started exit procedures (as opposed to being forcefully terminated externally), it might result in stdout/stderr continuing to function, but I ended up having the same issue (as well as experiencing an inability to suspend the PE thread in the case of Mimikatz).

Unable to mitigate this problem, I landed on simply preventing users from being able to continue to run the PE or load additional PE's into the affected Beacon (which WOULD result in a crash). This is another instance of Inline-Execute-PE falling short of where I would like it to be, but I settled for the fact that the Operator would at least still have their Beacon and be able to use it for normal functionality. 

### Inline-Execute-PE Data Structure
A challenging part of this project was ensuring the availability of PE's loaded into Beacons to all CobaltStrike Clients connected to the Team Server. Inline-Execute-PE's data is stored in structures created by Inline-Execute-PE.cna, which must be loaded into each Client that wishes to use the tool; as a result, these data structures live within each Client, not on the Team Server. If this data did live in a single central location (TS) it would be trivial to retrieve it from each Client and this whole thing would be a non-issue; were the CobaltStrike Team to formally integrate a capability like Inline-Execute-PE into CobaltStrike I am positive this is the direction they would go. But being that this is a community add-on, we make do with what we have.

There are a couple different scenarios we have to worry about when it comes to ensuring that each CobaltStrike Client has the latest, accurate data concerning PE's loaded into Beacons:

1. New Clients connecting to the TS and needing the current petable
2. Instances where only a single Client is connected to the TS and restarts CobaltStrike (thus losing the petable stored in the Client memory)
3. Client A making a change to Inline-Execute-PE data which must be communicated to Client B

A multi-pronged approach was taken to address these scenarios. To handle the case where only a single CobaltStrike Client is connected to the TS (and thus is the only entity that has the petable data), each time the Client alters the petable (peload, peconfig, peunload, etc) it also writes the contents of it's petable out to a local text file located in the CobaltStrike directory.  Should the Client exit/restart, or when Inline-Execute-PE.cna is reloaded, it will first attempt to read from the local petable.txt file in order to populate it's in-memory petable.

When multiple Clients are connected to a TS and a new Client joins (as per the Event Log), each Client fetches a list of all users connected to the TS and sorts it alphabetically.  The Client that is first on that list is selected as the "Broadcast" Client, and after waiting 5 seconds (to allow the new Client to initialize and read it's local petable.txt) will send messages (Actions) in the Event Log for each entry in it's petable. All clients (aside from the Broadcasting one) will read these messages and update their petables with the broadcast information; this includes updating existing entries as well as adding any additional ones that their respective petables do not contain.

Normal operations involving Inline-Execute-PE also rely on sending messages in the Event Log.  When Client A runs peload, a message is broadcast containing all of the pertinent petable information; ALL clients update their respective petables by parsing these broadcasted Event Log messages using the "on Event_Action" hook. Changes are also made to Inline-Execute-PE data when peload and peunload finish executing their BOF's; these changes are communicated back by Beacon (e.g. after running peload, Beacon calls back with the memory location of the pMemAddrs struct) and as such are visible to all connected Clients, which update their respective petables using the "on Beacon_Output" hook. 

These separate efforts combined result in Inline-Execute-PE being able to efficiently and reliably synchronize critical data between multiple Clients.

## Credits
This project would not have been possible without the following projects and resources which were referenced heavily and from which core parts of this project originated. Big thanks to the author's for their code and their vision.

1. [RunPE-In-Memory](https://github.com/aaaddress1/RunPE-In-Memory)
2. [Pezor](https://github.com/phra/PEzor)
3. Lots of StackOverflow
