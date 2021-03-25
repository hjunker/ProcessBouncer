# ProcessBouncer
ProcessBouncer is a PoC for blocking malware with a process-based approach. With a little fine-tuning this allows to effectively block most of current ransomware that is out there.

<img src="./img/pb-starting.png" width="30%" /><img src="./img/pb-started.png" width="30%" /><img src="./img/pb-inaction.png" width="30%" />

## IMPORTANT: CHECK BEFORE USAGE!!!

PLEASE READ THE COMPLETE FILE BEFORE USING PROCESS BOUNCER. CHECK THE SECTION MARKED "1. settings (CONFIG section)" FOR ADJUSTING PROCESSBOUNCER TO YOUR INDIVIDUAL NEEDS.

ProcessBouncer is mainly tested in combination with Windows Defender. Problems have been reported to me when using Symantec or TrendMicro. I will take care of this soon... ProcessBouncer is about to get new features which work directly with MS Defender.

## Run ProcessBouncer with default configuration

Simply running ProcessBouncer without customization might leave some risks and make you prone to false positives. But you can give it a try - preferably on a virtual test system that is not connected to production systems.

![Starting ProcessBouncer powershell script](./img/pb-starting.png)  

![ProcessBouncer reacting on some processes created on the system](./img/pb-started.png?raw=true)

![ProcessBouncer has blocked a malicious process started from an MS office application](./img/pb-inaction.png?raw=true)

### ExecutionPolicy and Run as...
Depending on your Windows version and various settings it might be necessary to run ProcessBouncer with Administrator's priviledges. If you run into the situation that you are not allowed running (unsigned) powershell scripts. Try running powershell as Administrator and type:
	Set-ExecutionPolicy Unrestricted
	...and confirm the dialogue.
Please refer to https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-6 for further information.

### Sign your ProcessBouncer script
No matter whether you run ProcessBouncer as Administrator or a regular user, you should 
allow your windows system(s) to execute only signed powershell scripts.

TODO: Well, I am gonna have to document this soon, maybe based on a writeup like this one: https://www.scriptinglibrary.com/languages/powershell/how-to-sign-a-powershell-script/

## Technical details
While this script is running (no admin permissions shall be required) this should protect the user from typical ransomware infections. This is accomplished by using _Windows Management Instrumentation (WMI)_ to get notified (asynchronously get events) on newly started processes and check some of their characteristics for things that are probably of malicious nature. There are various options to choose and to extend for making the script work best. Please check and tune the included white- and blacklists carefully. Once a process is rated as suspicious it is suspended / terminated. A GUI popup is shown to the user to inform him that it might be the time to take his hands of his keyboard and call the IT department. If you configure Process Bouncer to only suspend the suspicious process, you can e.g. set up a remote-session and check the process that is still running... and hey... you are on the front line of cyber defense... and you are winning!

### Limitations

Because Process Bouncer relies on WMI to get information about newly spawned processes, it will not be able to suspend extremely _short-lived processes_ (processes which only execute for a split second, e.g. Windows' _whoami.exe_). PsC is not involved in the process creation logic, it relies on 
WMI events which are only generated once the process has already been launched. There are methods to get synchronously involved in the process creation logic (e.g. by using the _PsSetCreateProcessNotifyRoutine kernel API_), but this is out of scope for this Powershell tool :-).

### Customization
Well, if you have gone through the steps of initial configuration / customization (the config section mentioned earlier - you remember?!) you should have a basic idea for further enhancements and customizations that especially meet the requirements and specifics of your infrastructure. You might want to exclude further paths from being able to execute processes. There might be individual applications that require some whitelisting. There is way more to work on here. Please feel welcome to get back to me with feedback and suggestions for further improvements. Twitter @HolgerJunker is a good way to catch me.

## License and Credits
license: this script is published under GPLv3 - please feel free to use and improve it.

_author:_ Holger Junker ([@HolgerJunker](https://twitter.com/HolgerJunker))

logo: © Can Stock Photo / Tribalium

technical credits: the initial implementation was re-done based on the great script Process Spawn Control (PsC, [website](https://github.com/felixweyne/ProcessSpawnControl)) from Felix Weyne in 2018.

Please also take a look at [ProcessBouncerService](https://github.com/Rotrixx/ProcessBouncerService) - an implementation of the same approach but as a windows service instead of a powershell script created by [@r0trixx](https://twitter.com/r0trixx) during his internship at my workplace in BSI.

musical credits: the work based on Felix's code was mainly done while listening to the great music of Mono Inc (e.g. Children of the Dark or Voices of Doom).
