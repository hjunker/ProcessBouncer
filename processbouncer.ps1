########################################
#
# ProcessBouncer - preventing ransomware with a simple script
#
# WARNING: Running this script shall prevent you from most of the current ransomware
# samples that are out there. This script is not a replacement for anti virus software,
# endpoint detection, etc. - it is only an additional security measure
# Everyone is advised to be careful and watch his or her clicks.

########################################


#
# 1. settings (CONFIG section)
#

$showPopup = $True
$popupWidth=650;
$popupScreenBorderDistance=20;

# logfile
$time = (Get-Date -Format "yyyy-MM-dd_HH-mm-ss");
$out_file = ".\ProcessBouncer-" + $time + ".log";

# To enable / disable reporting suspicious findings to the given endpoint can be done by setting $reportfindings to $True / $False. deactivate feedback you can comment the following line. But keep in mind that only by giving this kind of feedback there can be further improvements to ProcessBouncer.
$reportfindings = $False

# URL of the endpoint where suspicious finding is reported to (if $reportfindings == $True)
$endpointUrl = "http://www.seculancer.de/test.php"

# These processes are considered suspicious mostly but there are further checks. Handle with care.
# if you really need to run stuff like powershell or cmd, do not include them here. It might be better for you to catch them with suspicious parents - e.g. a svchost.exe called from powershell might be worth blocking.
$suspiciousProcesses=@("powershell.exe", "powershell","cmd.exe", "cmd");

# These LotL tools (meaning: living off the land tools already present on the victim's system that come handy for an attacker - not the great band lord of the lost)
$lotlTools=@("at", "at.exe", "bitsadmin", "bitsadmin.exe", "certutil", "certutil.exe", "cmd", "cmd.exe", "cmstp", "cmstp.exe", "control", "control.exe", "copy", "copy.exe", "csc", "csc.exe", "cscript", "cscript.exe", "curl", "curl.exe", "eqnedt32", "eqnedt32.exe", "hh", "hh.exe", "installutil", "installutil.exe", "javaw", "javaw.exe", "msbuild", "msbuild.exe", "mshta", "mshta.exe", "msiexec", "msiexec.exe", "msxsl", "msxsl.exe", "net", "net.exe", "netsh", "netsh.exe", "powershell", "powershell.exe", "psexec", "psexec.exe", "reg", "reg.exe", "regasm", "regasm.exe", "regedit", "regedit.exe", "regsvcs", "regsvcs.exe", "regsvr32", "regsvr32.exe", "remcos", "remcos.exe", "rundll32", "rundll32.exe", "runonce", "runonce.exe", "sc", "sc.exe", "schtasks", "schtasks.exe", "streams", "streams.exe", "tasklist", "tasklist.exe", "whoami", "whoami.exe", "winexesvc", "winexesvc.exe", "wmic", "wmic.exe", "wscript", "wscript");

# add # at the beginning of the following line to NOT check for LotL tools in suspiciousProcesses
$suspiciousProcesses = [array]$suspiciousProcesses + $lotlTools;

# These processes are considered suspicious when they become parents by creating a child process. Handle with care.
$suspiciousParents=@("WINWORD","WINWORD.EXE","EXCEL","EXCEL.EXE","powershell.exe","powershell","cmd","cmd.exe");

# these processes are whitelisted - meaning the just pass through Process Bouncer. Handle with greatest care. Malicious processes might lie about their name.
$ignoredProcesses=@("chrome.exe","dllhost.exe","SearchProtocolHost.exe","SearchFilterHost.exe","taskhost.exe", "conhost.exe", "SearchProtocolHost", "SearchProtocolHost.exe", "backgroundTaskHost.exe", "RuntimeBroker.exe"); #these processes will never be suspended

# these executable paths are considered suspicious. Handle with care
$suspiciousExecutablePaths=@("C:\\Users");#, $env:TEMP,[System.IO.Path]::GetTempPath(),$env:USERPROFILE);

# these whitelisted entries can skip detection e.g. for LotL tools! Handle with extreme care! Do not include things like C:\\Windows or C:\\WINDOWS\\system32 here!
#$whitelistedExecutablePaths = @("---");
$whitelistedExecutablePaths = @("C:\\hp", "C:\Programme", "C:\\Progra~1", "C:\\ProgramData", "C:\\Program Files (x86)\\Google\\Chrome\\Application", "C:\\Program Files\\Realtek\\Audio", "C:\\Program Files (x86)\\Microsoft\\Edge Dev\\Application", "C:\\Windows", "C:\\WINDOWS\\system32", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories");

# Suspicious double extension of file
$ext1 = @("jpg", "jpeg", "pdf", "doc", "docx", "docm", "dot", "xls");
$ext2 = @("exe", "com", "ps1", "dll", "bat", "pif");
ForEach ($e1 in $ext1)
	{
		ForEach ($e2 in $ext2)
		{
			[array]$DoubleExtensions += $e1 + "." + $e2;
		}
	}

# length which seems suspicious for some calls, might be e.g. from powershell payload
$suspiciousCmdLen = 20

# Test the default for TimeSpan is (0,0,0,0,750). Shorter time spans can result in increased system load. Longer time spans can result in blind spots with regards to very short-lived processes (which might apply to malicious powershell calls). Handle with a lot of care.
$new_process_check_interval = New-Object System.TimeSpan(0,0,0,0,750); #public TimeSpan (int days, int hours, int minutes, int seconds, int milliseconds);

#
# 2. setup - write some things to files from registry, ...
#

Add-Content -Path $out_file -Value ($time + ' - ProcessBouncer starting...')

# The following log data is written locally. It might be helpful for debugging yourself or if you need support from me.
$(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber

Add-Content -Path $out_file -Value ("Windows Major Version: " + $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber);
Add-Content -Path $out_file -Value ("Windows Minor Version: " + $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMinorVersionNumber).CurrentMinorVersionNumber);
#Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security' VBAWarnings).VBAWarnings);
#Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security' VBAWarnings).VBAWarnings);
#Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\excel\security' VBAWarnings).VBAWarnings);
#Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security' VBAWarnings).VBAWarnings);
#Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security' VBAWarnings).VBAWarnings);
#Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\powerpoint\security' VBAWarnings).VBAWarnings);
#Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\software\policies\microsoft\office\16.0\word\security' VBAWarnings).VBAWarnings);
Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\Environment: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Environment' Path).Path);
Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\Environment: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Environment' TEMP).TEMP);
Add-Content -Path $out_file -Value ("HKEY_CURRENT_USER\Environment: " + $(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Environment' TMP).TMP);

#cmd /c assoc

# TODO: Create undo-file when making changes!
#cmd /c ftype htafile
#cmd /c ftype WSHFile
#cmd /c ftype batfile
#cmd /c ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
#cmd /c ftype WSHFile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
#cmd /c ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"

#:: Block Office applications from creating child processes
#powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
#:: Block Office applications from injecting code into other processes
#powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enable
#:: Block Win32 API calls from Office macro
#powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enable
#:: Block Office applications from creating executable content
#powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids '3B576869-A4EC-4529-8536-B80A7769E899' -AttackSurfaceReductionRules_Actions enable
#:: Block execution of potentially obfuscated scripts
#powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
#:: Block executable content from email client and webmail
#powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
#:: Block JavaScript or VBScript from launching downloaded executable content
#powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled

Add-Content -Path $out_file -Value "---PROCESSES---";
Add-Content -Path $out_file -Value (Get-Process);
Add-Content -Path $out_file -Value "---SERVICES---";
Add-Content -Path $out_file -Value (Get-Service);
Add-Content -Path $out_file -Value "---HOTFIXES---";
Add-Content -Path $out_file -Value (Get-HotFix);
Add-Content -Path $out_file -Value "---AUTORUN---";
Add-Content -Path $out_file -Value (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\run);
Add-Content -Path $out_file -Value "---NETFIREWALLRULES---";
Add-Content -Path $out_file -Value (Get-NetFirewallRule -all);


#
# 3. Functionality to suspend and resume processes
# Source of this function: Poshcode, Joel Bennett 
#
Add-Type -Name Threader -Namespace "" -Member @"
	[Flags]
	public enum ProcessAccess : uint
	{
		Terminate = 0x00000001,
		CreateThread = 0x00000002,
		VMOperation = 0x00000008,
		VMRead = 0x00000010,
		VMWrite = 0x00000020,
		DupHandle = 0x00000040,
		SetInformation = 0x00000200,
		QueryInformation = 0x00000400,
		SuspendResume = 0x00000800,
		Synchronize = 0x00100000,
		All = 0x001F0FFF
	}

	[DllImport("ntdll.dll", EntryPoint = "NtSuspendProcess", SetLastError = true)]
	public static extern uint SuspendProcess(IntPtr processHandle);

	[DllImport("ntdll.dll", EntryPoint = "NtResumeProcess", SetLastError = true)]
	public static extern uint ResumeProcess(IntPtr processHandle);

	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(ProcessAccess dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

	[DllImport("kernel32.dll", SetLastError=true)]
	public static extern bool CloseHandle(IntPtr hObject);
"@

function Suspend-Process($processID) {
	if(($pProc = [Threader]::OpenProcess("SuspendResume", $false, $processID)) -ne [IntPtr]::Zero){
		Write-Host "Trying to suspend process: $processID"

		$result = [Threader]::SuspendProcess($pProc)
		if($result -ne 0) {
			Write-Error "Failed to suspend. SuspendProcess returned: $result"
			return $False
		}
		[Threader]::CloseHandle($pProc) | out-null;
	} else {
		Write-Error "Unable to open process. Not elevated? Process doesn't exist anymore?"
		return $False
	}
	return $True
}

function Resume-Process($processID) {
	if(($pProc = [Threader]::OpenProcess("SuspendResume", $false, $processID)) -ne [IntPtr]::Zero){
		Write-Host "Trying to resume process: $processID"
		Write-Host ""
		$result = [Threader]::ResumeProcess($pProc)
		if($result -ne 0) {
			Write-Error "Failed to resume. ResumeProcess returned: $result"
		}
		[Threader]::CloseHandle($pProc) | out-null
	} else {
		Write-Error "Unable to open process. Process doesn't exist anymore?"
	}
}

# TODO: Terminate suspicious processes instead of just keeping them suspended
function Terminate-Process($processID) {
	if(($pProc = [Threader]::OpenProcess("SuspendResume", $false, $processID)) -ne [IntPtr]::Zero){
		Write-Host "Trying to terminate process: $processID"
		Write-Host ""
		$result = [Threader]::TerminateProcess($pProc)
		if($result -ne 0) {
			Write-Error "Failed to terminate. TerminateProcess returned: $result"
		}
		[Threader]::CloseHandle($pProc) | out-null
	} else {
		Write-Error "Unable to open process. Process doesn't exist anymore?"
	}
}

#
# 4. Functionality to create user interface popup dialog
#

#function GenerateForm($processName,$processID,$parentProcessName) {
	[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null;
	[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null;

	$screen = [System.Windows.Forms.Screen]::PrimaryScreen;
	$bounds = $screen.Bounds;
	 
	$mainForm = New-Object System.Windows.Forms.Form;
	$mainForm.TopMost = $True
	$labelProcessRun = New-Object System.Windows.Forms.Label;
	$labelRunningProcess = New-Object System.Windows.Forms.Label;
	$labelProcessID = New-Object System.Windows.Forms.Label;
	$labelParentProcessID = New-Object System.Windows.Forms.Label;
	$closeFormButton = New-Object System.Windows.Forms.Button;
	$resumeButton = New-Object System.Windows.Forms.Button;
	$suspendButton = New-Object System.Windows.Forms.Button;

	#button event handlers;
	$handler_closeFormButton_Click={
		$this.findform().close();
	}

	$handler_resumeButton_Click={ 
		if ($listBox.SelectedItem -ne $null){
			#[int]$processToResume=[convert]::ToInt32($this.Tag);
			$selectedId = $listBox.SelectedItem.substring($listBox.SelectedItem.IndexOf('(')+1,$listBox.SelectedItem.IndexOf(')')-$listBox.SelectedItem.IndexOf('(')-1);
			#[int]$processToResume=[convert]::ToInt32($listBox.SelectedItem);
			[int]$processToResume=[convert]::ToInt32($selectedId);
			$outstr = "Process " + $listBox.SelectedItem + " resumed by user.";
			Add-Content -Path $out_file -Value $outstr;
			$listBox.Items.Remove($listBox.SelectedItem);
			Resume-Process -processID $processToResume
			#$this.findform().close();
		}
	}
	$handler_suspendButton_Click={
		if ($listBox.SelectedItem -ne $null){
			$outstr = "Process " + $listBox.SelectedItem + " kept suspended by user.";
			Add-Content -Path $out_file -Value $outstr;
			$listBox.Items.Remove($listBox.SelectedItem);
			#$this.findform().close();
		}
	}

	#resume/suspend form
	$popupHeight=$popupWidth*0.4;
	$mainForm.Size = new-object System.Drawing.Size $popupWidth,$popupHeight;
	$mainForm.ControlBox = $False;
	$mainForm.Name = "mainForm";
	$mainForm.FormBorderStyle = 'None';
	$mainForm.BackColor = '#2c3e5b';
	$mainForm.Text = "ProcessBouncer Warning: New process";
	$mainForm.Left = $bounds.Right-$popupWidth-$popupScreenBorderDistance; 
	$mainForm.Top = $bounds.Top+$popupScreenBorderDistance	; 
	$mainForm.StartPosition = 'Manual'; 

	#label description new process
	$labelProcessRun.Text = "ProcessBouncer wants to deny access:"
	$labelProcessRun.AutoSize = $True
	$labelProcessRun.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelProcessRun.ForeColor = 'white';
	$labelProcessRun_drawingPoint = New-Object System.Drawing.Point;
	$labelProcessRun_drawingPoint.X = ($popupWidth*0.05);
	$labelProcessRun_drawingPoint.Y = ($popupHeight*0.06);
	$labelProcessRun.Location = $labelProcessRun_drawingPoint;

	#label running process
	$labelRunningProcess.Text = "Process: $processName"
	$labelRunningProcess.AutoSize = $True
	$labelRunningProcess.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelRunningProcess.ForeColor = 'white';
	$labelRunningProcess_drawingPoint = New-Object System.Drawing.Point;
	$labelRunningProcess_drawingPoint.X = ($popupWidth*0.05);
	$labelRunningProcess_drawingPoint.Y = ($popupHeight*0.25);
	$labelRunningProcess.Location = $labelRunningProcess_drawingPoint;

	#label process id
	$labelProcessID.Text = "Process ID: $processID"
	$labelProcessID.AutoSize = $True
	$labelProcessID.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelProcessID.ForeColor = 'white';
	$labelProcessID_drawingPoint = New-Object System.Drawing.Point;
	$labelProcessID_drawingPoint.X = ($popupWidth*0.05);
	$labelProcessID_drawingPoint.Y = ($popupHeight*0.4);
	$labelProcessID.Location = $labelProcessID_drawingPoint;

	#label parent process name 
	$labelParentProcessID.Text = "Parent Process: $parentProcessName"
	$labelParentProcessID.AutoSize = $True
	$labelParentProcessID.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$labelParentProcessID.ForeColor = 'white';
	$labelParentProcessID_drawingPoint = New-Object System.Drawing.Point;
	$labelParentProcessID_drawingPoint.X = ($popupWidth*0.05);
	$labelParentProcessID_drawingPoint.Y = ($popupHeight*0.55);
	$labelParentProcessID.Location = $labelParentProcessID_drawingPoint;

	#CloseForm Button
	$closeFormButton.TabIndex = 2;
	$closeFormButton_drawingSize = New-Object System.Drawing.Size;
	$closeFormButton_drawingSize.Width = 0.05*$popupWidth;
	$closeFormButton_drawingSize.Height = 0.05*$popupWidth;
	$closeFormButton.Size = $closeFormButton_drawingSize;
	$closeFormButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat;
	$closeFormButton.FlatAppearance.BorderSize = 0;
	$closeFormButton.ForeColor = 'White';
	$closeFormButton.Text = "X";

	$closeFormButton_drawingPoint = New-Object System.Drawing.Point;
	$closeFormButton_drawingPoint.X = ($popupWidth*0.93);
	$closeFormButton_drawingPoint.Y = ($popupHeight*0.05);
	$closeFormButton.Location = $closeFormButton_drawingPoint;

	#resume process button
	$resumeButton.TabIndex = 0;
	$resumeButton_drawingSize = New-Object System.Drawing.Size;
	$resumeButton_drawingSize.Width = 0.40*$popupWidth;
	$resumeButton_drawingSize.Height = 0.20*$resumeButton_drawingSize.Width;
	$resumeButton.Size = $resumeButton_drawingSize;
	$resumeButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat;
	$resumeButton.FlatAppearance.BorderColor = 'White';
	$resumeButton.ForeColor = 'White';
	$resumeButton.BackColor = '#169355';
	$resumeButton.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$resumeButton.Text = "Allow run";
	$resumeButton.Tag = $processID;

	$resumeButton_drawingPoint = New-Object System.Drawing.Point;
	$resumeButton_drawingPoint.X = ($popupWidth*0.05);
	$resumeButton_drawingPoint.Y = ($popupHeight*0.75);
	$resumeButton.Location = $resumeButton_drawingPoint;

	#suspend process button
	$suspendButton.TabIndex = 1;
	$suspendButton_drawingSize = New-Object System.Drawing.Size;
	$suspendButton_drawingSize.Width = $resumeButton_drawingSize.Width;
	$suspendButton_drawingSize.Height = $resumeButton_drawingSize.Height;
	$suspendButton.Size = $suspendButton_drawingSize;
	$suspendButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat;
	$suspendButton.FlatAppearance.BorderColor = 'White';
	$suspendButton.ForeColor = 'White';
	$suspendButton.BackColor = '#921650';
	$suspendButton.Font = New-Object System.Drawing.Font("Lucida Console",9,[System.Drawing.FontStyle]::Regular);
	$suspendButton.Text = "Keep suspended";

	$suspendButton_drawingPoint = New-Object System.Drawing.Point;
	$suspendButton_drawingPoint.X = $popupWidth-($popupWidth*0.05) - $resumeButton_drawingSize.Width;
	$suspendButton_drawingPoint.Y = $resumeButton_drawingPoint.Y;
	$suspendButton.Location = $suspendButton_drawingPoint;

	$listBox = New-Object System.Windows.Forms.ListBox
	$listBox.Location = New-Object System.Drawing.Point(10,40)
	$listBox.Size = New-Object System.Drawing.Size(600,40)
	$listBox.Height = 80

	#add event handlers to buttons
	$closeFormButton.add_Click($handler_closeFormButton_Click);
	$resumeButton.add_Click($handler_resumeButton_Click);
	$suspendButton.add_Click($handler_suspendButton_Click);

	#add controls to form
	$mainForm.Controls.Add($closeFormButton);
	$mainForm.Controls.Add($resumeButton);
	$mainForm.Controls.Add($suspendButton);
	$mainForm.Controls.Add($labelProcessRun);
	#$mainForm.Controls.Add($labelProcessID);
	#$mainForm.Controls.Add($labelParentProcessID);
	#$mainForm.Controls.Add($labelRunningProcess);
	$mainForm.Controls.Add($listBox)

	#If we call $mainForm.ShowDialog() to launch the form, the console and form will share the same thread.
	#This means that the form will launch, and no further code of the powershell script will be processed run until the form closes.
	#We need to work around this by launching the form in a new runspace.
	#Source of tis code snippet: LogicVomit, Reddit. https://www.reddit.com/r/PowerShell/comments/41lebp/how_to_close_a_runspace_from_a_powershell_gui/ 
	$Runspace = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($Host);
	$Runspace.ApartmentState = 'STA';
	$Runspace.ThreadOptions = 'ReuseThread';
	$Runspace.Open();

	$Runspace.SessionStateProxy.SetVariable('mainForm', $mainForm);

	#Create new thread
	$PowerShellRunspace = [System.Management.Automation.PowerShell]::Create();
	$PowerShellRunspace.Runspace = $Runspace;
	$PowerShellRunspace.AddScript({
		$mainForm.ShowDialog();
	}) | out-null;

	# open and run the runspace asynchronously
	$AsyncResult = $PowerShellRunspace.BeginInvoke();
#}


#
# 5. Functionality to monitor newly created processes & interact with the suspend/resume functionality.
# 	 This makes use of Windows Management Instrumentation to get information about newly created processes.
#

#There is a bug in WqlEventQuery which occurs when the supplied time interval is too small and if your system locale is non-English (e.g. Belgian).
#(relevant StackOverflow page: https://stackoverflow.com/questions/5953434/wmi-query-in-c-sharp-does-not-work-on-non-english-machine)
#Should you get the error "Exception calling WaitForNextEvent ... Unparsable query", uncomment the below code which changes the culture for the PS session.
$culture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US');
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture;
[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture;

Write-Host "Monitoring newly spawned processes via WMI...";
Write-host "";

#https://docs.microsoft.com/en-us/dotnet/api/system.management.wqleventquery.withininterval
$scope = New-Object System.Management.ManagementScope("\\.\root\cimV2");
$query = New-Object System.Management.WQLEventQuery("__InstanceCreationEvent",$new_process_check_interval,"TargetInstance ISA 'Win32_Process'" );
$watcher = New-Object System.Management.ManagementEventWatcher($scope,$query);

$processSpawnCounter=1;
do
{
	$newlyArrivedEvent = $watcher.WaitForNextEvent(); #Synchronous call! If Control+C is pressed to stop the PowerShell script, PS will only react once the call has returned an event.
	$e = $newlyArrivedEvent.TargetInstance;
	Write-Host "($processSpawnCounter) New process spawned:";

	$processName=[string]$e.Name;
	Write-host "PID:`t`t" $e.ProcessId;
	Write-host "Name:`t`t" $processName;
	Write-host "PPID:`t`t" $e.ParentProcessID;
	Write-host "ExecutablePath:`t`t" $e.ExecutablePath;
	$filehash = "n/a";
	if ($e.ExecutablePath -ne $Null)
	{
		$filehash = (Get-FileHash $e.ExecutablePath -Algorithm SHA256).Hash;
        #$filehash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
	}
	Write-host "File Hash:`t`t" $filehash;
	#$itemproperties = Get-ItemProperty $e.ExecutablePath | Format-List;
	$itemproperties = Get-ChildItem $e.ExecutablePath;
	Write-host "filesize:`t`t" $itemproperties.Length;

	#Write-host "file properties:`t`t" $itemproperties;
	Write-host "CommandLine:`t`t" $e.CommandLine;

	if (($e.processName -eq "powershell.exe") -or ($e.processName -eq "powershell"))
	{
		# TODO: extract powershell payload from command line - i.e. throw away command and options from $e.CommandLine and put it into Write-host
	}

#	foreach ($item in $e){
#		Write-host "item:`t`t" $item;
#	}
	
	$parent_process=''; 
	try {$proc=(Get-Process -id $e.ParentProcessID -ea stop); $parent_process=$proc.ProcessName;} catch {$parent_process='unknown';}
	Write-host "Parent name:`t" $parent_process; 
	Write-host "CommandLine:`t" $e.CommandLine;

	$time = (Get-Date -UFormat "%A %B/%d/%Y %T");
	Add-Content -Path $out_file -Value ($time + "|" + $e.ProcessId + "|" + $processName + "|" + $parent_process + "|" + $e.ExecutablePath + "|" + $filehash + "|" + $e.CommandLine);

	$tobeignored = $False;
	$tobechecked = $False;

	# the following conditional statements can be tuned, extended, etc. to meet your specific requirements, minimize false positives, whitelist legitimate scripts and tools, ...
	#if (-not ($ignoredProcesses -match $processName))
	if (
		($ignoredProcesses -match $processName)
		)
	{
		$tobeignored = $True;
		Write-Host "-- ignoredProcesses match";
	}

	if (
		($null -ne ($whitelistedExecutablePaths | ? { $e.ExecutablePath -match $_ }))
		)
	{
		$tobeignored = $True;
		Write-Host "-- whitelistedExecutablePaths match";
	}

	if (
	   ($null -ne ($suspiciousProcesses | ? { $processName -match $_ }))
	   )
	   {
	   	$tobechecked = $True;
	   	Write-Host "-- suspiciousProcesses match";
	   }

	if (
	   ($suspiciousParents -match $parent_process)
	   )
	   {
	   	$tobechecked = $True;
	   	Write-Host "-- suspiciousParents match";
	   }

	   if (
	   ($null -ne ($suspiciousExecutablePaths | ? { $e.ExecutablePath -match $_ }))
	   )
	   {
	   	$tobechecked = $True;
	   	Write-Host "-- suspiciousExecutablePaths match";
	   }

	   if (
	   ($null -ne ($DoubleExtensions | ? { $e.ExecutablePath -match $_ }))
	   )
	   {
	   	$tobechecked = $True;
	   	Write-Host "-- doubleExtensions match";
	   }

#	   if (
#	   ($e.CommandLine.length -gt $suspiciousCmdLen)
#	   )
#	   {
#	   	$tobechecked = $True;
#	   	Write-Host "-- suspiciousCmdLen match";
#	   }

	if (($tobeignored -match $True) -and ($tobechecked -match $False))
	#if (($tobechecked -match $False))
	{
		Write-Host "Process ignored as per configuration.";
	}else{
		if(Suspend-Process -processID $e.ProcessId){
			Write-Host "Process is suspended. Creating GUI popup.";
			$outstr = "process " + $e.ProcessId + " has been suspended";
			Add-Content -Path $out_file -Value $outstr;
			if($reportfindings -match $True){
				$cmdlen = $e.CommandLine.Length;
				if ($cmdlen > 530) {
					$cmdlen = 530;
				}
				$url = $endpointUrl + "?procname=" + $processName + "&processParentName=" + $parent_process + "&executablePath=" + $e.ExecutablePath + "&CommandLine=" + $e.CommandLine.Substring(0,$cmdlen) + "&fileHash=" + $filehash
				#Write-host "Reporting URL: " + $url;
				$response = Invoke-WebRequest -URI $url
				}
			if ($showPopup -eq $True){
				#GenerateForm -processName $processName -processID $e.ProcessId -parentProcessName $parent_process -commandline $e.CommandLine;
				$listItemText = $processName + " initiated by " + $parent_process + " (" + $e.ProcessId + ")";
				#$listItemText = $e.ProcessId;
				[void] $listBox.Items.Add($listItemText)
				}
		}else{
			Write-Host "error during handling of suspicious process."
		}
	}

	Write-host "";
	$processSpawnCounter += 1;
} while ($True)
