<#
    Author:      Max Capote
    
    Project:     Windows Enumeration PowerShell Tool
    
    Description: The goal of this small project is to provide a fairly comprehensive
                 tool for becoming familiar with both PowerShell as well as what
                 information is important to enumerate while attempting to elevate
                 privileges on a Windows machine
#>

<#
    Negligable errors may be thrown when attempting to find certain components that
    are not installed or otherwise missing, so setting this preference just makes
    for cleaner output in some instances
#>
$ErrorActionPreference = 'SilentlyContinue'

# A constant value used to indicate that a user wishes to exit the module
Set-Variable EXIT_MENU_OPTION -option Constant -value 6

# The following two constants are used for referencing specific directories
# that come up when digging through the system for files possibly containing
# passwords
Set-Variable SYSTEM_ROOT -option Constant -value $Env:SystemRoot
Set-Variable USER_PROFILE -option Constant -value $Env:USERPROFILE

<#
    ================================================================================
        UI and Utility Functions
    ================================================================================
#>

function Border {
    Write-Host "====================================================="
}

function Banner {
    <#
        I completely acknowledge that using a Here-String for a
        multi-line string is better practice than a series of
        Write-Host, but I think Here-String makes the formatting
        of the actual function less clear. Do as I say, not as I
        do
    
        A) Here-String

            Write-Host @"
        |  Windows Privilege Escalation Enumeration Module  |
        |           Author: Max Capote | T0uri5t            |
        "@

        B) Write-Host

            Write-Host "|  Windows Privilege Escalation Enumeration Module  |"
            Write-Host "|           Author: Max Capote | T0uri5t            |"
    #>

    Write-Host "|  Windows Privilege Escalation Enumeration Module  |"
    Write-Host "|           Author: Max Capote | T0uri5t            |"
}

function BuildFullBanner {
    # Interesting note, in PowerShell, 'clear' and 'cls' are
    # aliases for this 'Clear-Host' command
    Clear-Host
    Border
    Banner
    Border
}

function GetAnswer {
    return Read-Host "`nOpt (Ex: 0)"
}

function HandleInputMain {
    $answer = GetAnswer

    switch ($answer) {
        0 {GetOSInfo; break}
        1 {GetUserEnum; break}
        2 {GetNetEnum; break}
        3 {GetProcsAndTasks; break}
        4 {GetPasswdLocations; break}
        5 {OtherMenu; break}
        default {break}
    }

    return DetermineTermination -answer $answer
}

function DetermineTermination {
    <#
        The 'param' function gives a lot of control over parameters.
        Using this, parameters can be named or positional. To add, a
        data type could be specified, but is not required. For example,
        I do not include one for the paramter below so that the main
        loop just continues to iterate given an invalid option. Lastly,
        we can also specify if a parameter must be passed to the given
        function by setting the 'Mandatory' field
      
        Additional Examples:

            A) [Parameter(Mandatory=$true, Position=0)]
               [string] $Message

            B) function Ex-HelloWorld([String] $Message)

            c) function Ex-HelloWorld([String] $Message = "Hello")
    #>
    param (
        $answer
    )

    if ($answer -ne $EXIT_MENU_OPTION) {
        return $true
    } else {
        return $false
    }
}

function MainMenu {
    BuildFullBanner
    Write-Host "|   (0) General OS Information                      |"
    Write-Host "|   (1) User and Group Enumeration                  |"
    Write-Host "|   (2) Network Enumeration                         |"
    Write-Host "|   (3) Process and Task Enumeration                |"
    Write-Host "|   (4) Possible Password Locations                 |"
    Write-Host "|   (5) Other                                       |"
    Write-Host "|   (6) Exit                                        |"
    Border
    return HandleInputMain
}

function HandleInputOther {
    switch (GetAnswer) {
        0 {GetUSP; break}
        1 {GetAIE; break}
        2 {GetStoredCreds; break}
        3 {GetDrivers; break}
        4 {GetWSL; break}
        default {break}
    }
}

function OtherMenu {
    BuildFullBanner
    Write-Host "|   (0) Unquoted Service Paths                      |"
    Write-Host "|   (1) AlwaysInstallElevated                       |"
    Write-Host "|   (2) Stored Credentials                          |"
    Write-Host "|   (3) Drivers                                     |"
    Write-Host "|   (4) Windows Subsystem for Linux                 |"
    Write-Host "|   (5) Return to Main Menu                         |"
    Border
    HandleInputOther
}

# This useful bit will hold the console until a keystroke is provided
function HoldUntilReady {
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function ExitMessage {
    Clear-Host
    Write-Host "`nThanks for stopping by ;)`n"
    sleep(1)
}

<#
    ================================================================================
        END UI and Utility Functions
    ================================================================================
#>

<#
    ================================================================================
        Primary Functions
    ================================================================================
#>

function GetOSInfo {
    Clear-Host
    Border

    <#
        Get-WmiObject is a command I have found to be very useful. It essentially
        finds instances of WMI classes or information about the available classes,
        of which there are many

        Get-ChildItem is another extremely useful utility and essentially functions
        as a general 'find' for PowerShell as it acquires the items of a directory
        as well as each subdirectory
    #>

    Write-Host "`n`nBasic OS Information for Host ($Env:COMPUTERNAME):`n"
    Write-Host -NoNewLine "OS Name:               " (((Get-WmiObject Win32_OperatingSystem).Name).Split("|")[0] | Out-String)
    Write-Host -NoNewLine "OS Version:            " ((Get-WmiObject Win32_OperatingSystem).Version | Out-String)
    Write-Host -NoNewLine "Current Build:         " ((Get-WmiObject Win32_OperatingSystem).BuildNumber | Out-String)
    Write-Host "OS Architecture:       " ((Get-WmiObject Win32_OperatingSystem).OSArchitecture | Out-String) "`n"
    Border

    Write-Host "`n`nPatches and Updates:"
    Write-Host -NoNewLine (Get-HotFix | Select-Object Description,HotFixID,InstalledOn | Out-String)
    Border

    Write-Host "`n`nAll Environment Variables:"
    Write-Host -NoNewLine (Get-ChildItem Env: | Out-String)
    Border

    Write-Host "`n`nAvailable Drives:"
    Write-Host -NoNewLine (Get-PSDrive | where {$_.Provider -like 'Microsoft.PowerShell.Core\FileSystem'} | Out-String)
    Border

    Write-Host "`n`nPowerShell:`n"
    Write-Host "Version:   " $PSVersionTable.PSVersion "`n`n"
    Border

    HoldUntilReady
}

function GetUserEnum {
    Clear-Host
    Border

    # Environment variables generally contain noteworthy information, and
    # referencing them in PowerShell is pretty simple -> as seen in the
    # immediate block of code

    Write-Host "`n`nWho You Are:`n"
    Write-Host $Env:USERDOMAIN\$Env:USERNAME "`n`n"
    Border

    Write-Host "`n`nLocal Users:"
    Write-Host -NoNewLine (Get-LocalUser | Out-String)
    Border

    Write-Host "`n`nUsers Under 'C:\Users\':"
    Write-Host -NoNewLine (Get-ChildItem C:\Users -Force -Directory | Select-Object Name | Out-String)
    Border

    Write-Host "`n`nLogin Requirements:`n"
    Write-Host (net accounts | Out-String)
    Border

    Write-Host "`n`nLocal Groups:"
    Write-Host -NoNewLine (Get-LocalGroup | Select-Object Name | Out-String)
    Border

    # Commented out due to sheer amount of output while testing
    #Write-Host "`n`nDomain Groups:`n"
    #Write-Host (net group /domain | Out-String)
    #Border

    HoldUntilReady
}

function GetNetEnum {
    Clear-Host
    Border

    Write-Host "`n`nNetwork Adapter IPv4 Information:"
    Write-Host -NoNewLine (Get-NetIPAddress -AddressFamily IPv4 | Out-String)
    Border

    Write-Host "`n`nTCP Port Information:"
    Write-Host -NoNewLine (Get-NetTCPConnection | Sort-Object -Property RemoteAddress | Format-Table LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Out-String)
    Border

    <#
        Sadly, 'CMD' commands do not always translate well to PowerShell. I have
        tried to keep the project as pure to PowerShell as I can, but compromises had
        to be made with some features
    #>

    Write-Host "`n`nCurrent Routing Tables:`n"
    Write-Host (route print | Out-String) "`n"
    Border

    Write-Host "`n`nARP Table:"
    Write-Host -NoNewLine (Get-NetNeighbor -AddressFamily IPv4 | Sort-Object -Property IPAddress| Format-Table IPAddress,LinkLayerAddress,State | Out-String)
    Border

    Write-Host "`n`nFirewall Configuration:"
    Write-Host -NoNewLine (Get-NetFirewallProfile | Format-List Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowUserApps,AllowUserPorts,LogFileName | Out-String)
    Border

    # Commented out due to sheer amount of output while testing
    #Write-Host "`n`nAll Firewall Rules:"
    #Write-Host -NoNewLine (Get-NetFirewallRule | Out-String)
    #Border

    Write-Host "`n`nSMB Shares:"
    Write-Host -NoNewLine (Get-SmbShare | Out-String)
    Border

    HoldUntilReady
}

function GetProcsAndTasks {
    Clear-Host
    Border

    Write-Host "`n`nAvailable Processes:"
    Write-Host -NoNewLine (Get-Process | Format-Table ProcessName, Id | Out-String)
    Border

    # This output is quite messy, sadly
    Write-Host "`n`nProcesses Running as SYSTEM:`n"
    Write-Host (tasklist /v /fi "username eq system")
    # 'Get-Process -IncludeUserName' requires elevated privileges
    Write-Host "`n"
    Border

    Write-Host "`n`nInstalled Programs Under 'C:\Program Files\' and 'C:\Program Files (x86)\':"
    Write-Host -NoNewLine (Get-ChildItem 'C:\Program Files\', 'C:\Program Files (x86)\' | ft Parent,Name,LastWriteTime | Out-String)
    Border

    Write-Host "`n`nInstalled Programs Under 'HKLM':"
    Write-Host -NoNewLine (Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name | Out-String)
    Border

    Write-Host "`n`nScheduled Tasks:"
    # Here, the final output displays scheduled tasks for non-MS entities
    Write-Host -NoNewLine (Get-ScheduledTask | where {$_.TaskPath -notlike '\Microsoft*'} | Out-String)
    Border

    Write-Host -NoNewLine "`n`nStartup Tasks:"
    Write-Host -NoNewLine (Get-CimInstance Win32_StartupCommand | Select-Object Name,command,Location,User | Format-List | Out-String)
    Border

    HoldUntilReady
}

function GetPasswdLocations {
    Clear-Host
    Border

    <#
        A note: The registry can also be queried in an attempt to uncover
        passwords. I opted to leave that functionality out just for the sake
        of simplicity and clarity of output
    #>

    Write-Host "`n`nFiles Possibly Containing Passwords:`n"
    $files = LoadFilepaths
    foreach ($file in $files) {
        if ((Get-Content $file | Out-String) -Like "*pass*") {
            Write-Host $file
        }
    }
    Write-Host "`n"
    Border

    HoldUntilReady
}

function LoadFilepaths {
    <#
        This disgusting block is an array of strings that contains
        filepaths that are likely to contain credentials
    
        There may be an argument for just traversing the entire file system
        for such files, but in doing this focused approach, we may at least save
        some amount of time and performance
    #>

    return "C:\unattend.xml",
    "C:\inetpub\wwwroot\web.config",
    "$USER_PROFILE\pagefile.sys",
    "$USER_PROFILE\ntuser.dat",
    "$SYSTEM_ROOT\Panther\unattend.xml",
    "$SYSTEM_ROOT\Panther\Unattend\unattend.xml",
    "$SYSTEM_ROOT\debug\NetSetup.log",
    "$SYSTEM_ROOT\iis6.log",
    "$SYSTEM_ROOT\system32\config\AppEvent.Evt",
    "$SYSTEM_ROOT\system32\config\SecEvent.Evt",
    "$SYSTEM_ROOT\system32\config\default.sav",
    "$SYSTEM_ROOT\system32\config\security.sav",
    "$SYSTEM_ROOT\system32\config\software.sav",
    "$SYSTEM_ROOT\system32\config\system.sav",
    "$SYSTEM_ROOT\System32\drivers\etc\hosts",
    "$SYSTEM_ROOT\System32\drivers\etc\lmhosts.sam",
    "$SYSTEM_ROOT\repair\SAM",
    "$SYSTEM_ROOT\System32\config\RegBack\SAM",
    "$SYSTEM_ROOT\System32\config\SAM",
    "$SYSTEM_ROOT\System32\config\SYSTEM",
    "$SYSTEM_ROOT\System32\config\RegBack\system"
}

function GetUSP {
    Clear-Host
    Border

    Write-Host "`n`nUnquoted Service Paths:`n"
    $services = Get-WmiObject win32_service
    foreach ($service in $services) {
        if (-Not ($service.pathname.Contains('"'))) {
            Write-Host "Service Name:   " $service.name
            Write-Host "Service Path:   " $service.pathname "`n"
        }
    }
    Write-Host
    Border

    HoldUntilReady
}

function GetAIE {
    Clear-Host
    Border

    Write-Host "`n`nAlwaysInstallElevated:`n`n"
    $hkcu = GETAIE-Helper -location "HKCU"
    if ($hkcu -ne $null) {
        Write-Host "AlwaysInstallElevated is present in HKCU and set to $hkcu`n`n"
    }
    $hklm = GETAIE-Helper -location "HKLM"
    if ($hklm -ne $null) {
        Write-Host "AlwaysInstallElevated is present in HKLM and set to $hklm`n`n"
    }
    Border
    
    HoldUntilReady
}

function GETAIE-Helper {
    param (
        [string] $location
    )

    try {
        $val = (Get-ItemProperty -Path "$location":\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated).AlwaysInstallElevated
        throw
    } catch {
        Write-Host "AlwaysInstallElevated key is not present in $location`n`n"
    }

    return $val
}

function GetStoredCreds {
    Clear-Host
    Border

    $str = (cmdkey /list | Out-String)
    Write-Host "`n`n" (-join $str[2..($str.length - 1)])
    Border

    HoldUntilReady
}

function GetDrivers {
    Clear-Host
    Border

    Write-Host "`n`nDrivers:"
    Write-Host (driverquery | Out-String) "`n"
    Border
    
    HoldUntilReady
}

function GetWSL {
    Clear-Host
    Border

    Write-Host "`n`nWindows Subsystem for Linux:`n"
    if ($(Get-WmiObject -query "select * from Win32_OptionalFeature where name = 'Microsoft-Windows-Subsystem-Linux'").InstallState -ne 1) {
        Write-Host "WSL is not currently installed`n`n"
    } else {
        Write-Host "WSL is currently installed`n`n"
    }
    Border

    HoldUntilReady
}

<#
    ================================================================================
        END Primary Functions
    ================================================================================
#>

<#
    ================================================================================
       'Main'
    ================================================================================
#>

while(MainMenu) {
}

ExitMessage

<#
    ================================================================================
        END 'Main'
    ================================================================================
#>
