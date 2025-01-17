<#
.SYNOPSIS
  To fix PC not getting Win Update coming from Intune Dist
.DESCRIPTION
  Fix Win10/11 Updating issues 
.PARAMETER <Parameter_Name>
  No parameters Required
.OUTPUTS
  Actions logged to \WinUpdateFixLog_[DATE]_.log
  DISM log to working folder
.NOTES
  Version:        1.3.6 
  Author:         Artur Ferreira
  Creation Date:  08.07.2024
  Purpose/Change: Service Desk Task Automation
  Company:        
  Contact for more info   
.EXAMPLE
  No example provided
#>

#When getting event from eventviewer we cannot silent the error with erroraction - so ignoring all errors.
#comment out bellow for troubleshooting script and for debug mode
$ErrorActionPreference= 'silentlycontinue'

#Region Functions
#****************************************************

#stop services and confirm they are stopped else request manual stop
function StopServiceCheck {
    param (
        [Parameter(Mandatory=$true)]
         [string] $ServiceName
    )

    $runningService = $true
    $counter = 0
    do{
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $checkService = Get-Service -Name $ServiceName    
        if(!($($checkService.Status) -eq "Running")) { $runningService = $false }
        Start-Sleep -Seconds 2
        $counter++
    }while(($runningService -eq $true) -and ($counter -le 10))
}

#function to write to log
function Write-Log {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$true)]
        [string]$LogFilePath
    )
    $date = get-date -format "ddmmyy hh:ss" 
    $logMessage = "[$date] :: $Message"
    Add-Content -Path $logFilePath -Value $logMessage
}

function GotError{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage,
        [Parameter(Mandatory=$true)]
        [string]$Location
    )
    $errorMsg =@"
    ****************************************************************************************************************
     ERROR::$Location > $ErrorMessage
     ****************************************************************************************************************
"@
    
    Write-Log -Message "`n $errorMsg" -LogFilePath $logPath
}

#****************************************************
#endregion Functions

#log info
$today = get-date -format "ddMMyy" 
$logPath = ".\WinUpdateFixLog_" + $today + "_.log"
#*********

#info on disk space available
Write-host "Cheking free Space"
#check free Space
$availableSpace = Get-WmiObject -Class Win32_LogicalDisk -ComputerName "localhost" | Where-Object {$_. DriveType -eq 3} | Select-Object DeviceID, {$_.Size /1GB}, {$_.FreeSpace /1GB} 
Write-Warning "Available free space: $($availableSpace.'$_.FreeSpace /1GB') GB"
Write-Log -Message "::Available Space:: > $($availableSpace.'$_.FreeSpace /1GB') GB" -LogFilePath $logPath


#check for HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update from intune policy ring
$checkForRingPolicyUpdateExistance = Get-ItemProperty -Path  "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update"
if([string]::IsnullOrempty($checkForRingPolicyUpdateExistance)){ 
    Write-Host "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update does NOT exist." -ForegroundColor Red
    Write-Host "Intune ring policy may not be correctly applied" -ForegroundColor Red
    Write-Log -Message "::Registry Check:: > HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update does NOT exist." -LogFilePath $logPath
} else {
    Write-Warning "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update  - Exists"
    Write-Log -Message "::Registry Check:: > HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update  - Exists" -LogFilePath $logPath
}

#check for compatible OS to update via intune win 10Pro , Enteterprise, 
write-host "Checking prerequisite OS..."
$runningOs = (Get-WmiObject -class Win32_OperatingSystem).Caption
Write-warning "Runing $runningOs"
Write-Log -Message "OS:: > $runningOs" -LogFilePath $logPath

##Checking EventViewer
write-host "Checking Event Viewer"
try {
    # When Windows Setup fails, the result and extend code are recorded as an informational event in the 
    #  Application log by Windows Error Reporting as event 1001. The event name is WinSetupDiag02
    $events = Get-WinEvent -FilterHashtable @{LogName="Application";ID="1001";Data="WinSetupDiag02"} -ErrorAction SilentlyContinue
    $event = [xml]$events[0].ToXml()
    $event.Event.EventData.Data
    $xmlPath = "Event_" + $today + ".xml"
    $event | Out-File -FilePath  $xmlPath -ErrorAction SilentlyContinue
    Write-Log -Message "XML from Event Viewer error log created: $xmlPath " -LogFilePath $logPath
}
catch {
    #Event 1001 or WinSetupDiag02 not found in EventViewer
    Write-Warning "Event ID 1001 or WinSetupDiag02 not found" 
    GotError -ErrorMessage $_ -Location "Event ID 1001 or WinSetupDiag02 not found"    
}

Pause

[array]$servicesList = @("bits","wuauserv","appidsvc","cryptsvc")

$retry = 1

#if the stopservicescheck function tries 10 times and fails to stop service  (as per function definition)
#we loop sending info to log of the event and forcing loops till the services are really stopped
Do{
    Write-Warning "Attempt $retry for stopping services"

    Write-Log -Message "[SYSTEM]:======== Attempt $retry for stopping services ========" -LogFilePath $logPath   

    #stoping services with warning for services not stopping
    Write-Warning "Running: Stoping Services" #INFO
    Write-Log -Message "Stoping Services" -LogFilePath $logPath
    try {
        foreach($service in $servicesList){
            StopServiceCheck -ServiceName $service
            Write-Log -Message "Stopping Service: $service" -LogFilePath $logPath
        }
    }
    catch {
        GotError -ErrorMessage $_ -Location "stoping services"
    }

    $servicesStopped = $true

    #Geting Service status
    $services = @{
        "bits" = (Get-Service bits).Status
        "wuauserv" = (Get-Service wuauserv).Status
        "appidsvc" = (Get-Service appidsvc).Status
        "cryptsvc" = (Get-Service cryptsvc).Status
        }

    #displaying services status
    $services

    #write system service status to log
    Write-Log -Message "[SYSTEM]: bits $($services.bits)" -LogFilePath $logPath
    Write-Log -Message "[SYSTEM]: wuauserv $($services.wuauserv)" -LogFilePath $logPath
    Write-Log -Message "[SYSTEM]: appidsvc $($services.appidsvc)" -LogFilePath $logPath
    Write-Log -Message "[SYSTEM]: cryptsvc $($services.cryptsvc)" -LogFilePath $logPath

    Write-Host "`n If any of the above services is still running you can try to terminate them manually before continuing `n"  -ForegroundColor Red
    Pause

    if($($services.bits) -eq "Running") { $servicesStopped = $false; Write-Log -Message "[SYSTEM]: BITS Service did NOT STOP" -LogFilePath $logPath }
    if($($services.wuauserv) -eq "Running") { $servicesStopped = $false; Write-Log -Message "[SYSTEM]: wuauserv Service did NOT STOP" -LogFilePath $logPath }
    if($($services.appidsvc) -eq "Running") { $servicesStopped = $false; Write-Log -Message "[SYSTEM]: appidsvc Service did NOT STOP" -LogFilePath $logPath }
    if($($services.cryptsvc) -eq "Running") { $servicesStopped = $false; Write-Log -Message "[SYSTEM]: cryptsvc Service did NOT STOP" -LogFilePath $logPath }

    $retry++

}while ($servicesStopped -eq $false)

#flushing DNS
Write-Warning "Running: flushdns" #INFO
Write-Log -Message " - Flushing DNS" -LogFilePath $logPath
try {
    Ipconfig /flushdns
    Write-Log -Message " - Flushing DNS: OK" -LogFilePath $logPath
}
catch {
    GotError -ErrorMessage $_ -Location "Flushing DNS"
}

#REG REMOVE From windows update
Write-Warning "Running: Clearing REG" #INFO
Write-Log -Message "REG REMOVE From windows update" -LogFilePath $logPath
try {
    $profPath = $env:ALLUSERSPROFILE
    $profPath_ = $profPath +"\Application Data\Microsoft\Network\Downloader\qmgr*.dat"
    
    Remove-Item -Path $profPath_ -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Deleted %ALLUSERPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat%" -LogFilePath $logPath

    $profPath__ = $profPath +"\Microsoft\Network\Downloader\qmgr*.dat"
    Remove-Item -Path $profPath__ -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Deleted %ALLUSERPROFILE\\Microsoft\Network\Downloader\qmgr*.dat" -LogFilePath $logPath

    Remove-Item "C:\Windows\Logs\WindowsUpdate\*" -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Deleted C:\Windows\Logs\WindowsUpdate\*" -LogFilePath $logPath
}
catch {
    GotError -ErrorMessage $_ -Location "REG REMOVE From windows update"
}

#Pending updates
Write-Warning "Running: Clearing pending.xml" #INFO
Write-Log -Message "Clearing pending.xml" -LogFilePath $logPath
try {
    if(Test-Path -Path "C:\Windows\winsxs\pending.xml.bak"){ 
        Remove-Item -Path "C:\Windows\winsxs\pending.xml.bak" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Deleted C:\Windows\winsxs\pending.xml.bak" -LogFilePath $logPath
    }
    if(Test-Path -Path "C:\Windows\winsxs\pending.xml"){ 
        takeown /f "C:\Windows\winsxs\pending.xml" 
        attrib -r -s -h /s /d "C:\Windows\winsxs\pending.xml" 
        Rename-Item "C:\Windows\winsxs\pending.xml" -NewName "C:\Windows\winsxs\pending.xml.bak" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Renamed C:\Windows\winsxs\pending.xml pending.xml.bak" -LogFilePath $logPath
    }
}
catch {
    GotError -ErrorMessage $_ -Location "Pending updates "
}

#SoftwareDistribution
Write-Warning "Running: Clearing SoftwareDistribution" #INFO
write-Log -Message "Clearing SoftwareDistribution.bak" -LogFilePath $logPath
try {
    if(Test-Path -Path "C:\Windows\SoftwareDistribution.bak"){ 
        Remove-Item -Path "C:\Windows\SoftwareDistribution.bak" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Deleted C:\Windows\SoftwareDistribution.bak" -LogFilePath $logPath
    }
    if(Test-Path -Path "C:\Windows\SoftwareDistribution"){ 
        attrib -r -s -h /s /d "C:\Windows\SoftwareDistribution" 
        
        ###### Fix #####
        Get-ChildItem -Path "C:\windows" | Where-Object {$_.Name -like "SoftwareDistribution*"} | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log -Message "Deleted C:\Windows\SoftwareDistribution* - FIXED" -LogFilePath $logPath
        ################
    }
}
catch {
    GotError -ErrorMessage $_ -Location " SoftwareDistribution "
}

#checking pol file for curruption before deleting
try {
    $pol_file = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
    [Byte[]]$pol_file_header = Get-Content -Encoding Byte -Path $pol_file -TotalCount 4 -ErrorAction SilentlyContinue
    if (($pol_file_header -join '') -eq '8082101103') {
        Write-Host "Checked: .pol file curruption Resul: NOT CURRUPTED" -ForegroundColor Yellow
        Write-Log -Message "Checked: .pol file curruption Resul: NOT CURRUPTED" -LogFilePath $logPath
    }
    else {
        Write-Host "Checked: .pol file curruption Resul: CURRUPTED" -ForegroundColor Red
        Write-Log -Message "Checked: .pol file curruption Resul: CURRUPTED" -LogFilePath $logPath
    }
}
catch {
    GotError -ErrorMessage $_ -Location " .pol  file curruption "
}

#Registry.pol
Write-Warning "Running: Clearing Registry.pol" #INFO
write-Log -Message "Clearing SoftwareDistribution.bak" -LogFilePath $logPath
try {
    if(Test-Path -Path "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"){ 
        attrib -h -r -s "C:\Windows\System32\GroupPolicy"
        Remove-Item -Path "C:\Windows\System32\GroupPolicy\Machine\Registry.pol" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Deleted C:\Windows\System32\GroupPolicy\Machine\Registry.pol" -LogFilePath $logPath
    }
}
 catch {
    GotError -ErrorMessage $_ -Location "  registry.pol "
}

#CatRoot
Write-Warning "Running: Clearing system32\Catroot2.bak" #INFO
Write-Log -Message "Clearing system32\Catroot2.bak" -LogFilePath $logPath
try {
    if(Test-Path -Path "C:\Windows\system32\Catroot2.bak"){ Remove-Item -Path "C:\Windows\system32\Catroot2.bak" -Force -ErrorAction SilentlyContinue}
    if(Test-Path -Path "C:\Windows\system32\Catroot2"){ 
        attrib -r -s -h /s /d "C:\Windows\system32\Catroot2" 
        Rename-Item "C:\Windows\system32\Catroot2" -NewName "C:\Windows\system32\Catroot2.bak " -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Renamed C:\Windows\system32\Catroot2 Catroot2.bak" -LogFilePath $logPath
    }
}
catch {
    GotError -ErrorMessage $_ -Location " catRoot "
}

#Registry Policies Reset
Write-Warning "Running: Reset Windows Update policies" #INFO
Write-Log -Message "Reset Windows Update policies" -LogFilePath $logPath
try {
    #Reset Windows Update policies
    Write-Warning "Running: Reset Win update Policies" #INFO
    Remove-Item -Path "Registry::HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Deleted [REG] HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -LogFilePath $logPath

    Remove-Item -Path  "Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Deleted [REG] HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -LogFilePath $logPath

    Remove-Item -Path  "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Deleted [REG] HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -LogFilePath $logPath

    Remove-Item -Path  "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Deleted [REG] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -LogFilePath $logPath
}
catch {
    GotError -ErrorMessage $_ -Location " Registry Policies Reset "
}

#it script times out comment bellow GPUPDATE PROCEDURE
Write-Warning "Running: GPUpdate - Please wait" #INFO
Write-Log -Message "GPUPDATE" -LogFilePath $logPath
try {
    gpupdate /force
}
catch {
    GotError -ErrorMessage $_ -Location " GPUPDATE "
}

#BITS
Write-Warning "Running: Reset BITS" #INFO
Write-Log -Message "Reset BITS" -LogFilePath $logPath
try {
    #Reset the BITS service and the Windows Update service to the default security descriptor
    $updateBits = "sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
    $updateBits | Out-File updateBits.bat
    start-process -FilePath ".\updateBits.bat"
    start-sleep -Seconds 1
    Remove-Item .\updateBits.bat -Force -Erroraction SilentlyContinue
}
catch {
    GotError -ErrorMessage $_ -Location "Reset BITS"
}

#Wuauserv
Write-Warning "Running: Reset Wuauserv" #INFO
Write-Log -Message "Reset Wuauserv" -LogFilePath $logPath
try {
    $updateWuauserv = "sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
    $updateWuauserv | Out-File updateWuauserv.bat
    start-process -FilePath ".\updateWuauserv.bat"
    start-sleep -Seconds 2
    Remove-Item .\updateWuauserv.bat -Force -Erroraction SilentlyContinue
}
catch {
    GotError -ErrorMessage $_ -Location "Reset Wuauserv"
}

Start-Sleep -Seconds 3

#dll array to re register
[array]$registerDLL =@("atl.dll","urlmon.dll","mshtml.dll","shdocvw.dll","browseui.dll","jscript.dll","vbscript.dll","scrrun.dll","msxml.dll","msxml3.dll","msxml6.dll","actxprxy.dll","softpub.dll","wintrust.dll","dssenh.dll","rsaenh.dll","gpkcsp.dll","sccbase.dll","slbcsp.dll","cryptdlg.dll","oleaut32.dll","ole32.dll","shell32.dll","initpki.dll","wuapi.dll","wuaueng.dll","wuaueng1.dll","wucltui.dll","wups.dll","wups2.dll","wuweb.dll","qmgr.dll","qmgrprxy.dll","wucltux.dll","muweb.dll","wuwebv.dll","wudriver.dll")

#Re-registering Dlls
Write-Warning "Running: Reregistering Dlls" #INFO
Write-Log -Message "Reregistering Dlls" -LogFilePath $logPath
try {
    ForEach($dll in $registerDLL){
        regsvr32.exe /s $dll
        Write-Log -Message ">> Registering $dll" -LogFilePath $logPath
    }
}
catch {
    GotError -ErrorMessage $_ -Location "Reregistering Dlls "
}

Start-Sleep -Seconds 2

#Sockets Reset
Write-Warning "Running: Reset Sockets" #INFO
Write-Log -Message "Reseting SOCKETS" -LogFilePath $logPath
try {
    netsh winsock reset
    netsh winsock reset proxy
    Write-Log -Message "Reset SOCKETS: OK" -LogFilePath $logPath
}
catch {
    GotError -ErrorMessage $_ -Location "Reseting SOCKETS"
}

Start-Sleep -Seconds 2

#Set the startup type as automatic
Write-Warning "Running: Config Sc" #INFO
Write-Log -Message "Sc config" -LogFilePath $logPath
try {
    $scCommands =@"
    sc config wuauserv start= auto
    sc config bits start= auto 
    sc config DcomLaunch start= auto 
"@
    $scCommands | Out-File scCommands.bat
    Start-Process -FilePath ".\scCommands.bat"
    Start-Sleep -Seconds 2
    Remove-Item .\scCommands.bat -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Sc Actions: OK" -LogFilePath $logPath
}
catch {
    GotError -ErrorMessage $_ -Location "Config Sc "
}

Start-Sleep -Seconds 3

#Restarting Services
Write-Warning "Running: Starting Services" #INFO
Write-Log -Message "Starting services" -LogFilePath $logPath
try {
    #start services
    foreach($service in $servicesList){
        Start-Service -ServiceName $service
        Write-Log -Message "Starting service: $service" -LogFilePath $logPath
    }
}
catch {
    GotError -ErrorMessage $_ -Location "Starting services "
}

#
DISM.exe /Online /Cleanup-image /Restorehealth
#

Start-Sleep -Seconds 1

#check if DISM found any curruption
if(Test-Path "C:\Windows\Logs\CBS\CBS.log"){
    try {
        Copy-Item -Path "C:\Windows\Logs\CBS\CBS.log" .\CBS.log -Force -ErrorAction SilentlyContinue
        $cbsLog = get-content -Path .\CBS.log
        Write-Log -Message "CBS.log Exists >> copied to working folder" -LogFilePath $logPath
    
        #display CBS.log
        $cbsLog

        Write-Host "`n For detailed DISM info please see the CBS.log in this folder`n"
    }
    catch {
        GotError -ErrorMessage $_ -Location "Aquiring CBS.log file "
    }
}else {
    Write-Log -Message "CBS.log file not found" -LogFilePath $logPath
    Write-Log -Message "Default CBS,log file location should be %SYSTEMROOT%\Logs\CBS\CBS.log" -LogFilePath $logPath
}

Write-Warning "Checking..."

#checkdisk
Write-Warning "To schedule system check for next boot, please press Y followed by enter key"
chkdsk /F

#scandisk 
Write-Warning "Preforming SFC"
sfc.exe /scannow


#setting Disable Safeguard For Feature Updates Policy to Enabled
Write-Host "NOTE: If this is NOT the first time running the script please set the bellow to Y, otherwise Set it to N" -ForegroundColor Cyan
$runPolicy = Read-Host "Set `"Disable Safeguard For Feature Updates`" (Y|N)"
#
if($($runPolicy.ToUpper()) -eq "Y") {
        #
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWUfBSafeguards" -Type "DWord" -Value 1
        #
} else {
    Write-Warning "`"Disable Safeguard For Feature Updates`" will not be enabled"
}



# Restart computer
$msg =@"
******************************************************************************************************************
*        When the device restarts a scan will take place to check for currupt files and fix them.                *
*        Do not press any key to cancel this action. Once finished the  device will start normally               *
******************************************************************************************************************
"@

Write-host $msg -ForegroundColor Yellow

Write-Host "Computer will now restart" -ForegroundColor Green
Write-Log -Message " Script Finished Successfully " -LogFilePath $logPath

Pause
shutdown /r /f /t 0
