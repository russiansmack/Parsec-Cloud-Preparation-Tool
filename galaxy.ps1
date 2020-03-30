#Modifies Local Group Policy to enable Shutdown scrips items
function add-gpo-modifications {
    $querygpt = Get-content C:\Windows\System32\GroupPolicy\gpt.ini
    $matchgpt = $querygpt -match '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    if ($matchgpt -contains "*0000F87571E3*" -eq $false) 
    {
        write-output "Adding modifications to GPT.ini"
        $gptstring = get-content C:\Windows\System32\GroupPolicy\gpt.ini
        $gpoversion = $gptstring -match "Version"
        $GPO = $gptstring -match "gPCMachineExtensionNames"
        $add = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
        $replace = "$GPO" + "$add"
        (Get-Content "C:\Windows\System32\GroupPolicy\gpt.ini").Replace("$GPO","$replace") | Set-Content "C:\Windows\System32\GroupPolicy\gpt.ini"
        [int]$i = $gpoversion.trim("Version=") 
        [int]$n = $gpoversion.trim("Version=")
        $n +=2
        (Get-Content C:\Windows\System32\GroupPolicy\gpt.ini) -replace "Version=$i", "Version=$n" | Set-Content C:\Windows\System32\GroupPolicy\gpt.ini
    }
    else
    {
        write-output "Not Required"
    }
}

#Adds Premade Group Policu Item if existing configuration doesn't exist
function addRegItems
{
    if (Test-Path ("C:\Windows\system32\GroupPolicy" + "\gpt.ini")) 
    {
        add-gpo-modifications
    }
    Else
    {
        Move-Item -Path $path\ParsecTemp\PreInstall\gpt.ini -Destination C:\Windows\system32\GroupPolicy -Force | Out-Null
    }
    
    regedit /s $path\ParsecTemp\PreInstall\NetworkRestore.reg
    regedit /s $path\ParsecTemp\PreInstall\ForceCloseShutDown.reg
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

function Test-RegistryValue {
# https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
param (

 [parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Path,

[parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Value
)

try {

Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
 return $true
 }

catch {

return $false

}

}



#set update policy
function set-update-policy {
Write-Output "Disabling Windows Update"
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}
}

#set automatic time and timezone
function set-time {
Write-Output "Setting Time to Automatic"
Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
}

#disable new network window
function disable-network-window {
Write-Output "Disabling New Network Window"
if((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}
}

#Enable Pointer Precision 
function enhance-pointer-precision {
Write-Output "Enabling Enhanced Pointer Precision"
Set-Itemproperty -Path 'HKCU:\Control Panel\Mouse' -Name MouseSpeed -Value 1 | Out-Null
}

#enable Mouse Keys
function enable-mousekeys {
Write-Output "Enabling Mouse Keys"
set-Itemproperty -Path 'HKCU:\Control Panel\Accessibility\MouseKeys' -Name Flags -Value 63 | Out-Null
}

#disable shutdown start menu
function remove-shutdown {
Write-Output "Disabling Shutdown Option in Start Menu"
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoClose -Value 1 | Out-Null
}

#Sets all applications to force close on shutdown
function force-close-apps {
if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) 
{Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
"Removed Startup Item from Razer Synapse"}
Else {New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"}
}

#show hidden items
function show-hidden-items {
Write-Output "Showing Hidden Files in Explorer"
set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1 | Out-Null
}

#show file extensions
function show-file-extensions {
Write-Output "Showing File Extensions"
Set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name HideFileExt -Value 0 | Out-Null
}

#disable logout start menu
function disable-logout {
Write-Output "Disabling Logout"
if((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
}

#disable lock start menu
function disable-lock {
Write-Output "Disable Lock"
if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
if((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}
}

#set wallpaper
function set-wallpaper {
Write-Output "Setting WallPaper"
if((Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "System" | Out-Null}
if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value Wallpaper) -eq $true) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -value "C:\ParsecTemp\parsec+desktop.png" | Out-Null} Else {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -PropertyType String -value "C:\ParsecTemp\parsec+desktop.png" | Out-Null}
if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value WallpaperStyle) -eq $true) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -value 2 | Out-Null} Else {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -PropertyType String -value 2 | Out-Null}
Stop-Process -ProcessName explorer
}

#disable recent start menu items
function disable-recent-start-menu {
New-Item -path HKLM:\SOFTWARE\Policies\Microsoft\Windows -name Explorer
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -PropertyType DWORD -Name HideRecentlyAddedApps -Value 1
}

#enable auto login - remove user password
function autoLogin { 
  Write-Host "This cloud machine needs to be set to automatically login - doing that" -ForegroundColor red 
  (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AutoLogon.zip", "$path\Autologon.zip")
  Expand-Archive "$path\Autologon.zip" -DestinationPath "$path" -Force
  
  #TOFIX: REMOVE THIS HACK FOR PROD
  Write-Host "Running a hack to enable LA Servers us-west-2" -ForegroundColor red
  aws configure set region us-west-2
  
  $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri http://169.254.169.254/latest/api/token
  $instanceId = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/instance-id
  aws s3 cp s3://demo-parsec/herpderp.pem herpderp.pem 
  $winPass = aws ec2 get-password-data --instance-id $instanceId --priv-launch-key herpderp.pem --query PasswordData --output text
  $autoLoginP = Start-Process "$path\Autologon.exe" -ArgumentList "/accepteula", $autoLoginUser, $env:Computername, $winPass -PassThru -Wait
  If ($autoLoginP.ExitCode -eq 0) {
    Write-Host "AutoLogin Enabled" -ForegroundColor green 
  } Else {
    Write-Host "AutoLogin ERROR" -ForegroundColor red 
  }
}

#create shortcut for electron app
function create-shortcut-app {
Write-Output "Moving Parsec app shortcut to Desktop"
Copy-Item -Path $path\ParsecTemp\PostInstall\Parsec.lnk -Destination $path
}

#Disables Server Manager opening on Startup
function disable-server-manager {
Write-Output "Disable Auto Opening Server Manager"
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

#AWS Clean up Desktop Items
function clean-aws {
remove-item -path "$path\EC2 Feedback.Website"
Remove-Item -Path "$path\EC2 Microsoft Windows Guide.website"
}

Function ExtractRazerAudio {
#Move extracts Razer Surround Files into correct location
Write-Host "Moving Razer Surround files to the correct location"
cmd.exe /c '"C:\Program Files\7-Zip\7z.exe" x C:\ParsecTemp\Apps\razer-surround-driver.exe -oC:\ParsecTemp\Apps\razer-surround-driver -y' | Out-Null
}

Function ModidifyManifest {
#modifys the installer manifest to run without interraction
$InstallerManifest = 'C:\ParsecTemp\Apps\razer-surround-driver\$TEMP\RazerSurroundInstaller\InstallerManifest.xml'
$regex = '(?<=<SilentMode>)[^<]*'
(Get-Content $InstallerManifest) -replace $regex, 'true' | Set-Content $InstallerManifest -Encoding UTF8
}

#AWS Specific tweaks
function aws-setup {
#clean-aws
Write-Output "Installing audio driver"
#(New-Object System.Net.WebClient).DownloadFile($(((Invoke-WebRequest -Uri https://www.tightvnc.com/download.php -UseBasicParsing).Links.OuterHTML -like "*Installer for Windows (64-bit)*").split('"')[1].split('"')[0]), "C:\ParsecTemp\Apps\tightvnc.msi")
(New-Object System.Net.WebClient).DownloadFile("http://rzr.to/surround-pc-download", "C:\ParsecTemp\Apps\razer-surround-driver.exe")
#start-process msiexec.exe -ArgumentList '/i C:\ParsecTemp\Apps\TightVNC.msi /quiet /norestart ADDLOCAL=Server SET_USECONTROLAUTHENTICATION=1 VALUE_OF_USECONTROLAUTHENTICATION=1 SET_CONTROLPASSWORD=1 VALUE_OF_CONTROLPASSWORD=4ubg9sde SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=4ubg9sde' -Wait
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value $env:USERNAME | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "" | Out-Null
if((Test-RegistryValue -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value AutoAdminLogin)-eq $true){Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogin -Value 1 | Out-Null} Else {New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogin -Value 1 | Out-Null}
Write-Host "Installing Razer Surround - it's the Audio Driver - you DON'T need to sign into Razer Synapse" -ForegroundColor green
ExtractRazerAudio
ModidifyManifest
$OriginalLocation = Get-Location
Set-Location -Path 'C:\ParsecTemp\Apps\razer-surround-driver\$TEMP\RazerSurroundInstaller\'
Write-Output "The Audio Driver, Razer Surround is now installing"
Start-Process RzUpdateManager.exe
Set-Location $OriginalLocation
Set-Service -Name audiosrv -StartupType Automatic
#Write-Output "VNC has been installed on this computer using Port 5900 and Password 4ubg9sde"
}

#Provider specific driver install and setup
Function provider-specific {
Write-Output "Doing provider specific customizations"
#Device ID Query 
$gputype = get-wmiobject -query "select DeviceID from Win32_PNPEntity Where (deviceid Like '%PCI\\VEN_10DE%') and (PNPClass = 'Display' or Name = '3D Video Controller')" | Select-Object DeviceID -ExpandProperty DeviceID
if ($gputype -eq $null) 
{Write-Output "No GPU Detected, skipping provider specific tasks"}
Else{
if($gputype.substring(13,8) -eq "DEV_13F2") {
#AWS G3.4xLarge M60
Write-Output "Tesla M60 Detected"
autologin
aws-setup
}
ElseIF($gputype.Substring(13,8) -eq "DEV_118A"){#AWS G2.2xLarge K520
autologin
aws-setup
Write-Output "GRID K520 Detected"
}
ElseIF($gputype.Substring(13,8) -eq "DEV_1BB1") {
#Paperspace P4000
Write-Output "Quadro P4000 Detected"
} 
Elseif($gputype.Substring(13,8) -eq "DEV_1BB0") {
#Paperspace P5000
Write-Output "Quadro P5000 Detected"
}
Elseif($gputype.substring(13,8) -eq "DEV_15F8") {
#Tesla P100
Write-Output "Tesla P100 Detected"
if((Test-Path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe") -eq $true) {remove-item -path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe"} Else {}
if((Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk") -eq $true) {Remove-Item -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk"} Else {}
autologin
aws-setup
}
Elseif($gputype.substring(13,8) -eq "DEV_1BB3") {
#Tesla P4
Write-Output "Tesla P4 Detected"
if((Test-Path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe") -eq $true) {remove-item -path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe"} Else {}
if((Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk") -eq $true) {Remove-Item -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk"} Else {}
autologin
aws-setup
}
Elseif($gputype.substring(13,8) -eq "DEV_1EB8") {
#Tesla T4
Write-Output "Tesla T4 Detected"
if((Test-Path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe") -eq $true) {remove-item -path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe"} Else {}
if((Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk") -eq $true) {Remove-Item -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk"} Else {}
autologin
aws-setup
}
Elseif($gputype.substring(13,8) -eq "DEV_1430") {
#Quadro M2000
Write-Output "Quadro M2000 Detected"
autologin
aws-setup
}
Else{write-host "The installed GPU is not currently supported, skipping provider specific tasks"}
}
}

function Install7Zip {
#7Zip is required to extract the Parsec-Windows.exe File
Write-Host "Downloading and Installing 7Zip"
$url = Invoke-WebRequest -Uri https://www.7-zip.org/download.html
(New-Object System.Net.WebClient).DownloadFile("https://www.7-zip.org/$($($($url.Links | Where-Object outertext -Like "Download")[1]).OuterHTML.split('"')[1])" ,"C:\ParsecTemp\Apps\7zip.exe")
Start-Process C:\ParsecTemp\Apps\7zip.exe -ArgumentList '/S /D="C:\Program Files\7-Zip"' -Wait}

Function ExtractInstallFiles {
#Move Parsec Files into correct location
Write-Host "Moving files to the correct location"
cmd.exe /c '"C:\Program Files\7-Zip\7z.exe" x C:\ParsecTemp\Apps\parsec-windows.exe -oC:\ParsecTemp\Apps\Parsec-Windows -y' | Out-Null
if((Test-Path -Path 'C:\Program Files\Parsec')-eq $true) {} Else {New-Item -Path 'C:\Program Files\Parsec' -ItemType Directory | Out-Null}
if((Test-Path -Path "C:\Program Files\Parsec\skel") -eq $true) {} Else {Move-Item -Path C:\ParsecTemp\Apps\Parsec-Windows\skel -Destination 'C:\Program Files\Parsec' | Out-Null} 
if((Test-Path -Path "C:\Program Files\Parsec\vigem") -eq $true) {} Else  {Move-Item -Path C:\ParsecTemp\Apps\Parsec-Windows\vigem -Destination 'C:\Program Files\Parsec' | Out-Null} 
if((Test-Path -Path "C:\Program Files\Parsec\wscripts") -eq $true) {} Else  {Move-Item -Path C:\ParsecTemp\Apps\Parsec-Windows\wscripts -Destination 'C:\Program Files\Parsec' | Out-Null} 
if((Test-Path -Path "C:\Program Files\Parsec\parsecd.exe") -eq $true) {} Else {Move-Item -Path C:\ParsecTemp\Apps\Parsec-Windows\parsecd.exe -Destination 'C:\Program Files\Parsec' | Out-Null} 
if((Test-Path -Path "C:\Program Files\Parsec\pservice.exe") -eq $true) {} Else {Move-Item -Path C:\ParsecTemp\Apps\Parsec-Windows\pservice.exe -Destination 'C:\Program Files\Parsec' | Out-Null} 
Start-Sleep 1
}

#Checks for Server 2019 and asks user to install Windows Xbox Accessories in order to let their controller work
Function Server2019Controller {
if ((gwmi win32_operatingsystem | % caption) -like '*Windows Server 2019*') {
    "Detected Windows Server 2019, downloading Xbox Accessories 1.2 to enable controller support"
    (New-Object System.Net.WebClient).DownloadFile("http://download.microsoft.com/download/6/9/4/69446ACF-E625-4CCF-8F56-58B589934CD3/Xbox360_64Eng.exe", "C:\ParsecTemp\Drivers\Xbox360_64Eng.exe")
    Write-Host "In order to use a controller, you need to install Microsoft Xbox Accessories " -ForegroundColor Red
    Start-Process C:\ParsecTemp\Drivers\Xbox360_64Eng.exe -Wait
    }
}

Function InstallViGEmBus {
#Required for Controller Support.
Write-Host "Installing ViGEmBus - https://github.com/ViGEm/ViGEmBus"
#$Vigem = @{}
#$Vigem.DriverFile = "C:\Program Files\Parsec\Vigem\ViGEmBus.cat";
#$Vigem.CertName = 'C:\Program Files\Parsec\Vigem\Wohlfeil_IT_e_U_.cer';
#$Vigem.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
#$Vigem.Cert = (Get-AuthenticodeSignature -filepath $vigem.DriverFile).SignerCertificate; 
#$Vigem.CertInstalled = if ((Get-ChildItem -Path Cert:\CurrentUser\TrustedPublisher | Where-Object Subject -Like "*CN=Wohlfeil.IT e.U., O=Wohlfeil.IT e.U.*" ) -ne $null) {$True}
#Else {$false}
#if ($vigem.CertInstalled -eq $true) {
cmd.exe /c '"C:\Program Files\Parsec\vigem\10\x64\devcon.exe" install "C:\Program Files\Parsec\vigem\10\ViGEmBus.inf" Nefarius\ViGEmBus\Gen1' | Out-Null
#} 
#Else {[System.IO.File]::WriteAllBytes($Vigem.CertName, $Vigem.Cert.Export($Vigem.ExportType));
#Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath 'C:\Program Files\Parsec\Vigem\Wohlfeil_IT_e_U_.cer' | Out-Null
#Start-Sleep 5
#cmd.exe /c '"C:\Program Files\Parsec\vigem\devcon.exe" install "C:\Program Files\Parsec\vigem\ViGEmBus.inf" Root\ViGEmBus' | Out-Null
#}
}

Function CreateFireWallRule {
#Creates Parsec Firewall Rule in Windows Firewall
Write-host "Creating Parsec Firewall Rule"
New-NetFirewallRule -DisplayName "Parsec" -Direction Inbound -Program "C:\Program Files\Parsec\Parsecd.exe" -Profile Private,Public -Action Allow -Enabled True | Out-Null
}

Function CreateParsecService {
#Creates Parsec Service
Write-host "Creating Parsec Service"
cmd.exe /c 'sc.exe Create "Parsec" binPath= "\"C:\Program Files\Parsec\pservice.exe\"" start= "auto"' | Out-Null
sc.exe Start 'Parsec' | Out-Null
}

Function DownloadParsecServiceManager {
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
(New-Object System.Net.WebClient).DownloadFile("https://github.com/jamesstringerparsec/Parsec-Service-Manager/blob/master/Launcher.exe?raw=true", "$ENV:UserProfile\Desktop\ParsecServiceManager.exe") | Unblock-File
}

Function InstallParsec {
Write-Host "Installing Parsec"
Install7Zip
ExtractInstallFiles
#InstallViGEmBus
CreateFireWallRule
CreateParsecService
DownloadParsecServiceManager
Write-host "Successfully installed Parsec"
}

#Apps that require human intervention
function Install-Gaming-Apps {
InstallParsec
New-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Parsec.App.0" -Value "C:\Program Files\Parsec\parsecd.exe" | Out-Null
Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
Start-Sleep -s 1
Write-Output "app_host=1" | Out-File -FilePath $ENV:AppData\Parsec\config.txt -Encoding ascii
}

#Disable Devices
function disable-devices {
write-output "Disabling devices not required"
Start-Process -FilePath "C:\ParsecTemp\Devcon\devcon.exe" -ArgumentList '/r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"'
Get-PnpDevice| where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
Get-PnpDevice| where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
Start-Process -FilePath "C:\ParsecTemp\Devcon\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1013&DEV_00B8*"'
}

#Cleanup
function clean-up {
Write-Output "Cleaning up!"
Remove-Item -Path C:\ParsecTemp\Drivers -force -Recurse
Remove-Item -Path $path\ParsecTemp -force -Recurse
}

#cleanup recent files
function clean-up-recent {
Write-Output "Removing recent files"
remove-item "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force | Out-Null
}


########################## THE CLEAN VERSION STARTS HERE
########################## THE CLEAN VERSION STARTS HERE
########################## THE CLEAN VERSION STARTS HERE
########################## THE CLEAN VERSION STARTS HERE

#This is to remove autostartup of razer window : MUST ADD
function Remove-Razer-Startup {
    if (((Get-Item -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run).GetValue("Razer Synapse") -ne $null) -eq $true) 
    {Remove-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "Razer Synapse"
    "Removed Startup Item from Razer Synapse"}
    Else {"Razer Startup Item not present"}
    }

#Create ParsecTemp folder in C Drive
function create-directories {
    Write-Output "Creating Directories in $path Drive"
    if((Test-Path -Path $path )-eq $true){} Else {New-Item -Path $path -ItemType directory | Out-Null}
    if((Test-Path -Path $path\Apps) -eq $true) {} Else {New-Item -Path $path\Apps -ItemType directory | Out-Null}
    if((Test-Path -Path $path\DirectX) -eq $true) {} Else {New-Item -Path $path\DirectX -ItemType directory | Out-Null}
    if((Test-Path -Path $path\Drivers) -eq $true) {} Else {New-Item -Path $path\Drivers -ItemType Directory | Out-Null}
    if((Test-Path -Path $path\Devcon) -eq $true) {} Else {New-Item -Path $path\Devcon -ItemType Directory | Out-Null}
}

#download-files-S3
function download-resources {
    Write-Output "Downloading Parsec, DirectX June 2010 Redist, DevCon and Google Chrome."
    Write-Host "Downloading DirectX" -NoNewline
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe", "$path\Apps\directx_Jun2010_redist.exe") 
    Write-host "`r - Success!"
    Write-Host "Downloading Devcon" -NoNewline
    (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/parsec-files-ami-setup/Devcon/devcon.exe", "$path\Devcon\devcon.exe")
    Write-host "`r - Success!"
    Write-Host "Downloading Parsec" -NoNewline
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "$path\Apps\parsec-windows.exe")
    Write-host "`r - Success!"
    Write-Host "Downloading Chrome" -NoNewline
    #(New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/parseccloud/image/parsec+desktop.png", "$path\parsec+desktop.png")
    #(New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/parseccloud/image/white_ico_agc_icon.ico", "$path\white_ico_agc_icon.ico")
    (New-Object System.Net.WebClient).DownloadFile("https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi", "$path\Apps\googlechromestandaloneenterprise64.msi")
    Write-host "`r - Success!"
}

#install-base-files-silently
function install-windows-features {
    Write-Output "Installing .Net 3.5, Direct Play and DirectX Redist 2010"
    Start-Process -filepath "C:\Windows\System32\msiexec.exe" -ArgumentList '/qn /i "C:\ParsecTemp\Apps\googlechromestandaloneenterprise64.msi"' -Wait
    Start-Process -FilePath "$path\Apps\directx_jun2010_redist.exe" -ArgumentList '/T:C:\ParsecTemp\DirectX /Q'-wait
    Start-Process -FilePath "$path\DirectX\DXSETUP.EXE" -ArgumentList '/silent' -wait
    Install-WindowsFeature Direct-Play | Out-Null
    Install-WindowsFeature Net-Framework-Core | Out-Null
    Remove-Item -Path $path\DirectX -force -Recurse 
}

Write-Host -foregroundcolor red "
THIS IS GALAXY.
We are installing all the needed essentials to make this machine stream games
"   

#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)
$path = "C:\ParsecTemp" #Path for installer



#addRegItems
create-directories
download-resources
install-windows-features
set-update-policy 
force-close-apps 
disable-network-window
disable-logout
disable-lock
show-hidden-items
show-file-extensions
enhance-pointer-precision
enable-mousekeys
set-time
set-wallpaper
disable-server-manager
Install-Gaming-Apps
Start-Sleep -s 5
#Server2019Controller
create-shortcut-app
#gpu-update-shortcut
disable-devices
clean-up
clean-up-recent
provider-specific
Write-Host "Open Parsec and sign in (use ParsecServiceManager.exe if connected via RDP)" -ForegroundColor RED
pause
