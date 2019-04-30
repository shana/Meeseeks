# Description: Malware Analysis Victim VM
# Author: Bhavna Soman <bhavna.soman@gmail.com>
# Last Updated: 2018-08-20
#
# To install everything, run:
#   Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/shana/Meeseeks/master/Carrie-x64.ps1'))
#
 
Set-ExecutionPolicy RemoteSigned -scope CurrentUser

if ((Get-Command "choco" -ErrorAction SilentlyContinue) -eq $null) {
    write-output "Installing Chocolatey"
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) 
}

#--- System frameworks ---
write-output "Installing essential system frameworks"
choco install -y dotnet4.6.1 mingw 

if ($PSVersionTable.PSVersion -lt "3.0") {
    choco install -y powershell4
}

write-output "Installing scoop"
iex (new-object net.webclient).downloadstring('https://get.scoop.sh')

#--- Essential tools
write-output "Installing essential tooling"
choco install -y winscp winrar 7zip netcat

#--- Git ---
write-output "Installing git"
choco install -y git
$env:path+='C:\Program Files\Git\cmd'
refreshenv

#--- Apps ---
write-output "Installing browsers and editors"
choco install -y googlechrome notepadplusplus sublimetext3 

#---- RE Tools ---
write-output "Installing the RE tools"

choco install -y regshot --allow-empty-checksums
choco install -y windbg

choco install -y sysinternals 
$TargetFile = "C:\ProgramData\chocolatey\lib\sysinternals\tools\"
$ShortcutFile = "$env:Public\Desktop\Sysinternals.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

$TargetFile = "C:\ProgramData\chocolatey\lib\sysinternals\tools\Procmon.exe"
$ShortcutFile = "$env:Public\Desktop\Procmon.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

$TargetFile = "C:\ProgramData\chocolatey\lib\sysinternals\tools\procexp.exe"
$ShortcutFile = "$env:Public\Desktop\Procexp.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y dependencywalker 
$TargetFile = "C:\ProgramData\chocolatey\lib\dependencywalker\content\depends.exe"
$ShortcutFile = "$env:Public\Desktop\DependencyWalker.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y wireshark 
$TargetFile = "C:\Program Files\Wireshark\Wireshark.exe"
$ShortcutFile = "$env:Public\Desktop\Wireshark.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y hxd 
$TargetFile = "C:\Program Files\HxD\HxD.exe"
$ShortcutFile = "$env:Public\Desktop\HxD.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y javadecompiler-gui 
$TargetFile = "C:\ProgramData\chocolatey\lib\javadecompiler-gui\tools\jd-gui-windows-1.4.0\jd-gui.exe" 
$ShortcutFile = "$env:Public\Desktop\Javadecompiler-Gui.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y upx 
$TargetFile = "C:\ProgramData\chocolatey\lib\upx\tools\upx394w\upx.exe"
$ShortcutFile = "$env:Public\Desktop\Upx.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y processhacker  

choco install -y explorersuite 
$TargetFile = "C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe"
$ShortcutFile = "$env:Public\Desktop\Cff Explorer.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y ilspy 
$TargetFile = "C:\ProgramData\chocolatey\lib\ilspy\tools\ILSpy.exe"
$ShortcutFile = "$env:Public\Desktop\ILSpy.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y ida-free
$TargetFile = "C:\Program Files\IDA Freeware 7.0\ida.exe"
$ShortcutFile = "$env:Public\Desktop\Ida Freeware.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y git
$env:path+='C:\Program Files\Git\cmd'
refreshenv

git clone https://github.com/shana/Meeseeks.git

choco install -y Pestudio-Latest -s .\Meeseeks\Packages\
$TargetFile = "C:\ProgramData\chocolatey\lib\pestudio-latest\tools\pestudio\pestudio.exe"
$ShortcutFile = "$env:Public\Desktop\Pestudio.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y FileAlyzer -s .\Meeseeks\Packages\
$TargetFile = "C:\Program Files\Safer Networking\FileAlyzer 2\FileAlyzer2.exe"
$ShortcutFile = "$env:Public\Desktop\FileAlyzer.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

# $url_ByteHist = "https://cert.at/static/downloads/software/bytehist/bytehist_1_0_102_windows.zip"
# $output_ByteHistArchive = "$env:Public\Documents\bytehist_1_0_102_windows.zip"
# $output_ByteHist = "$env:Public\Documents\ByteHist\"
# (New-Object System.Net.WebClient).DownloadFile($url_ByteHist, $output_ByteHistArchive)

$source = ".\Meeseeks\Packages\Scylla\Scylla v0.9.7c"
$destination = "$env:Public\Documents\"
copy-item $source $destination -Recurse -Force
$TargetFile = "$env:Public\Documents\Scylla v0.9.7c\Scylla_x86.exe"
$ShortcutFile = "$env:Public\Desktop\Scylla.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

$source = ".\Meeseeks\Packages\bytehist_1_0_102_windows\win32"
$destination = "$env:Public\Documents\ByteHist"
copy-item $source $destination -Recurse -Force
$TargetFile = "$env:Public\Documents\ByteHist\bytehist.exe"
$ShortcutFile = "$env:Public\Desktop\ByteHist.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

choco install -y ollydbg 
$TargetFile = "C:\Program Files (x86)\OllyDbg\OLLYDBG.EXE"
$ShortcutFile = "$env:Public\Desktop\OllyDbg.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

$url_OllyDump = "http://www.openrce.org/downloads/download_file/108"
$output_OllyDumpArchive = "$env:Public\Documents\OllyDump.zip"
$output_OllyDump = "C:\Program Files (x86)\OllyDbg\"
(New-Object System.Net.WebClient).DownloadFile($url_OllyDump, $output_OllyDumpArchive)
$shell_1 = new-object -com shell.application
$zip_1 = $shell_1.NameSpace($output_OllyDumpArchive)
foreach($item_1 in $zip_1.items())
{
        $shell_1.Namespace($output_OllyDump).copyhere($item_1)
}

$url_RDG = "http://rdgsoft.net/downloads/RDG.Packer.Detector.v0.7.6.2017.zip"
$output_RDGArchive = "$env:Public\Documents\RDGPackerDetector.zip"
$output_RDG = "$env:Public\Documents\"
(New-Object System.Net.WebClient).DownloadFile($url_RDG, $output_RDGArchive)

$shell_2 = new-object -com shell.application
$zip_2 = $shell_2.NameSpace($output_RDGArchive)
foreach($item_2 in $zip_2.items())
{
        $shell_2.Namespace($output_RDG).copyhere($item_2)
}
$TargetFile_2 = "$env:Public\Documents\RDG Packer Detector v0.7.6.2017\RDG Packer Detector v0.7.6.exe"
$ShortcutFile_2 = "$env:Public\Desktop\RDGPackerDetector.lnk"
$WScriptShell_2 = New-Object -ComObject WScript.Shell
$Shortcut_2 = $WScriptShell_2.CreateShortcut($ShortcutFile_2)
$Shortcut_2.TargetPath = $TargetFile_2
$Shortcut_2.Save()

# $shell_3 = new-object -com shell.application
# $zip_3 = $shell_3.NameSpace($output_ByteHistArchive)
# foreach($item_3 in $zip_3.items())
# {
#         $shell_3.Namespace($output_ByteHist).copyhere($item_3)
# }
# $TargetFile_3 = "$env:Public\Documents\ByteHist\win32\bytehist.exe"
# $ShortcutFile_3 = "$env:Public\Desktop\ByteHist.lnk"
# $WScriptShell_3 = New-Object -ComObject WScript.Shell
# $Shortcut_3 = $WScriptShell_3.CreateShortcut($ShortcutFile_3)
# $Shortcut_3.TargetPath = $TargetFile_3
# $Shortcut_3.Save()

if ((Get-Command "scoop" -ErrorAction SilentlyContinue) -eq $null) {
    write-output "Installing scoop"
    iex (new-object net.webclient).downloadstring('https://get.scoop.sh')
}
