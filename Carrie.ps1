# Description: Malware Analysis Victim VM
# Author: Bhavna Soman <bhavna.soman@gmail.com>
# Last Updated: 2018-08-20
#
# To install everything, run:
#   iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/shana/Meeseeks/master/Carrie.ps1'))
#
Add-Type -TypeDefinition @"
public class ScriptException : System.Exception
{
    public int ExitCode { get; private set; }
    public ScriptException(string message, int exitCode) : base(message)
    {
        this.ExitCode = exitCode;
    }
}
"@

New-Module -ScriptBlock {
    function Add-Shortcut([string]$TargetFile, [string]$ShortcutFile) {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
        $Shortcut.TargetPath = $TargetFile
        $Shortcut.Save()
    }

    function Run-Command([scriptblock]$Command, [switch]$Fatal, [switch]$Quiet) {
        $output = ""

        $exitCode = 0

        if ($Quiet) {
            $output = & $command 2>&1 | %{ "$_" }
        } else {
            & $command
        }

        if (!$? -and $LastExitCode -ne 0) {
            $exitCode = $LastExitCode
        } elseif ($? -and $LastExitCode -ne 0) {
            $exitCode = $LastExitCode
        }

        if ($exitCode -ne 0) {
            if (!$Fatal) {
                Write-Host "``$Command`` failed" $output
            } else {
                Die $exitCode "``$Command`` failed" $output
            }
        }
        $output
    }

    function Die([int]$exitCode, [string]$message, [object[]]$output) {
        #$host.SetShouldExit($exitCode)
        if ($output) {
            Write-Host $output
            $message += ". See output above."
        }
        $hash = @{
            Message = $message
            ExitCode = $exitCode
            Output = $output
        }
        Throw (New-Object -TypeName ScriptException -ArgumentList $message,$exitCode)
        #throw $message
    }

    function Is-Directory([String] $path) {
        return (Test-Path $path) -and (Get-Item $path) -is [System.IO.DirectoryInfo]
    }

    function Download-Unzip([string]$url, [string]$zip, [string]$targetDir) {
        (New-Object System.Net.WebClient).DownloadFile($url, $zip)
        $shell_1 = new-object -com shell.application
        $zip_1 = $shell_1.NameSpace($zip)
        foreach($item_1 in $zip_1.items())
        {
            $shell_1.Namespace($targetDir).copyhere($item_1)
        }
    }

    Export-ModuleMember -Function Add-Shortcut,Run-Command,Die,Is-Directory,Download-Unzip
}

set-location $env:USERPROFILE
$Is64Bit=[System.Environment]::Is64BitOperatingSystem

if((Get-ExecutionPolicy) -gt 'RemoteSigned' -or (Get-ExecutionPolicy) -eq 'ByPass') {
    Set-ExecutionPolicy RemoteSigned -scope CurrentUser
}

if ((Get-Command "choco" -ErrorAction SilentlyContinue) -eq $null) {
    write-output "Installing Chocolatey"
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) 
}
 
#--- System frameworks ---
write-output "Installing essential system frameworks"
choco install -y dotnet4.6.1

if ($PSVersionTable.PSVersion -lt "3.0") {
    choco install -y powershell4
}

#--- Essential tools
write-output "Installing essential tooling"
choco install -y winscp winrar 7zip netcat mingw

#--- Git ---
write-output "Installing git"
choco install -y git
$env:path+='C:\Program Files\Git\cmd'
refreshenv

$SkipClone = Is-Directory "Meeseeks"
if (!$SkipClone) {
    Run-Command -Fatal { & "C:\Program Files\Git\cmd\git.exe" clone https://github.com/shana/Meeseeks.git }
}

#--- Apps ---
write-output "Installing browsers and editors"
choco install -y googlechrome notepadplusplus sublimetext3 

#---- RE Tools ---
write-output "Installing the RE tools"

choco install -y regshot --allow-empty-checksums
choco install -y windbg

choco install -y sysinternals
Add-Shortcut "C:\ProgramData\chocolatey\lib\sysinternals\tools\" "$env:Public\Desktop\Sysinternals.lnk"
Add-Shortcut "C:\ProgramData\chocolatey\lib\sysinternals\tools\Procmon.exe" "$env:Public\Desktop\Procmon.lnk"
Add-Shortcut "C:\ProgramData\chocolatey\lib\sysinternals\tools\procexp.exe" "$env:Public\Desktop\Procexp.lnk"

choco install -y dependencywalker 
Add-Shortcut "C:\ProgramData\chocolatey\lib\dependencywalker\content\depends.exe" "$env:Public\Desktop\DependencyWalker.lnk"

choco install -y wireshark 
Add-Shortcut "C:\Program Files\Wireshark\Wireshark.exe" "$env:Public\Desktop\Wireshark.lnk"

choco install -y hxd 
Add-Shortcut "C:\Program Files\HxD\HxD.exe" "$env:Public\Desktop\HxD.lnk"

choco install -y javadecompiler-gui
Add-Shortcut "C:\ProgramData\chocolatey\lib\javadecompiler-gui\tools\jd-gui-windows-1.4.0\jd-gui.exe" "$env:Public\Desktop\Javadecompiler-Gui.lnk"

choco install -y upx 
Add-Shortcut "C:\ProgramData\chocolatey\lib\upx\tools\upx394w\upx.exe" "$env:Public\Desktop\Upx.lnk"

choco install -y processhacker

choco install -y explorersuite 
Add-Shortcut "C:\Program Files\NTCore\Explorer Suite\CFF Explorer.exe" "$env:Public\Desktop\Cff Explorer.lnk"

choco install -y ilspy 
Add-Shortcut "C:\ProgramData\chocolatey\lib\ilspy\tools\ILSpy.exe" "$env:Public\Desktop\ILSpy.lnk"

if ($Is64Bit) {
    choco install -y ida-free
    $TargetFile = "C:\Program Files\IDA Freeware 7.0\ida.exe"
} else {
    write-output "...in a tragic twist of events, IDA Free can no longer be installed on a 32 bit OS."
    write-output "and the only free images of windows that I have found are 32 bit"
    write-output "...so here's a hack job"
        # ─────────▄▄───────────────────▄▄──
        # ──────────▀█───────────────────▀█─
        # ──────────▄█───────────────────▄█─
        # ──█████████▀───────────█████████▀─
        # ───▄██████▄─────────────▄██████▄──
        # ─▄██▀────▀██▄─────────▄██▀────▀██▄
        # ─██────────██─────────██────────██
        # ─██───██───██─────────██───██───██
        # ─██────────██─────────██────────██
        # ──██▄────▄██───────────██▄────▄██─
        # ───▀██████▀─────────────▀██████▀──
        # ──────────────────────────────────
        # ──────────────────────────────────
        # ──────────────────────────────────
        # ───────────█████████████──────────
        # ──────────────────────────────────
        # ──────────────────────────────────

    choco install -y ida-5.0 -s .\Meeseeks\Packages\
    $TargetFile = "C:\Program Files\IDA Free\idag.exe"
}
Add-Shortcut $TargetFile "$env:Public\Desktop\Ida Free.lnk"

choco install -y Pestudio-Latest -s .\Meeseeks\Packages\
Add-Shortcut "C:\ProgramData\chocolatey\lib\pestudio-latest\tools\pestudio\pestudio.exe" "$env:Public\Desktop\Pestudio.lnk"

choco install -y FileAlyzer -s .\Meeseeks\Packages\
Add-Shortcut "C:\Program Files\Safer Networking\FileAlyzer 2\FileAlyzer2.exe" "$env:Public\Desktop\FileAlyzer.lnk"

# $url_ByteHist = "https://cert.at/static/downloads/software/bytehist/bytehist_1_0_102_windows.zip"
# $output_ByteHistArchive = "$env:Public\Documents\bytehist_1_0_102_windows.zip"
# $output_ByteHist = "$env:Public\Documents\ByteHist\"
# (New-Object System.Net.WebClient).DownloadFile($url_ByteHist, $output_ByteHistArchive)

$source = ".\Meeseeks\Packages\Scylla\Scylla v0.9.7c"
$destination = "$env:Public\Documents\"
copy-item $source $destination -Recurse -Force
Add-Shortcut "$env:Public\Documents\Scylla v0.9.7c\Scylla_x86.exe" "$env:Public\Desktop\Scylla.lnk"

$source = ".\Meeseeks\Packages\bytehist_1_0_102_windows\win32"
$destination = "$env:Public\Documents\ByteHist"
copy-item $source $destination -Recurse -Force
Add-Shortcut "$env:Public\Documents\ByteHist\bytehist.exe" "$env:Public\Desktop\ByteHist.lnk"

choco install -y ollydbg 
$OllyDbg = "C:\Program Files\OllyDbg\"
if ($Is64Bit) {
    $OllyDbg = "C:\Program Files (x86)\OllyDbg\"
}
Add-Shortcut "$OllyDbg\OLLYDBG.EXE" "$env:Public\Desktop\OllyDbg.lnk"

Download-Unzip "http://www.openrce.org/downloads/download_file/108" "$env:Public\Documents\OllyDump.zip" $OllyDbg

Download-Unzip "http://rdgsoft.net/downloads/RDG.Packer.Detector.v0.7.6.2017.zip" "$env:Public\Documents\RDGPackerDetector.zip" "$env:Public\Documents\"
Add-Shortcut "$env:Public\Documents\RDG Packer Detector v0.7.6.2017\RDG Packer Detector v0.7.6.exe" "$env:Public\Desktop\RDGPackerDetector.lnk"

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
