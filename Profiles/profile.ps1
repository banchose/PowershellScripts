# about_profiles
# $Profile = CurrentUserCurrentHost
# $Profile.CurrentUserAllHosts
# $Profile.allUsersAllHosts
# $Profile.allUsersCurrentHost
#
# AllUsersAllHosts          $PsHome\profile.ps1
# AllUsersCurrentHost       $PsHome\HostId_profile.ps1
# CurrentUserAllHosts       $Home\Documents\WindowsPowerShell\profile.ps1
# CurrentUserCurrentHost    $Home\Documents\WindowsPowerShell\HostId_profile.ps1


$DropHome = "D:\data\MyProgramData\Dropbox"
$HRIDrop = "X:\"
$Yesterday = (Get-Date) - (New-TimeSpan -Day 1)




Function ff ([String]$glob) { Get-ChildItem -filter "$glob" -Recurse -Force }


Function getdroproot {
    if (test-path $DropHome) {
        return $DropHome
    }
    else {
       if (test-path $HRIDrop) {
            return $HRIDrop
        }
    }
    else {
        Write-Host "No Dropbox path found"
    }
}

# Function npp { notepad $PSCommandPath}

function nppp {
    
    $LocalProfilePath = "C:\Users\Home\Documents\WindowsPowerShell\profile.ps1"
    $DropboxProfilePath = "D:\data\MyProgramData\Dropbox\Share-HIN\Scripts\Powershell\Profiles\Profile.ps1"
    notepad "$DropboxProfilePath"
    copy  -path $DropboxProfilePath -destination $LocalProfilePath -Confirm

}


function hrinppp {
    
    $DropboxProfilePath = "X:\Dropbox\Share-HIN\Scripts\Powershell\Profiles\Profile.ps1"
    $LocalProfilePath = "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1"
    notepad "$DropboxProfilePath"
    copy  -path $DropboxProfilePath -destination $LocalProfilePath -Confirm
    
}


Function lsl([String]$directory = ".") { get-ChildItem $directory -Force | Sort-Object -Property Length }
Function lsx { get-ChildItem -Force }
Function lst { get-ChildItem -Force | Sort-Object LastWriteTime }
Function which($cmd) { (Get-Command $cmd).Definition }

function sudo 
{
    $file, [string]$arguments = $args;
    $psi = new-object System.Diagnostics.ProcessStartInfo $file;
    $psi.Arguments = $arguments;
    $psi.Verb = "runas";
    $psi.WorkingDirectory = get-location;
    [System.Diagnostics.Process]::Start($psi);
}


Function hometrace {


#  ASA Config to allow ICMP through
#  class class-default
#      user-statistics accounting
#      inspect icmp 
#
#
#

$IpTraceAddresses = [ordered]@{

    AsusHubInside = "192.168.1.1"
    AsusHubOutside = "192.168.2.2"
    ASA5506Inside = "192.168.2.1"
    ASA5506Outside = "192.168.0.3"
    TWCableModemInside = "192.168.0.1"
    GoogleDNSInternet1 = "8.8.4.4"
    GoogleDNSInternet2 = "8.8.8.8"
    OpenDNSInternet1 = "208.67.222.222"
    OpenDNSInternet2 = "208.67.220.220"
    ns1TelstraNet = "139.130.4.5"


}


# if (Test-Connection -Count 2 $AsusHubInside -Quiet) { Write-Host "Found ASUS Hub Inside: $AsusHubInside" -ForegroundColor Green}
# if (Test-Connection -Count 2 $AsusHubOutside -Quiet) { Write-Host "Found ASUS Hub Outside: $AsusHubOutside" -ForegroundColor Green}
# if (Test-Connection -Count 2 $ASA5506Inside -Quiet) { Write-Host "Found $ASA5506Inside" -ForegroundColor Green}
# # if (Test-Connection -Count 2 $ASA5506Outside -Quiet) { Write-Host "Found $ASA5506Outside" -ForegroundColor Green}
# if (Test-Connection -Count 5 $GoogleDNSInternet -Quiet) { Write-Host "Found $GoogleDNSInternet" -ForegroundColor Green}
# if (Test-Connection -Count 5 $GoogleDNSInternet2 -Quiet) { Write-Host "Found $GoogleDNSInternet2" -ForegroundColor Green}

foreach ($h IN $IpTraceAddresses.GetEnumerator()) {
    # Write-Host "$($h.Name): $($h.Value)" 
    if (Test-Connection -count 2 -ComputerName $($h.Value) -Quiet) {
        Write-Host "ICMP Echo Reply From: $($h.key) at $($h.Value)" -ForegroundColor Green
        }
    Else {
        Write-Host "Failed Reply From: $($h.key) at $($h.Value)" -ForegroundColor Red
        }
    }
            

Write-Host "Checking ASUS RT-AC68R and ubee"

Test-NetConnection -CommonTCPPort http $IpTraceAddresses.AsusHubInside
Test-NetConnection -CommonTCPPort http $IpTraceAddresses.TWCableModemInside
}


Function cdh {
    cd $env:userprofile
}



Function cdscripts {
    $PowershellSandbox = "X:\Dropbox\Share-HIN\Scripts\Powershell\hri"
	if (Test-Path $PowershellSandbox) {
		cd $PowershellSandbox
	}
	Else {
		Write-Host "The path for `$PowershellSandbox: $PowershellSandbox does not exist" -Foreground Yellow
	}
}

Function cdsand {
	$PowershellSandbox = "X:\Dropbox\Share-HIN\Sandbox"
	if (Test-Path $PowershellSandbox) {
		cd $PowershellSandbox
	}
	Else {
		Write-Host "The path for `$PowershellSandbox: $PowershellSandbox does not exist" -Foreground Yellow
	}
}

Function cddb {
    $DropRoot = "X:\Dropbox\Share-HIN"
    if ($env:computername -Like "HRI185128") {
        if (test-path "$DropRoot"){
            cd $DropRoot
        }
    }
}

Function prompt { 'PS [' + $(Get-Date) + '] ' + $(Get-Location) + '>' }



Function LoggedOnUser([string]$computer){
    (Get-WmiObject -class win32_computersystem -computername $computer).username -replace "HRIALB`\\",""
}

Function hritrace {
#  ASA Config to allow ICMP through
#  class class-default
#      user-statistics accounting
#      inspect icmp 
#
#
#

$IpTraceAddresses = [ordered]@{

    riverhri    = "150.142.185.62"
    tunnel1     = "150.142.10.1"
    dohdiva     = "150.142.1.57"
    unknown     = "10.50.124.62"
    health1dc1  = "150.142.96.30"
    health1dc2  = "150.142.48.120"
    dnsvip      = "150.142.12.4"
    tunnel1rpmi = "150.142.10.114"
    hrmips      = "150.142.104.14"
    rpmi        = "150.142.104.62"
    hribdc1     = "150.142.104.225"
    hribdc2     = "150.142.104.226"


}

get-date

foreach ($h IN $IpTraceAddresses.GetEnumerator()) {
    # Write-Host "$($h.Name): $($h.Value)" 
    if (Test-Connection -count 2 -ComputerName $($h.Value) -Quiet) {
        Write-Host "ICMP Echo Reply From: $($h.key) at $($h.Value)" -ForegroundColor Green
        }
    Else {
        Write-Host "Failed Reply From: $($h.key) at $($h.Value)" -ForegroundColor Red
        }
    }
            

# Write-Host "Checking Services"

# Test-NetConnection -CommonTCPPort http $IpTraceAddresses.riverhri
# Test-NetConnection -CommonTCPPort http $IpTraceAddresses.rpmi

}

Function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}


Function GetProfiles {
    ($profile | Get-Member -MemberType NoteProperty).Name | 
    ForEach-Object { 
        $path = $profile.$_
        New-Object PSObject -Property ([Ordered]@{Path=$Path; Exists=(Test-Path $Path) }) 
    }
}


Function ShowHostsFile
{
    $Path = "$env:windir\system32\drivers\etc\hosts"
    Start-Process -FilePath notepad -ArgumentList $Path -Verb runas
}


Function GetSysInternals  {
    $UtilityZipFile = "SysinternalsSuite.zip"
    $Source = "https://download.sysinternals.com/files/$UtilityZipFile"
    $Destination = "$env:temp\$UtilityZipFile"
    Invoke-WebRequest -uri $Source -OutFile $Destination -ea stop
    Unblock-File $Destination -ea stop
    Expand-Archive -Path $Destination -DestinationPath C:\Utils -force
}

Function syncbuff {
    $robocopy = "C:\Windows\system32\robocopy.exe"
    $roboparams = @("/maxage:30", "/copy:DAT", "/tee", "/w:2", "/r:2", "/s", "/Purge")
    $RoboSource = "\\hribdc2\d_ro"
    $RoboDest = "D:\RPCI-Backup"
    $RoboXD = @("`$RECYCLE.BIN", "System Volume Information", "APPS")
    if (-not (test-path "Y:\Data1")) {
        $cred = Get-Credential
        try {
            new-psdrive -Name "Y" -PSProvider FileSystem -root "\\hribdc2\d_ro" -Credential $cred -ea stop -Persist
        }
        Catch {
            Write-Host "Could not map Buffalo Y:"
            Return
        }
    }
    & $robocopy $RoboSource $RoboDest $roboparams /XD $RoboXD  
    # get-childitem -path "y:" 
}

Function ARPPing ($Computer) {
#----------------------------------------------------------------
# Require nping
#----------------------------------------------------------------
$nping = "C:\Program Files (x86)\nmap\nping.exe"
if (-not (Test-Path $nping)) {Write-Host "Exiting... Can not find $nping" -Foregroundcolor yellow; Return $False}
#---------------------------------------------------------------
 if (-not ([System.Net.IPAddress]::TryParse($Computer,[ref]$null))) {
     Try {
         Write-Host "This was a host name and not IP Address"
         $DNSobj = Resolve-DnsName -Name $Computer -ea stop
         $ComputerIPAddress =  $DNSobj | select -expand IPAddress
     }
     Catch {
         Write-Host "Could not resolve $Computer" -Foregroundcolor yellow
         Return $False
     }
 }
Else {
    $ComputerIPAddress = $Computer
}

  #  $nping = "C:\Program Files (x86)\Nmap\nping.exe"
 $npingResult = &$nping -c 2 --arp $Computer
 if ($npingResult | Sls "ARP reply $ComputerIPAddress") {
     $True
 }
 Else {
     $False
 }
}

function Say-Something
{
      param
        (
            [Parameter(Mandatory=$true)]
                $Text
                  )
         
           $speaker = New-Object -ComObject Sapi.SpVoice
             $null    = $speaker.Speak($Text)
}





function getsymfile {
    if (test-path "\\vserv2\c$\Program Files (x86)\Symantec\Symantec Endpoint Protection Manager\data\inbox\log\ersecreg.log") {
      copy "\\vserv2\c$\Program Files (x86)\Symantec\Symantec Endpoint Protection Manager\data\inbox\log\ersecreg.log" "c:\temp" 
      copy "\\vserv2\c$\Program Files (x86)\Symantec\Symantec Endpoint Protection Manager\data\inbox\log\ersecreg-1.log" "c:\temp"
    }
    Else {
        Write-Host "Cannot get vserv2"
    }
}
