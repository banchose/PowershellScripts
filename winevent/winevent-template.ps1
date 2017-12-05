########################################################
#
# This is a template script showing the different ways of using get-winevent
# Primarily throught -FilterHashTable
#
#
#
#
# Get-WinEvent -FilterHashTable @{key='value'...}
#
# Key name|Value data type|Accepts wildcard chars
# LogName <String[]> Yes
# ProviderName <String[]> Yes
# Path <String[]> No
# Keywords <Long[]> No
# ID <Int32[]> No
# Level <Int32[]> No
# StartTime <DateTime> No
# EndTime <DataTime> No
# UserID <SID> No
# Data <String[]> No
# * <String[]> No
#
# Level
# 5: Verbose
# 4: Informational
# 3: Warning
# 2: Error
# 1: Critical
# 0: LogAlways
#
#
#
#
########################################################
# $starttime=[datetime]"11/22/2017 19:30"
# $endtime=[datetime]"11/22/2017 20:00"
$starttime = (Get-Date).addHours(-4)
$endtime= Get-Date

$Yesterday = (Get-Date) - (New-TimeSpan -Day 1)
$LastHour = (Get-Date).AddHours(-1)
$Last2Hours = (Get-Date).AddHours(-2)
$Last2Days = (Get-Date).AddHours(-48)
$Last2Weeks= (Get-DAte) - (New-TimeSpan -Day 14)
########################################################
#
$cred = Get-Credential
#
########################################################

echo $starttime
echo $endtime

$computername="mira"
# Get-WinEvent -ComputerName $ComputerName -Credential $cred -FilterHashtable @{logname="system", "application";StartTime=$Yesterday} -MaxEvents 200
# Get-WinEvent -ComputerName $ComputerName -Credential $cred -FilterHashtable @{logname="system", "application";level=1,2,3;StartTime=$Yesterday} -MaxEvents 200
# Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{logname="system", "application";StartTime=$starttime;EndTime=$endtime}
# Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{logname="system", "application";level=1,2,3;StartTime=$starttime;EndTime=$endtime}
Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{logname="system", "application";StartTime=$starttime;EndTime=$endtime}
# Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ProviderName="EventLog";StartTime=$Last2Weeks;ID='6013'}  # <-- uptime
# Get-WinEvent -ComputerName $ComputerName  -FilterHashTable @{ProviderName="EventLog";StartTime=$Last2Weeks;ID='6009'}  # <-- Boot
# Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ProviderName="Microsoft-Windows-Kernel-General";StartTime=$Last2Weeks;ID='12'} #<-- Another Boot Check
# Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ProviderName="Microsoft-Windows-WER-SystemErrorReporting";StartTime=$Last2Weeks;ID='1001'} | fl * #<-- bugcheck

# MSSQL Sever
# Get-WinEvent -ComputerName $ComputerName -FilterHashTable @{ProviderName='MSSQL$ONESOLUTION';StartTime=$Last2Days} -MaxEvents 100 | fl * #<-- bugcheck
