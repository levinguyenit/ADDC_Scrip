Import-Module ActiveDirectory
$UserName = "Username"

$PDC = (Get-ADDomainController -Filter * | Where-Object {$_.OperationMasterRoles -contains "PDCEmulator"})

$UserInfo = Get-ADUser -Identity $UserName

$LockedOutEvents = Get-WinEvent -ComputerName $PDC.HostName -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending

Foreach($Event in $LockedOutEvents)
  {
    If($Event | Where {$_.Properties[2].value -match $UserInfo.SID.Value})
    {

      $Event | Select-Object -Property @(
        @{Label = 'User'; Expression = {$_.Properties[0].Value}}
        @{Label = 'DomainController'; Expression = {$_.MachineName}}
        @{Label = 'EventId'; Expression = {$_.Id}}
        @{Label = 'LockoutTimeStamp'; Expression = {$_.TimeCreated}}
        @{Label = 'Message'; Expression = {$_.Message -split "`r" | Select -First 1}}
        @{Label = 'LockoutSource'; Expression = {$_.Properties[1].Value}}       
      )

    }}
