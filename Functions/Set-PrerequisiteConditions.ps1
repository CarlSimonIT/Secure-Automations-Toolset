function Set-PrerequisiteConditions {
  [CmdletBinding()]

  ${Launch Set-PrerequisiteConditions Function-START} = [System.DateTime]::Now

  #region | user session awareness |
  Write-Verbose -Message "Determine the type of Windows installation."
  ${Windows Installation Type} = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name 'InstallationType' | Select-Object -ExpandProperty 'InstallationType'
  Write-Verbose -Message "`${Windows Installation Type} = ${Windows Installation Type}"

  if (${Windows Installation Type} -eq 'Server Core') {
    Write-Verbose -Message "Exiting because this instance of Windows is Server Core"
    break
  }

  Write-Verbose -Message "Initialize and set to `$null a variable that will hold the object representing explorer.exe process"
  $_Var_Name = 'explorer.exe Process'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  Write-Verbose -Message "Get Windows RDS Session number for the current interactive logon session."
  $UserTerminalSessionID = Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id) | Select-Object -ExpandProperty 'SessionId'

  Write-Verbose -Message "Save to recently initialized variable the object representing explorer.exe"
  Set-Variable -Name $_Var_Name -Value $(
    Get-CimInstance -ClassName 'Win32_Process' -Filter "Name = 'explorer.exe' and SessionId = '$UserTerminalSessionID'" -Verbose:$false `
    | Sort-Object 'ProcessId' `
    | Select-Object -First 1
  )

  Write-Verbose -Message "Initialize and set to `$null a variable that will hold the UserName of the account that owns the explorer.exe process"
  $_Var_Name = 'explorer.exe Owner'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  Write-Verbose -Message "Save to recently initialized variable the UserName of the account that owns the explorer.exe process"
  Set-Variable -Name $_Var_Name -Value $(
    Invoke-CimMethod -InputObject ${explorer.exe Process} -MethodName 'GetOwner' -Verbose:$false `
    | Select-Object -ExpandProperty 'User'
  )
  #endregion

  #region | bw.exe |
  Write-Verbose -Message "Confirm presence of Bitwarden Password Manager CLI (bw.exe) in the PATH directory with name WindowsApps"
  do {
    Write-Debug -Message "exit loop if bw.exe is present"
    $IsPresent = Test-Path -Path "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps\bw.exe"
    if ($IsPresent) {break}

    Write-Debug -Message "Initialize new variable to stand as a session variable and ensure value is `$null"
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    Write-Debug -Message "Download the Bitwarden Password Manager CLI (bw.exe)"
    while (-not $TempSessionVar) {
      Write-Debug -Message "Invoke-WebRequest fails the 1st attempt time because of no DNS resource record on the DNS server"
      $RedirectedError = $(
        $HT = @{
          Uri             = 'https://vault.bitwarden.com/download/?app=cli&platform=windows'
          SessionVariable = 'TempSessionVar'
          OutFile         = "$env:SystemDrive\Users\${explorer.exe Owner}\Downloads\bw-windows.zip"
          Verbose         = $true
        }
        Invoke-WebRequest @HT
      ) 2>&1
    }

    Write-Debug -Message "extract bw.exe to WindowsApps folder in the profile of the user that owns explorer.exe"
    $HT = @{
      Path        = "$env:SystemDrive\Users\${explorer.exe Owner}\Downloads\bw-windows.zip"
      Destination = "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps"
      Verbose     = $true
    }
    Expand-Archive @HT

    Write-Debug -Message "Remove the downloaded .zip file"
    $Path = "$env:SystemDrive\Users\${explorer.exe Owner}\Downloads\bw-windows.zip"
    if (Test-Path -Path $Path) {
      Remove-Item -Path $Path
    }
  } while ($true)
  Write-Host -Object 'Bitwarden Password Manager CLI (bw.exe) has finished downloading!'
  #endregion

  #region | jq |
  Write-Verbose -Message "Confirm presence of the jq JSON processor. Necessary for writing into the Bitwarden Password Manager via the Bitwarden CLI."
  winget.exe install --id 'jqlang.jq' --location "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps" --source 'winget'
  #endregion

  #region | Automations related to PowerShell Engine Shutdown |
  #region | Code executed when PowerShell detects that a request to close the PowerShell host process has been submitted |
  Write-Verbose -Message "Initialize `${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String} variable."

  $_Var_Name = 'ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null -Scope 'Script'}

  ${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String} = -join $(
    "## Save to variable the status of bw.exe`n"
    "`${Bitwarden CLI Authentication Status} = bw.exe status | ConvertFrom-Json | % 'status'`n"
    "Write-Verbose -Message 'Does This Appear?'"
    "## Lock the Bitwarden Password Manager CLI if `"bw.exe status`" evaluates to 'unlocked'`n"
    "switch (`${Bitwarden CLI Authentication Status}) {`n"
    "  'unauthenticated' {break}`n"
    "  'locked'          {break}`n"
    "  'unlocked'        {bw.exe lock > `$null}`n"
    "  default           {break}`n"
    "}`n"
  )

  ${ScriptBlock to Run at PowerShell Engine Shutdown Event} = [ScriptBlock]::Create(${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String})
  #endregion
  #region | Event Registration |
  ## If the PowerShell Job associated with the Registered Event (i.e., a request to close the PowerShell host process) 
  ## doesn't exist, then register for the Event representing the PowerShell engine shutdown. 
  $IsJobAlreadyPresent = (Get-Job | Select-Object -ExpandProperty 'Command') -replace [System.Char](0xd),'' | ForEach-Object -Process {
    Compare-Object -ReferenceObject $_ -DifferenceObject ${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String}
  }

  if (-not $IsJobAlreadyPresent) {
    $HT = @{
      SourceIdentifier = ([System.Management.Automation.PsEngineEvent]::Exiting)
      Action           = ${ScriptBlock to Run at PowerShell Engine Shutdown Event}
      Verbose          = $true
    }
    Register-EngineEvent @HT > $null
  }

  #endregion
  #endregion

  ${Launch Set-PrerequisiteConditions Function-END} = [System.DateTime]::Now
  $ts = ${Launch Set-PrerequisiteConditions Function-END} - ${Launch Set-PrerequisiteConditions Function-START}

  Write-Verbose -Message "  Prerequisite Check Duration:`t  $($ts.TotalSeconds.ToString('n3')) Seconds"
}