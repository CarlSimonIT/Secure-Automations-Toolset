function Set-PrerequisiteConditions {
  [CmdletBinding()]

  $PreRequisites_Begin = Get-Date
  #Write-Verbose -Message "  `$env:BW_SESSION = $env:BW_SESSION"

  #region | user session awareness |
  # Get type of Windows installation
  ${Windows Installation Type} = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name 'InstallationType' | Select-Object -ExpandProperty 'InstallationType'

  # Exit if instance of Windows is Server Core
  if (${Windows Installation Type} -eq 'Server Core') {
    break
  }

  # Initialize and set to $null a variable that will hold the object representing explorer.exe process
  $_Var_Name = 'explorer.exe Process'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Get Windows RDS Session number for the current interactive logon session. 
  $UserTerminalSessionID = Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id) | Select-Object -ExpandProperty 'SessionId'

  # Save to recently initialized variable the object representing explorer.exe
  Set-Variable -Name $_Var_Name -Value $(
    Get-CimInstance -ClassName 'Win32_Process' -Filter "Name = 'explorer.exe' and SessionId = '$UserTerminalSessionID'" -Verbose:$false | Sort-Object 'ProcessId' | Select-Object -First 1
  )

  # Initialize and set to $null a variable that will hold the UserName of the account that owns the explorer.exe process
  $_Var_Name = 'explorer.exe Owner'
  try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

  # Save to recently initialized variable the UserName of the account that owns explorer.exe
  Set-Variable -Name $_Var_Name -Value $(
    Invoke-CimMethod -InputObject ${explorer.exe Process} -MethodName 'GetOwner' -Verbose:$false | Select-Object -ExpandProperty 'User'
  )
  #endregion

  #region | bw.exe |
  ## Confirm presence of Bitwarden Password Manager CLI (bw.exe) in the PATH directory with name WindowsApps
  do {
    # exit loop if bw.exe is present
    $IsPresent = Test-Path -Path "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps\bw.exe"
    if ($IsPresent) {break}

    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the Bitwarden Password Manager CLI (bw.exe)
    while (-not $TempSessionVar) {
      # Invoke-WebRequest fails the 1st attempt time because of no DNS resource record on the DNS server
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

    # extract bw.exe to WindowsApps folder in the profile of the user that owns explorer.exe    
    $HT = @{
      Path        = "$env:SystemDrive\Users\${explorer.exe Owner}\Downloads\bw-windows.zip"
      Destination = "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps"
      Verbose     = $true
    }
    Expand-Archive @HT

    # Remove the downloaded .zip file
    $Path = "$env:SystemDrive\Users\${explorer.exe Owner}\Downloads\bw-windows.zip"
    if (Test-Path -Path $Path) {
      Remove-Item -Path $Path
    }
  } while ($true)
  #endregion

  #region | jq |
  ## Confirm presence of the jq JSON processor. Necessary for writing into the Bitwarden Password Manager via the Bitwarden CLI
  do {
    # exit loop if jq-windows-amd64.exe is present
    $IsPresent = Test-Path -Path "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps\jq.exe"
    if ($IsPresent) {break}

    # Initialize new variable to stand as a session variable and ensure value is $null. 
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    # Download the jq JSON processor
    # Latest version as of 2026-09-27 is 1.8.2
    # start msedge.exe 'https://jqlang.org/'
    while (-not $TempSessionVar) {
      # Invoke-WebRequest fails the 1st attempt time because of no DNS resource record on the DNS server
      $RedirectedError = $(
        $HT = @{
          Uri             = 'https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-windows-amd64.exe'
          SessionVariable = 'TempSessionVar'
          #OutFile         = "$env:SystemDrive\Users\${explorer.exe Owner}\Downloads\jq-windows-amd64.exe"
          OutFile         = "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps\jq.exe"
          Verbose         = $true
        }
        Invoke-WebRequest @HT
      ) 2>&1
    }
    <# downloading with winget should also work |
      winget.exe install --help
      winget install jqlang.jq
      winget download --name jq --download-directory "$env:SystemDrive\Users\${explorer.exe Owner}\AppData\Local\Microsoft\WindowsApps"
      renaming the exe is necessary. 
      winget.exe install --name jq --location "$env:LocalAppData\Microsoft\WindowsApps"
      start msedge 'https://jqlang.org/download/'
    #>
    Write-Verbose -Message 'jq.exe JSON processor has finished downloading!'
  } while ($true)
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

  # ${Is Job Already Present} = if ($null -ne $IsJobAlreadyPresent) {$true} else {$false}
  # Write-Verbose -Message "`n`t`t`$IsJobAlreadyPresent = $IsJobAlreadyPresent`n"
  # Write-Verbose -Message "`n`t`t`${Is Job Already Present} = ${Is Job Already Present}`n"
  # Write-Verbose -Message "`n`t`t-not `$IsJobAlreadyPresent = $(-not $IsJobAlreadyPresent)`n"

  if (-not $IsJobAlreadyPresent) {
    #Write-Verbose -Message "  `$env:BW_SESSION = $env:BW_SESSION"
    $HT = @{
      SourceIdentifier = ([System.Management.Automation.PsEngineEvent]::Exiting)
      Action           = ${ScriptBlock to Run at PowerShell Engine Shutdown Event}
      Verbose          = $true
    }
    Register-EngineEvent @HT > $null
    # $EngineEventOutput = Register-EngineEvent @HT | Format-Table -AutoSize | Out-String
    # $EngineEventOutput | ForEach-Object -Process {Write-Verbose -Message "$_"}
  }

  # $IsJobPresentNow = (Get-Job | Select-Object -ExpandProperty 'Command') -replace [System.Char](0xd),'' | ForEach-Object -Process {
  #   Compare-Object -ReferenceObject $_ -DifferenceObject ${ScriptBlock to Run at PowerShell Engine Shutdown Event Here-String}
  # }
  # ${Is Job Present Now} = if ($null -ne $IsJobPresentNow) {$true} else {$false}
  # Write-Verbose -Message "`n`t`t`$IsJobPresentNow = $IsJobPresentNow`n"
  # Write-Verbose -Message "`n`t`t`${Is Job Present Now} = ${Is Job Present Now}`n"

  #endregion
  #endregion

  $PreRequisites_Finish = Get-Date

  Write-Verbose -Message "  Prerequisite Check Duration:`t  $(($PreRequisites_Finish - $PreRequisites_Begin).TotalSeconds.ToString('n3')) Seconds"
}