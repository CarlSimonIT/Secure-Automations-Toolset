function Authenticate-IntoBitwardenPasswordManagerCLI {
  [CmdletBinding()]
  [Alias('Unlock-BwCli')]
  param (
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Regular expression sourced from 'https://www.regular-expressions.info/email.html'"
    )]
    [ValidatePattern(
      '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    )]
    [System.String]
    [Alias('email')]
    $EmailAddressOfBitwardenAccount
  )


  Write-Verbose -Message "Jumping into Set-PrerequisiteConditions from $($PSCmdlet.MyInvocation.InvocationName)"
  Set-PrerequisiteConditions
  Write-Verbose -Message "Returning from Set-PrerequisiteConditions into $($PSCmdlet.MyInvocation.InvocationName)"

  # Capture status of Bitwarden Password Manager CLI. Only values of interest for our purposes are 'locked' and 'unauthenticated'
  $RedirectedErrors = $(
    $time_Begin = Get-Date
    Write-Verbose -Message "Burning through `n`t  `${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'`n`t  with $($PSCmdlet.MyInvocation.InvocationName)`n"
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
    $time_End = Get-Date
  ) 2>&1
  Write-Verbose -Message "Authentication status check duration by $($PSCmdlet.MyInvocation.InvocationName): $(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds"

  Write-Verbose -Message "Auth status of BwCLI is '${Authentication Status of the Bitwarden CLI}'"

  # Authenticate into Bitwarden Password Manager CLI
  switch (${Authentication Status of the Bitwarden CLI}) {
    'unauthenticated' {      
      [System.String[]]$(bw.exe login $EmailAddressOfBitwardenAccount) | ForEach-Object -Process {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          # Write-Verbose -Message "  `$env:BW_SESSION = $env:BW_SESSION"
          $env:BW_SESSION = $Matches['BW_SESSION']
          # Write-Verbose -Message "  `$env:BW_SESSION = $env:BW_SESSION"
        }
      }
      # $AuthStat = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
      # Write-Verbose -Message "Auth status of BwCLI is '$AuthStat'"
      break
    }
    'locked' {
      [System.String[]]$(bw.exe unlock) | ForEach-Object -Process {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          # Write-Verbose -Message "  `$env:BW_SESSION = $env:BW_SESSION"
          $env:BW_SESSION = $Matches['BW_SESSION']
          # Write-Verbose -Message "  `$env:BW_SESSION = $env:BW_SESSION"
        }
      }
      # $AuthStat = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
      # Write-Verbose -Message "Auth status of BwCLI is '$AuthStat'"
      break
    }
    default {
      Write-Verbose -Message "Bitwarden CLI was already unlocked"
      break
    }
  }
}
