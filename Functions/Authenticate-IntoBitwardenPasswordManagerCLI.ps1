function Authenticate-IntoBitwardenPasswordManagerCLI {
  [CmdletBinding()]

  [Alias(
    'Unlock-BwCli'
  )]

  param (
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Regular expression sourced from 'https://www.regular-expressions.info/email.html'"
    )]
    [ValidatePattern(
      '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    )]
    [System.String]
    [Alias(
      'email'
    )]
    $EmailAddressOfBitwardenAccount
  )


  Write-Verbose -Message "Jumping into Set-PrerequisiteConditions from $($PSCmdlet.MyInvocation.InvocationName)"
  Set-PrerequisiteConditions
  Write-Verbose -Message "Returning from Set-PrerequisiteConditions into $($PSCmdlet.MyInvocation.InvocationName)"

  Write-Verbose -Message "Capture status of Bitwarden Password Manager CLI. Only values of interest for our purposes are 'locked' and 'unauthenticated'"
  $RedirectedErrors = $(
    $time_Begin = Get-Date
    Write-Verbose -Message "Proceeding through `n  `${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'`n`t  with $($PSCmdlet.MyInvocation.InvocationName)`n"
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
    $time_End = Get-Date
  ) 2>&1
  Write-Verbose -Message "Authentication status check duration by $($PSCmdlet.MyInvocation.InvocationName): $(($time_End - $time_Begin).TotalSeconds.ToString('n3')) Seconds"

  Write-Verbose -Message "Authentication status of Bitwarden CLI is '${Authentication Status of the Bitwarden CLI}'"

  <#
    Bitwarden CLI Two-step Login Methods: 'https://bitwarden.com/help/cli/#enums'
      bw.exe login --help

      $EmailAddressOfBitwardenAccount = 'pwdsec3@gmail.com'
      # Get-Content -Path "$env:OneDrive\Desktop\Bitwarden Password.txt" | Set-Clipboard

      $PSModuleInfo = Import-Module 'TUN.CredentialManager' -PassThru -Force

      # Title of Bitwarden Account password
      ${Bitwarden Account Password Title} = "!Bitwarden Account Password-DELETE THIS"

      # Verify whether the Bitwarden Account password is already present in the local Windows Credential Manager
      $EncryptedObject = Get-StoredCredential -Target ${Bitwarden Account Password Title}
      $EncryptedPassword = $EncryptedObject.Password
      $UnencryptedObject = Get-StoredCredential -Target ${Bitwarden Account Password Title} -AsCredentialObject
      $UnencryptedPassword = Get-StoredCredential -Target ${Bitwarden Account Password Title} -AsCredentialObject | Select-Object -ExpandProperty 'Password'

      [System.Environment]::SetEnvironmentVariable('NoSync',"$env:UserProfile\NoSync")
      $NoSync = [System.IO.DirectoryInfo]"$env:SystemDrive\Users\${explorer.exe Owner}\NoSync"

      [System.Environment]::SetEnvironmentVariable($(
        ${Bitwarden Account Password Title}
      ),$(
        $UnencryptedPassword
      ))
      # ${env:!Bitwarden Account Password-DELETE THIS}

      # --passwordenv <passwordenv>    Environment variable storing your password
      
      bw.exe login --passwordenv '!Bitwarden Account Password-DELETE THIS' $EmailAddressOfBitwardenAccount 
    $($EncryptedPassword)
  #>
  switch (${Authentication Status of the Bitwarden CLI}) {
    'unauthenticated' {
      Write-Verbose -Message 'Attempting to authenticate into Bitwarden Password Manager CLI.'
      [System.String[]]$(
        bw.exe login $EmailAddressOfBitwardenAccount
      ) | ForEach-Object -Process {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
        }
      }
      break
    }
    'locked' {
      Write-Verbose -Message 'Attempting to unlock an authenticated Bitwarden Password Manager CLI session...'
      [System.String[]]$(bw.exe unlock) | ForEach-Object -Process {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
        }
      }
      break
    }
    default {
      Write-Verbose -Message "Bitwarden CLI was already unlocked"
      break
    }
  }
}

