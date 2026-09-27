function _CheckBitwardenVaultAuthenticationStatus {
  [CmdletBinding()]
  param (
    [Parameter(
      Mandatory = $false, 
      Position = 0,
      HelpMessage = "Email address of Bitwarden account. TIP: Use the `$PSDefaultParameterValues automatic variable to avoid repetitive input"
    )]
    [Alias('email')]
    [ValidatePattern(
      '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    )]
    [System.String]
    $EmailAddressOfBitwardenAccount
  )

  # Save to variable the authentication status of bw.exe
  $RedirectedErrors = $(
    $time_AuthCheck_Begin = [System.DateTime]::Now
    Write-Verbose -Message "Burning through `n`t  `${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'`n`t  with $($PSCmdlet.MyInvocation.InvocationName)`n"
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
    $time_AuthCheck_End = [System.DateTime]::Now
  ) 2>&1
  Write-Verbose -Message "Authentication status check duration by $($PSCmdlet.MyInvocation.InvocationName): $(($time_AuthCheck_End - $time_AuthCheck_Begin).TotalSeconds.ToString('n3')) Seconds"

  # Authenticate if status is anything aside from 'unlocked'
  if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {
    Authenticate-IntoBitwardenPasswordManagerCLI
  }
}