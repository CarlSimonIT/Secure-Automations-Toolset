# Secure Automations Toolset

## Overview
**Secure Automations Toolset** (SAT) incorporates the [Bitwarden Password Manager CLI](https://bitwarden.com/help/cli/) and the [Bitwarden Secrets Manager CLI](https://bitwarden.com/help/secrets-manager-cli/) to provide a highly secure pre-production environment of Hyper-V hosts and Hyper-V VMs running Windows Server. 

## Demonstration
[![Video-Secure Automations Toolset Demonstration](https://img.youtube.com/vi/Qf-CLud4Wqo/0.jpg)](https://www.youtube.com/watch?v=Qf-CLud4Wqo)

## Requirements
In addition to `secure-automations-toolset.psm1`, the PowerShell script module file, other necessary conditions for using SAT are:  
* Internet connectivity. 
* PowerShell 7. 
* A Bitwarden account with a Bitwarden Vault in the Free tier or above. Paying for Bitwarden is not necessary. 
* The ability to log into that instance of Windows with a non-admin account. 
* Credentials of an account holding membership in the local Administrators group. Logging into Windows as admin will not be necessary. 

Optional items: 
* A personal [Microsoft Account](https://account.microsoft.com/account/) (MSA) in the Free tier and configured to be a [passwordless account](https://support.microsoft.com/en-us/windows/go-passwordless-with-your-microsoft-account-585a71d7-2295-4878-aeac-a014984df856). 
* OneDrive desktop application with the MSA signed-in and syncing to the cloud. Do not enable [OneDrive Backup](https://support.microsoft.com/en-us/office/turn-on-onedrive-backup-4e44ceab-bcdf-4d17-9ae0-6f00f6080adb) unless you can confirm that the contents of your Documents, Desktop, and Pictures libraries are below 5GB. [Data loss](https://askleo.com/onedrive-backup-versus-using-onedrive-for-backup-even-though-onedrive-isnt-backup/) can result. 

## Start
### PowerShell 7
Launch Windows PowerShell in an elevated security context. Execute the line below to download & install PowerShell 7. 
```powershell
Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"
```

> [!NOTE]
> Several alternatives for installing [PowerShell 7 on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows) are available. 

Close Windows PowerShell. 

### Bitwarden Account
Visit [vault.bitwarden.com](https://vault.bitwarden.com/#/login) and select **create account**. Sign up for a [free Bitwarden vault](https://bitwarden.com/go/start-free/). Create a Bitwarden Organization with a title to match your lab environment. Accept the free offer for Bitwarden Secrets Manager. 

[![Video-New Bitwarden Account](https://img.youtube.com/vi/i_uSPgdqVO8/0.jpg)](https://www.youtube.com/watch?v=i_uSPgdqVO8)

### Bitwarden Desktop Application
Download and install the [Bitwarden Desktop Application](https://bitwarden.com/download/). Authenticate with the Bitwarden account created above. 

### Bitwarden Organization
Return to the [web interface](https://vault.bitwarden.com/#/login). Define a Collection and a Project with matching names. Spin up a machine account with an access token. Open your Bitwarden Password Manager desktop app and create a new **Item**. Set the attributes of the **Item** according to the pattern below. 

| Key | Value |
| :-- | :-- |
| Name | Access token name |
| Username | Machine account name |
| Password | Access token value |
|  |  |

Provision your machine account with Read/Write access to your Bitwarden Projects. 

[![Video-Configure Bitwarden Organization](https://img.youtube.com/vi/0_bWK1RH2DE/0.jpg)](https://www.youtube.com/watch?v=0_bWK1RH2DE)

### Install Dependencies (Fast Option)
Import the SAT module into a PowerShell 7 session. 
```powershell
Import-Module Secure-Automations-Toolset.psm1
```

Automatically download & install the four dependencies by running this cmdlet. 
```
Unlock-BwCli
```

Supply your Bitwarden account username, password, and time-sensitive one-time password when prompted. 

### Install Dependencies (Slow Option)
<details>
  <summary>Click to Show</summary>


#### Microsoft Visual C++ 2015 - 2022 Redistributable
Bitwarden Secrets Manager CLI requires the `VCRUNTIME140.dll` file which is provided by both the x86 and x64 versions of the Microsoft Visual C++ 2015 - 2022 Redistributable. Verify the presence of either version. 
```powershell
(Get-CimInstance -ClassName 'Win32_Product').Where({($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X64 Minimum Runtime')) -or ($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X86 Minimum Runtime'))})
```

Install if necessary. Both versions are compatible but either version is sufficient. 
```powershell
Set-Location -Path $env:UserProfile\Downloads
# 64-bit version
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "vc_redist.x64.exe"
Start-Process -FilePath "vc_redist.x64.exe" -ArgumentList @("/quiet")
# 32-bit version
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x86.exe" -OutFile "vc_redist.x86.exe"
Start-Process -FilePath "vc_redist.x86.exe" -ArgumentList @("/quiet")
```

#### Bitwarden Password Manager CLI
Download the Bitwarden Password Manager CLI. Expand the zip file. Relocate `bw.exe` to a path directory. 
```powershell
Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" -OutFile "bw-windows.zip"
Expand-Archive -Path "bw-windows.zip"
Move-Item -Path ".\bw-windows\bw.exe" -Destination "$env:LocalAppData\Microsoft\WindowsApps"
```

#### jq
Writing to the Bitwarden Password Manager via the Bitwarden Password Manager CLI requires the jq JSON processor. Download and move to a path directory. 
```powershell
Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" -OutFile "jq-windows-amd64.exe"
Move-Item -Path "jq-windows-amd64.exe" -Destination "$env:LocalAppData\Microsoft\WindowsApps"
```

> [!NOTE]
> Periodically visit the [releases](https://github.com/jqlang/jq/releases) page for the jq JSON processor to confirm the latest version. 

#### Bitwarden Secrets Manager CLI
Download the Bitwarden Secrets Manager CLI. Expand the zip file. Relocate `bws.exe` to a path directory. 
```powershell
Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" -OutFile "bws-windows.zip"
Expand-Archive -Path "bws-windows.zip"
Move-Item -Path ".\bws-windows\bws.exe" -Destination "$env:LocalAppData\Microsoft\WindowsApps"
```

> [!NOTE]
> Periodically visit the [releases](https://github.com/bitwarden/sdk-sm/releases) page for the Bitwarden Secrets Manager CLI to confirm the latest version. 
</details>
