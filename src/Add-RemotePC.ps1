# Globals
$APIBaseUrl = $env:CASTLE_API_URL
$APIActions = @{
    "Register" = "$APIBaseUrl/remotepc/register"
    "GetStatus" = "$APIBaseUrl/remotepc/status"
    "UpdateStatus" = "$APIBaseUrl/remotepc/update-status"
}

$Models = @{
    "RegisterRemotePC" = [PSCustomObject]@{
        Name = "TestPC"
        OperatingSystem = "Powershell"
        IPAddress = "192.168.1.100"
    }
}

$RunKey = "RunCount"
$RunCounter = Read-AppSetting -Key $RunKey
$ConfigFile = Join-Path $env:APPDATA "CastleOps\settings.ini"

# -- App Config -- #
function Write-AppSettings {
    param (
        [string]$Key,
        [string]$Value
    )

    # Ensure directory exists
    $dir = Split-Path $ConfigFile
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory | Out-Null
    }

    # Load existing settings
    $settings = @{}
    if (Test-Path $ConfigFile) {
        Get-Content $ConfigFile | ForEach-Object {
            if ($_ -match "^(.*?)=(.*)$") {
                $settings[$matches[1]] = $matches[2]
            }
        }
    }

    # Update or add key
    $settings[$Key] = $Value

    # Write back to file
    $settings.GetEnumerator() | ForEach-Object {
        "$($_.Key)=$($_.Value)"
    } | Set-Content $ConfigFile
}

function Read-AppSetting {
    param (
        [string]$Key
    )

    if (Test-Path $ConfigFile) {
        foreach ($line in Get-Content $ConfigFile) {
            if ($line -match "^(.*?)=(.*)$" -and $matches[1] -eq $Key) {
                return $matches[2]
            }
        }
    }

    return $null
}

# -- Winrm -- #
function Set-HttpsCertificate {
    # Verify the certificate exists in the store
    $cert = Get-Childitem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*CastleOps*"} -ErrorAction SilentlyContinue
    if (-not $cert) {
        throw "Certificate with thumbprint $thumbprint not found in Cert:\LocalMachine\My"
    } else {
        "Creating HTPS certificate..."
        $cert = New-SelfSignedCertificate -DnsName "$env:COMPUTERNAME" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(100) -FriendlyName "CastleOps WinRM HTTPS Certificate"
    }
    return $cert
}

function New-WSManListener {
    $cert = Ensure-HttpsCertificate

    $existingListener = Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="http"}

    if($existingListener) {
      return "HTTPS WinRM listener already exists!"
    }

    $listenerParams = @{
        ResourceURI = 'winrm/config/listener'
        SelectorSet = @{
            Transport = "HTTPS"
            Address   = "*"
        }
        ValueSet    = @{
            Hostname              = $env:COMPUTERNAME
            CertificateThumbprint = $cert.Thumbprint
            Enabled               = $true
            Port                  = 5986
        }
    }
    New-WSManInstance @listenerParams

    Get-WSManInstance -SelectorSet.Transport 
}

function Enable-BasicAuthWinRm {
    "Enabling basic auth"
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
}

function Set-FireWallRule {
    $ruleName = "Windows Remote Management (HTTPS-In)"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

    if ($existingRule) {
        Write-Host "Firewall rule '$ruleName' already exists."
    } else {
        Write-Host "Firewall rule '$ruleName' does not exist. Creating it..."
        New-NetFirewallRule -DisplayName $ruleName -Name $ruleName -Profile Any -LocalPort 5986 -Protocol TCP -Action Allow
    }
}

# -- User Management -- #
function New-RemoteUser {
    param(
        [string]$UserName,
        [securestring]$Password
    )
    $userExists = (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)

    if ($userExists) {
        Write-Host "Local user '$UserName' exists."
    } else {
        Write-Host "Local user '$UserName' does not exist."
        New-LocalUser -Name $UserName -Password $Password -Description "User for CastleOps WinRM access"
    }
}

function Add-UserToGroups {
    param(
        [string]$UserName
    )

    $targetGroups = @("Administrators", "Remote Management Users")

    foreach ($group in $targetGroups) {
        $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
        $isMember = $false

        foreach ($member in $members) {
            if ($member.Name -like "*\$UserName") {
                $isMember = $true
                break
            }
        }

        if (-not $isMember) {
            Write-Host "Adding $UserName to $group..."
            Add-LocalGroupMember -Group $group -Member $UserName
        } else {
            Write-Host "$UserName is already a member of $group."
        }
    }
}

# -- Software Dependencies -- #
function Set-Python3 {
    param (
        [string]$InstallerUrl = "https://www.python.org/ftp/python/3.11.6/python-3.11.6-amd64.exe",
        [string]$TempInstallerPath = "$env:TEMP\python-installer.exe"
    )

    if ($RunCounter -lt 1) {
        Write-Host "Ensuring Python 3 is installed..."

        # Download the installer
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $TempInstallerPath

        Write-Host "📦 Installing Python 3 silently..."
        Start-Process -FilePath $TempInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait

        # Clean up
        Remove-Item $TempInstallerPath -Force

        # Verify installation
        $pythonCheck = Get-Command python3 -ErrorAction SilentlyContinue
        if ($pythonCheck) {
            Write-Host "✅ Python 3 installed successfully: $($pythonCheck.Source)"
        } else {
            Write-Host "❌ Installation failed. Please check manually."
        }
    }
}

# -- API Calls -- #
function Register-RemotePC {
    param (
        [object]$Model
    )

    $jsonBody = $Model | ConvertTo-Json -Depth 10
    $response = Invoke-RestMethod -Uri $APIActions.Register -Method Post -Body $jsonBody -ContentType "application/json"
    return $response
}

function Add-RemotePC {
    param (
        [string]$UserName,
        [securestring]$Password
    )

    try {
        Set-HttpsCertificate
        Enable-BasicAuthWinRm
        Set-FireWallRule
        New-RemoteUser -Username $UserName -Password $Password
        Add-UserToGroups -UserName $UserName
        New-WSManListener
        Set-Python3
    } catch {
        Write-Host "An error occurred: $_"
        exit 1
    }

    Register-RemotePC -Model $Models.RegisterRemotePC

    if(!$RunCounter) {
        Write-Host "First run"
        Write-AppSettings -Key $RunKey -Value 1
    } else {
        Write-Host "Run count: $RunCounter"
        Write-AppSettings -Key $RunKey -Value ([int]$RunCounter + 1)
    }
}

Add-RemotePC -UserName $env:CASTLE_PEON_REMOTE_ADMIN_USERNAME -Password $env:CASTLE_PEON_REMOTE_ADMIN_PASSWORD