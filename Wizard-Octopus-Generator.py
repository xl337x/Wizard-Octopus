import re
import os

def generate_powershell_script(tenant_configs):
    """
    Generates the PowerShell script with the provided tenant configurations hardcoded.
    """
    
    # Base PowerShell code structure (common parts)
    powershell_code = r'''
# ----------------------------------------------------------------------------------
# Multi-Tenant-IOC's-Blocker by mahdiesta
# Token Authentication Script for Microsoft Defender API
# ----------------------------------------------------------------------------------

# RED DOUBLE-LINE WELCOME BANNER
$bannerLine = ("=" * 79)
Write-Host $bannerLine -ForegroundColor Red
Write-Host $bannerLine -ForegroundColor Red
Write-Host "=                            Welcome to Wizard Octopus                       =" -ForegroundColor Red
Write-Host "=                    Multi-Tenant-IOC's-Blocker by mahdiesta                 =" -ForegroundColor Red
Write-Host $bannerLine -ForegroundColor Red
Write-Host $bannerLine -ForegroundColor Red
Write-Host "`n"

# ----------------------------------------------------------------------------------
# Tenant Configuration (Hardcoded from Python Script)
# ----------------------------------------------------------------------------------
'''

    if len(tenant_configs) == 1:
        # Single tenant configuration: embed directly
        config = tenant_configs[0]
        powershell_code += f'$tenantId   = "{config["tenantId"]}"\n'
        powershell_code += f'$appId      = "{config["appId"]}"\n'
        powershell_code += f'$appSecret  = "{config["appSecret"]}"\n\n'
        powershell_code += r'''
# ----------------------------------------------------------------------------------
# AUTHENTICATION STAGE
# ----------------------------------------------------------------------------------
Write-Host $bannerLine -ForegroundColor Cyan
Write-Host "=                           AUTHENTICATION STAGE                             =" -ForegroundColor Cyan
Write-Host $bannerLine -ForegroundColor Cyan
Write-Host "`nAuthenticating with Microsoft Defender API..." -ForegroundColor Cyan
Write-Host "Tenant ID: $tenantId" -ForegroundColor White
Write-Host "Application ID: $appId" -ForegroundColor White
Write-Host "`n"

$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri         = "https://login.windows.net/$tenantId/oauth2/token"
$authBody         = @{
    resource      = $resourceAppIdUri
    client_id     = $appId
    client_secret = $appSecret
    grant_type    = 'client_credentials'
}

try {
    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    $token        = $authResponse.access_token

    # Removed: Saving token to a file
    # Removed: Write-Host "Token retrieved and saved securely.`n"

    Write-Host "Authentication successful!" -ForegroundColor Green

} catch {
    Write-Host "`n"
    Write-Host $bannerLine -ForegroundColor DarkRed
    Write-Host "=                           ERROR STAGE                                     =" -ForegroundColor DarkRed
    Write-Host $bannerLine -ForegroundColor DarkRed
    Write-Host "`nAuthentication failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

'''
    else:
        # Multi-tenant configuration: embed all into an array
        powershell_code += '$tenantConfigs = @(\n'
        for config in tenant_configs:
            powershell_code += f'''    @{{
        tenantId = "{config["tenantId"]}"
        appId = "{config["appId"]}"
        appSecret = "{config["appSecret"]}"
    }},\n'''
        powershell_code += ')\n\n'
        powershell_code += r'''
# ----------------------------------------------------------------------------------
# AUTHENTICATION STAGE (Multi-Tenant)
# ----------------------------------------------------------------------------------
$tenantTokens = @{} # Dictionary to store tokens for each tenant

foreach ($config in $tenantConfigs) {
    $currentTenantId = $config.tenantId
    $currentAppId = $config.appId
    $currentAppSecret = $config.appSecret

    Write-Host $bannerLine -ForegroundColor Cyan
    Write-Host "=                           AUTHENTICATION STAGE                             =" -ForegroundColor Cyan
    Write-Host $bannerLine -ForegroundColor Cyan
    Write-Host "`nAuthenticating with Microsoft Defender API for Tenant ID: $($currentTenantId)..." -ForegroundColor Cyan
    Write-Host "Application ID: $($currentAppId)" -ForegroundColor White
    Write-Host "`n"

    $resourceAppIdUri = 'https://api.securitycenter.windows.com'
    $oAuthUri         = "https://login.windows.net/$currentTenantId/oauth2/token"
    $authBody         = @{
        resource      = $resourceAppIdUri
        client_id     = $currentAppId
        client_secret = $currentAppSecret
        grant_type    = 'client_credentials'
    }

    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        $token        = $authResponse.access_token

        # Store token with tenantId as key
        $tenantTokens[$currentTenantId] = $token

        # Removed: Saving token to a file
        # Removed: Write-Host "Token retrieved and saved securely.`n"

        Write-Host "Authentication successful for Tenant ID $($currentTenantId)!" -ForegroundColor Green

    } catch {
        Write-Host "`n"
        Write-Host $bannerLine -ForegroundColor DarkRed
        Write-Host "=                           ERROR STAGE                                     =" -ForegroundColor DarkRed
        Write-Host $bannerLine -ForegroundColor DarkRed
        Write-Host "`nAuthentication failed for Tenant ID $($currentTenantId)!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        # Continue to the next tenant even if one fails
    }
}

# If no tokens were successfully retrieved, exit
if ($tenantTokens.Count -eq 0) {
    Write-Host "No tenants were successfully authenticated. Exiting script." -ForegroundColor Red
    exit 1
}

'''

    # Append the rest of the PowerShell functions and main execution block (common to both single/multi)
    powershell_code += r'''
# ----------------------------------------------------------------------------------
# Function: Submit-IOC
# ----------------------------------------------------------------------------------
function Submit-IOC {
    param(
        [string]$Token,
        [string]$IndicatorValue,
        [string]$IndicatorType,
        [string]$Action = "Block",
        [string]$Title,
        [string]$Description,
        [string]$Severity = "High"
    )

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $Token"
    }

    $body = @{
        indicatorValue = $IndicatorValue
        indicatorType  = $IndicatorType
        action         = $Action
        title          = $Title
        description    = $Description
        severity       = $Severity
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri 'https://api.securitycenter.windows.com/api/indicators' -Method Post -Headers $headers -Body $body
        Write-Host "IOC submitted successfully: $IndicatorValue" -ForegroundColor Green
        return $response
    } catch {
        Write-Host "Failed to submit IOC: $IndicatorValue" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        # This catch block means if Invoke-RestMethod throws an error, FailedIOCs++ will be triggered.
        # If it doesn't throw, but $response is empty/null, then $failedIOCs++ will also be triggered.
    }
}

# ----------------------------------------------------------------------------------
# Function: Get-UserIOCs
# ----------------------------------------------------------------------------------
function Get-UserIOCs {
    $iocs = @()

    do {
        Write-Host "Select IOC type:" -ForegroundColor Cyan
        Write-Host "1. IP Address (public IPs only)" -ForegroundColor Green
        Write-Host "2. Domain Name" -ForegroundColor Green
        Write-Host "3. File Hash (SHA256)" -ForegroundColor Green
        Write-Host "4. File Hash (SHA1)" -ForegroundColor Green
        Write-Host "5. File Hash (MD5)" -ForegroundColor Green
        Write-Host "6. URL" -ForegroundColor Green
        Write-Host "0. Finish and submit" -ForegroundColor Red

        $choice = Read-Host "Enter your choice (0-6)"

        switch ($choice) {
            "1" {
                Write-Host "IP Address Entry" -ForegroundColor Blue
                $ip     = Read-Host "Enter malicious IP address"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($ip -and $title -and $desc) {
                    # Repair defanged IOC before adding
                    $repairedIp = Repair-DefangedIOC -DefangedIOC $ip
                    $iocs += @{ Value = $repairedIp; Type = "IpAddress"; Title = $title; Description = $desc }
                    Write-Host "IP address added!" -ForegroundColor Green
                }
            }
            "2" {
                Write-Host "Domain Name Entry" -ForegroundColor Blue
                $domain = Read-Host "Enter malicious domain"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($domain -and $title -and $desc) {
                    # Repair defanged IOC before adding
                    $repairedDomain = Repair-DefangedIOC -DefangedIOC $domain
                    $iocs += @{ Value = $repairedDomain; Type = "DomainName"; Title = $title; Description = $desc }
                    Write-Host "Domain added!" -ForegroundColor Green
                }
            }
            "3" {
                Write-Host "SHA256 Hash Entry" -ForegroundColor Blue
                $hash   = Read-Host "Enter SHA256 hash"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($hash -and $title -and $desc) {
                    $iocs += @{ Value = $hash; Type = "FileSha256"; Title = $title; Description = $desc }
                    Write-Host "SHA256 hash added!" -ForegroundColor Green
                }
            }
            "4" {
                Write-Host "SHA1 Hash Entry" -ForegroundColor Blue
                $hash   = Read-Host "Enter SHA1 hash"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($hash -and $title -and $desc) {
                    $iocs += @{ Value = $hash; Type = "FileSha1"; Title = $title; Description = $desc }
                    Write-Host "SHA1 hash added!" -ForegroundColor Green
                }
            }
            "5" {
                Write-Host "MD5 Hash Entry" -ForegroundColor Blue
                $hash   = Read-Host "Enter MD5 hash"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($hash -and $title -and $desc) {
                    $iocs += @{ Value = $hash; Type = "FileMd5"; Title = $title; Description = $desc }
                    Write-Host "MD5 hash added!" -ForegroundColor Green
                }
            }
            "6" {
                Write-Host "URL Entry" -ForegroundColor Blue
                $url    = Read-Host "Enter malicious URL"
                $title  = Read-Host "Enter title for this IOC"
                $desc   = Read-Host "Enter description"
                if ($url -and $title -and $desc) {
                    # Repair defanged IOC before adding
                    $repairedUrl = Repair-DefangedIOC -DefangedIOC $url
                    $iocs += @{ Value = $repairedUrl; Type = "Url"; Title = $title; Description = $desc }
                    Write-Host "URL added!" -ForegroundColor Green
                }
            }
            "0" {
                break
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            }
        }
        Write-Host ""
    } while ($choice -ne "0")

    return $iocs
}

# ============================================================================================
# NEW HELPER FUNCTIONS
# ============================================================================================

# ----------------------------------------------------------------------------------
# Function: Repair-DefangedIOC
# ----------------------------------------------------------------------------------
function Repair-DefangedIOC {
    param(
        [string]$DefangedIOC
    )
    
    if (-not $DefangedIOC) {
        return $DefangedIOC
    }
    
    # Replace common defanging patterns
    $repairedIOC = $DefangedIOC.Trim()
    
    # Common bracket patterns
    $repairedIOC = $repairedIOC -replace '\[\.?\]', '.'
    $repairedIOC = $repairedIOC -replace '\(\.?\)', '.'
    $repairedIOC = $repairedIOC -replace '\{\.?\}', '.'
    $repairedIOC = $repairedIOC -replace '\[dot\]', '.'
    $repairedIOC = $repairedIOC -replace '\{dot\}', '.'
    $repairedIOC = $repairedIOC -replace '\(dot\)', '.'
    $repairedIOC = $repairedIOC -replace '\[DOT\]', '.'
    $repairedIOC = $repairedIOC -replace '\{DOT\}', '.'
    $repairedIOC = $repairedIOC -replace '\(DOT\)', '.'
    
    # HTTP protocol defanging
    $repairedIOC = $repairedIOC -replace 'hxxp', 'http'
    $repairedIOC = $repairedIOC -replace 'hXXp', 'http'
    $repairedIOC = $repairedIOC -replace 'h[xX]{2}p', 'http'
    $repairedIOC = $repairedIOC -replace 'hXXPs', 'https'
    $repairedIOC = $repairedIOC -replace 'hxxps', 'https'
    $repairedIOC = $repairedIOC -replace 'h[xX]{2}ps', 'https'
    
    # Other common patterns
    $repairedIOC = $repairedIOC -replace '\[@\]', '@'
    $repairedIOC = $repairedIOC -replace '\[:\]', ':'
    $repairedIOC = $repairedIOC -replace '\[/\]', '/'
    $repairedIOC = $repairedIOC -replace '\[/\]', '/'
    $repairedIOC = $repairedIOC -replace 'meow', '.'
    $repairedIOC = $repairedIOC -replace 'DOT', '.'
    $repairedIOC = $repairedIOC -replace ' dot ', '.'
    $repairedIOC = $repairedIOC -replace ' DOT ', '.'
    
    # Additional bracket patterns for colons and slashes
    $repairedIOC = $repairedIOC -replace '\{:\}', ':'
    $repairedIOC = $repairedIOC -replace '\(:\)', ':'
    $repairedIOC = $repairedIOC -replace '\{/\}', '/'
    $repairedIOC = $repairedIOC -replace '\(/\)', '/'
    
    # Remove extra spaces that might be introduced
    $repairedIOC = $repairedIOC -replace '\s+', ' '
    $repairedIOC = $repairedIOC.Trim()
    
    return $repairedIOC
}

# ----------------------------------------------------------------------------------
# Function: Test-IOCExists
# ----------------------------------------------------------------------------------
function Test-IOCExists {
    param(
        [string]$Token,
        [string]$IndicatorValue,
        [string]$IndicatorType
    )
    
    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $Token"
    }
    
    try {
        # Query existing indicators
        $response = Invoke-RestMethod -Uri 'https://api.securitycenter.windows.com/api/indicators' -Method Get -Headers $headers
        
        # Check if IOC already exists
        $existingIOC = $response.value | Where-Object { 
            $_.indicatorValue -eq $IndicatorValue -and $_.indicatorType -eq $IndicatorType 
        }
        
        return $existingIOC -ne $null
    } catch {
        Write-Host "Warning: Could not check if IOC exists: $IndicatorValue" -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        return $false
    }
}

# ----------------------------------------------------------------------------------
# Function: Parse-TwoColumnLine
# ----------------------------------------------------------------------------------
function Parse-TwoColumnLine {
    param(
        [string]$Line
    )
    
    $line = $Line.Trim()
    
    # Skip empty lines and comments
    if (-not $line -or $line.StartsWith("#")) {
        return $null
    }
    
    # Try to split by comma first, then by tab, then by multiple spaces
    $parts = @()
    
    if ($line.Contains(",")) {
        $parts = $line -split "," | ForEach-Object { $_.Trim() }
    } elseif ($line.Contains("`t")) {
        $parts = $line -split "`t" | ForEach-Object { $_.Trim() }
    } else {
        # Split by multiple spaces (2 or more)
        $parts = $line -split "\s{2,}" | ForEach-Object { $_.Trim() }
    }
    
    # Must have exactly 2 parts
    if ($parts.Count -ne 2) {
        return $null
    }
    
    $indicator = $parts[0].Trim()
    $type = $parts[1].Trim()
    
    # Validate that we have both values
    if (-not $indicator -or -not $type) {
        return $null
    }
    
    return @{
        Indicator = $indicator
        Type = $type
    }
}

# ----------------------------------------------------------------------------------
# Function: Read-ExcelFile
# ----------------------------------------------------------------------------------
function Read-ExcelFile {
    param(
        [string]$FilePath
    )
    
    $iocs = @()
    
    try {
        # Import Excel module if available, otherwise use COM object
        if (Get-Module -ListAvailable -Name ImportExcel) {
            Import-Module ImportExcel -ErrorAction SilentlyContinue
            $excelData = Import-Excel -Path $FilePath -NoHeader
        } else {
            # Use COM object as fallback
            $excel = New-Object -ComObject Excel.Application
            $excel.Visible = $false
            $excel.DisplayAlerts = $false
            
            $workbook = $excel.Workbooks.Open($FilePath)
            $worksheet = $workbook.Worksheets.Item(1)
            
            # Get used range
            $usedRange = $worksheet.UsedRange
            $rowCount = $usedRange.Rows.Count
            $colCount = $usedRange.Columns.Count
            
            $excelData = @()
            for ($row = 1; $row -le $rowCount; $row++) {
                $rowData = @()
                for ($col = 1; $col -le $colCount; $col++) {
                    $cellValue = $worksheet.Cells.Item($row, $col).Text
                    $rowData += $cellValue
                }
                $excelData += ,($rowData -join " ")
            }
            
            $workbook.Close()
            $excel.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        }
        
        # Process Excel data - combine all cells into a single string
        $allText = ""
        foreach ($row in $excelData) {
            if ($row -is [array]) {
                $allText += ($row -join " ") + " "
            } else {
                $allText += $row + " "
            }
        }
        
        # Parse the combined text
        $iocs = Parse-ExcelIOCText -Text $allText -FilePath $FilePath
        
    } catch {
        Write-Host "Error reading Excel file: $FilePath" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    
    return $iocs
}

# ----------------------------------------------------------------------------------
# Function: Parse-ExcelIOCText
# ----------------------------------------------------------------------------------
function Parse-ExcelIOCText {
    param(
        [string]$Text,
        [string]$FilePath
    )
    
    $iocs = @()
    
    # Split text into tokens
    $tokens = $Text -split '\s+' | Where-Object { $_.Trim() -ne "" }
    
    $currentType = ""
    $typeMapping = @{
        "FileHash-MD5" = "FileMd5"
        "FileHash-SHA1" = "FileSha1"
        "FileHash-SHA256" = "FileSha256"
        "IPv4" = "IpAddress"
        "URL" = "Url"
        "Domain" = "DomainName"
    }
    
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $token = $tokens[$i].Trim()
        
        # Check if this token is a type indicator
        if ($typeMapping.ContainsKey($token)) {
            $currentType = $typeMapping[$token]
            Write-Host "Found IOC type: $token -> $currentType" -ForegroundColor Cyan
        } elseif ($currentType -ne "" -and $token -ne "") {
            # This is an indicator value
            $originalIndicator = $token
            $repairedIndicator = Repair-DefangedIOC -DefangedIOC $originalIndicator
            
            # Show repair if it was changed
            if ($originalIndicator -ne $repairedIndicator) {
                Write-Host "Repaired defanged IOC: $originalIndicator -> $repairedIndicator" -ForegroundColor Cyan
            }
            
            # Validate the indicator based on type
            $isValid = $true
            switch ($currentType) {
                "FileMd5" { 
                    if ($repairedIndicator -notmatch "^[a-fA-F0-9]{32}$") { $isValid = $false }
                }
                "FileSha1" { 
                    if ($repairedIndicator -notmatch "^[a-fA-F0-9]{40}$") { $isValid = $false }
                }
                "FileSha256" { 
                    if ($repairedIndicator -notmatch "^[a-fA-F0-9]{64}$") { $isValid = $false }
                }
                "IpAddress" { 
                    if ($repairedIndicator -notmatch "^([0-9]{1,3}\.){3}[0-9]{1,3}$") { $isValid = $false }
                }
                "Url" { 
                    if ($repairedIndicator -notmatch "^https?://") { $isValid = $false }
                }
                "DomainName" { 
                    if ($repairedIndicator -notmatch "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") { $isValid = $false }
                }
            }
            
            if ($isValid) {
                $title = "IOC from Excel file ($currentType)"
                $description = "Imported from $FilePath"
                
                $iocs += @{
                    Value = $repairedIndicator
                    Type = $currentType
                    Title = $title
                    Description = $description
                }
            } else {
                Write-Host "Warning: Invalid $currentType format, skipping: $repairedIndicator" -ForegroundColor Yellow
            }
        }
    }
    
    return $iocs
}

# ----------------------------------------------------------------------------------
# Function: Read-IOCsFromFile
# ----------------------------------------------------------------------------------
function Read-IOCsFromFile {
    param(
        [string]$FilePath
    )
    
    $iocs = @()
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "Error: File not found: $FilePath" -ForegroundColor Red
        return $iocs
    }
    
    try {
        $fileExtension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        
        if ($fileExtension -eq ".xlsx" -or $fileExtension -eq ".xls") {
            # Handle Excel files
            Write-Host "Processing Excel file..." -ForegroundColor Cyan
            $iocs = Read-ExcelFile -FilePath $FilePath
        } elseif ($fileExtension -eq ".json") {
            # Parse JSON file (existing functionality)
            $fileContent = Get-Content -Path $FilePath -Raw
            $jsonData = $fileContent | ConvertFrom-Json
            
            # Support different JSON structures
            $iocArray = @()
            if ($jsonData.IOCs) {
                $iocArray = $jsonData.IOCs
            } elseif ($jsonData -is [array]) {
                $iocArray = $jsonData
            } else {
                Write-Host "Error: Unsupported JSON structure in file: $FilePath" -ForegroundColor Red
                return $iocs
            }
            
            foreach ($item in $iocArray) {
                if ($item.Value -and $item.Type -and $item.Title -and $item.Description) {
                    # Repair defanged IOC before adding
                    $repairedValue = Repair-DefangedIOC -DefangedIOC $item.Value
                    $iocs += @{
                        Value = $repairedValue
                        Type = $item.Type
                        Title = $item.Title
                        Description = $item.Description
                    }
                } else {
                    Write-Host "Warning: Skipping malformed IOC entry in JSON file" -ForegroundColor Yellow
                }
            }
        } else {
            # Parse text file - support both two-column format and single-column format
            $fileContent = Get-Content -Path $FilePath -Raw
            $lines = $fileContent -split "`n" | Where-Object { $_.Trim() -ne "" }
            
            foreach ($line in $lines) {
                $line = $line.Trim()
                
                # Skip empty lines and comments
                if (-not $line -or $line.StartsWith("#")) {
                    continue
                }
                
                # Try to parse as two-column format first
                $parsedLine = Parse-TwoColumnLine -Line $line
                
                if ($parsedLine) {
                    # Two-column format: indicator,type
                    $indicator = $parsedLine.Indicator
                    $type = $parsedLine.Type
                    
                    # Repair defanged IOC
                    $repairedIndicator = Repair-DefangedIOC -DefangedIOC $indicator
                    
                    # Show repair if it was changed
                    if ($indicator -ne $repairedIndicator) {
                        Write-Host "Repaired defanged IOC: $indicator -> $repairedIndicator" -ForegroundColor Cyan
                    }
                    
                    $title = "IOC from file ($type)"
                    $description = "Imported from $FilePath"
                    
                    $iocs += @{
                        Value = $repairedIndicator
                        Type = $type
                        Title = $title
                        Description = $description
                    }
                } else {
                    # Fall back to single-column format with auto-detection
                    $indicator = $line
                    
                    # Repair defanged IOC first
                    $repairedIndicator = Repair-DefangedIOC -DefangedIOC $indicator
                    
                    # Show repair if it was changed
                    if ($indicator -ne $repairedIndicator) {
                        Write-Host "Repaired defanged IOC: $indicator -> $repairedIndicator" -ForegroundColor Cyan
                    }
                    
                    # Auto-detect IOC type based on pattern
                    $iocType = ""
                    $title = "IOC from file"
                    $description = "Imported from $FilePath"
                    
                    if ($repairedIndicator -match "^([0-9]{1,3}\.){3}[0-9]{1,3}$") {
                        $iocType = "IpAddress"
                        $title = "Malicious IP from file"
                    } elseif ($repairedIndicator -match "^[a-fA-F0-9]{64}$") {
                        $iocType = "FileSha256"
                        $title = "Malicious file hash (SHA256) from file"
                    } elseif ($repairedIndicator -match "^[a-fA-F0-9]{40}$") {
                        $iocType = "FileSha1"
                        $title = "Malicious file hash (SHA1) from file"
                    } elseif ($repairedIndicator -match "^[a-fA-F0-9]{32}$") {
                        $iocType = "FileMd5"
                        $title = "Malicious file hash (MD5) from file"
                    } elseif ($repairedIndicator -match "^https?://") {
                        $iocType = "Url"
                        $title = "Malicious URL from file"
                    } elseif ($repairedIndicator -match "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
                        $iocType = "DomainName"
                        $title = "Malicious domain from file"
                    } else {
                        Write-Host "Warning: Could not determine IOC type for: $repairedIndicator" -ForegroundColor Yellow
                        continue
                    }
                    
                    $iocs += @{
                        Value = $repairedIndicator
                        Type = $iocType
                        Title = $title
                        Description = $description
                    }
                }
            }
        }
        
        Write-Host "Successfully loaded $($iocs.Count) IOCs from file: $FilePath" -ForegroundColor Green
        
        # Show summary of loaded IOC types
        $typeGroups = $iocs | Group-Object -Property Type
        Write-Host "IOC Types loaded:" -ForegroundColor Cyan
        foreach ($group in $typeGroups) {
            Write-Host "  - $($group.Name): $($group.Count)" -ForegroundColor White
        }
        
    } catch {
        Write-Host "Error reading file: $FilePath" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    
    return $iocs
}

# ----------------------------------------------------------------------------------
# Function: Show-FinalSummary
# ----------------------------------------------------------------------------------
function Show-FinalSummary {
    param(
        [int]$TotalIOCs,
        [int]$SubmittedIOCs,
        [int]$SkippedIOCs,
        [int]$FailedIOCs
    )
    
    Write-Host "`n"
    Write-Host $bannerLine -ForegroundColor Yellow
    Write-Host "=                           FINAL SUMMARY                                   =" -ForegroundColor Yellow
    Write-Host $bannerLine -ForegroundColor Yellow
    Write-Host ""
    #Write-Host "Total IOCs processed: $TotalIOCs" -ForegroundColor White
    Write-Host "Successfully submitted: $SubmittedIOCs" -ForegroundColor Green
    Write-Host "Skipped (already exist): $SkippedIOCs" -ForegroundColor Yellow
    Write-Host "Failed to submit: $FailedIOCs" -ForegroundColor Red
    Write-Host ""
    
    if ($SubmittedIOCs -gt 0) {
        Write-Host "IOC submission completed successfully!" -ForegroundColor Green
    } elseif ($SkippedIOCs -gt 0 -and $FailedIOCs -eq 0) {
        Write-Host "All IOCs already exist in the system." -ForegroundColor Yellow
    } else {
        Write-Host "No IOCs were submitted." -ForegroundColor Red
    }
}

# ----------------------------------------------------------------------------------
# Main Execution Block
# ----------------------------------------------------------------------------------
'''
    if len(tenant_configs) == 1:
        # Single tenant main execution block
        powershell_code += r'''
try {
    # IOC INPUT METHOD SELECTION
    Write-Host $bannerLine -ForegroundColor Magenta
    Write-Host "=                           IOC INPUT METHOD                                =" -ForegroundColor Magenta
    Write-Host $bannerLine -ForegroundColor Magenta
    Write-Host "`nSelect IOC input method:" -ForegroundColor Magenta
    Write-Host "1. Enter IOCs manually" -ForegroundColor Green
    Write-Host "2. Load IOCs from file" -ForegroundColor Green
    Write-Host "   Supported formats:" -ForegroundColor Gray
    Write-Host "   - Excel (.xlsx/.xls): Type-Indicator pairs" -ForegroundColor Gray
    Write-Host "   - Two-column: indicator,type or indicator<tab>type" -ForegroundColor Gray
    Write-Host "   - Single-column: auto-detection (fallback)" -ForegroundColor Gray
    Write-Host "   - JSON: structured format" -ForegroundColor Gray
    Write-Host "0. Exit" -ForegroundColor Red
    
    $inputChoice = Read-Host "Enter your choice (0-2)"
    $userIOCs = @()
    
    switch ($inputChoice) {
        "1" {
            Write-Host "`nEnter your IOCs manually:`n" -ForegroundColor Cyan
            $userIOCs = Get-UserIOCs
        }
        "2" {
            $filePath = Read-Host "Enter file path (supports .txt, .csv, .xlsx, .xls, and .json)"
            if ($filePath) {
                $userIOCs = Read-IOCsFromFile -FilePath $filePath
            }
        }
        "0" {
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
        default {
            Write-Host "Invalid choice. Exiting..." -ForegroundColor Red
            exit 1
        }
    }
    
    Write-Host "`n"

    if ($userIOCs.Count -gt 0) {
        # IOC SUBMISSION STAGE
        Write-Host $bannerLine -ForegroundColor Blue
        Write-Host "=                           PROCESSING STAGE                                =" -ForegroundColor Blue
        Write-Host $bannerLine -ForegroundColor Blue
        Write-Host "`nProcessing $($userIOCs.Count) IOCs...`n" -ForegroundColor Cyan

        # Initialize counters
        $totalIOCs = $userIOCs.Count
        $submittedIOCs = 0
        $skippedIOCs = 0
        $failedIOCs = 0

        foreach ($ioc in $userIOCs) {
            Write-Host "`n--- Processing IOC: $($ioc.Value) (Type: $($ioc.Type)) ---" -ForegroundColor DarkCyan
            # IOC value should already be repaired from file reading or manual entry
            # But we'll double-check to ensure it's properly repaired
            $originalValue = $ioc.Value
            $repairedValue = Repair-DefangedIOC -DefangedIOC $originalValue
            
            # Update the IOC value if it was changed
            if ($originalValue -ne $repairedValue) {
                Write-Host "  Additional repair needed for IOC: $originalValue -> $repairedValue" -ForegroundColor Cyan
                $ioc.Value = $repairedValue
            }
            
            # Check if IOC already exists
            Write-Host "  Checking if IOC already exists..." -ForegroundColor Gray
            if (Test-IOCExists -Token $token -IndicatorValue $ioc.Value -IndicatorType $ioc.Type) {
                Write-Host "  IOC already exists, skipping: $($ioc.Value)" -ForegroundColor Yellow
                $skippedIOCs++
                continue
            }
            
            # Submit IOC
            Write-Host "  Submitting IOC..." -ForegroundColor Gray
            $result = Submit-IOC -Token $token -IndicatorValue $ioc.Value -IndicatorType $ioc.Type -Title $ioc.Title -Description $ioc.Description
            
            if ($result) {
                Write-Host "  IOC $($ioc.Value) submitted successfully." -ForegroundColor Green
                $submittedIOCs++
            } else {
                Write-Host "  IOC $($ioc.Value) submission failed (no explicit API error caught)." -ForegroundColor Red
                $failedIOCs++
            }
        }
        
        # Show final summary
        Show-FinalSummary -TotalIOCs $totalIOCs -SubmittedIOCs $submittedIOCs -SkippedIOCs $skippedIOCs -FailedIOCs $failedIOCs
    } else {
        Write-Host "No IOCs to process." -ForegroundColor Yellow
    }

    # COMPLETION STAGE
    Write-Host "`n"
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host "=                           COMPLETION STAGE                                =" -ForegroundColor Green
    Write-Host $bannerLine -ForegroundColor Green
    Write-Host "`nScript execution completed!" -ForegroundColor Green

    # Removed: return $token
} catch {
    # ERROR STAGE
    Write-Host "`n"
    Write-Host $bannerLine -ForegroundColor DarkRed
    Write-Host "=                           ERROR STAGE                                     =" -ForegroundColor DarkRed
    Write-Host $bannerLine -ForegroundColor DarkRed
    Write-Host "`nAn unexpected error occurred during IOC processing or file handling!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
'''
    else:
        # Multi-tenant main execution block
        powershell_code += r'''
foreach ($tenantConfig in $tenantConfigs) {
    $token = $null
    $currentTenantId = $tenantConfig.tenantId
    $currentAppId = $tenantConfig.appId
    $currentAppSecret = $tenantConfig.appSecret

    # Re-authenticate for this tenant to ensure fresh token and handle potential failures
    Write-Host "`n"
    Write-Host $bannerLine -ForegroundColor Cyan
    Write-Host "=                           RE-AUTHENTICATING FOR TENANT: $($currentTenantId)     =" -ForegroundColor Cyan
    Write-Host $bannerLine -ForegroundColor Cyan
    
    $resourceAppIdUri = 'https://api.securitycenter.windows.com'
    $oAuthUri         = "https://login.windows.net/$currentTenantId/oauth2/token"
    $authBody         = @{
        resource      = $resourceAppIdUri
        client_id     = $currentAppId
        client_secret = $currentAppSecret
        grant_type    = 'client_credentials'
    }

    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        $token        = $authResponse.access_token
        Write-Host "Authentication successful for Tenant ID $($currentTenantId)!" -ForegroundColor Green
        # Removed: Saving token to a file
    } catch {
        Write-Host "Authentication failed for Tenant ID $($currentTenantId). Skipping IOC processing for this tenant." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        continue # Skip to the next tenant
    }


    Write-Host "`n"
    Write-Host $bannerLine -ForegroundColor Blue
    Write-Host "=                           PROCESSING IOCs FOR TENANT: $($currentTenantId)     =" -ForegroundColor Blue
    Write-Host $bannerLine -ForegroundColor Blue

    # IOC INPUT METHOD SELECTION
    Write-Host $bannerLine -ForegroundColor Magenta
    Write-Host "=                           IOC INPUT METHOD                                =" -ForegroundColor Magenta
    Write-Host $bannerLine -ForegroundColor Magenta
    Write-Host "`nSelect IOC input method for Tenant ID $($currentTenantId):" -ForegroundColor Magenta
    Write-Host "1. Enter IOCs manually" -ForegroundColor Green
    Write-Host "2. Load IOCs from file" -ForegroundColor Green
    Write-Host "   Supported formats:" -ForegroundColor Gray
    Write-Host "   - Excel (.xlsx/.xls): Type-Indicator pairs" -ForegroundColor Gray
    Write-Host "   - Two-column: indicator,type or indicator<tab>type" -ForegroundColor Gray
    Write-Host "   - Single-column: auto-detection (fallback)" -ForegroundColor Gray
    Write-Host "   - JSON: structured format" -ForegroundColor Gray
    Write-Host "0. Skip this tenant" -ForegroundColor Red
    
    $inputChoice = Read-Host "Enter your choice (0-2)"
    $userIOCs = @()
    
    switch ($inputChoice) {
        "1" {
            Write-Host "`nEnter your IOCs manually for Tenant ID $($currentTenantId):`n" -ForegroundColor Cyan
            $userIOCs = Get-UserIOCs
        }
        "2" {
            $filePath = Read-Host "Enter file path (supports .txt, .csv, .xlsx, .xls, and .json) for Tenant ID $($currentTenantId)"
            if ($filePath) {
                $userIOCs = Read-IOCsFromFile -FilePath $filePath
            }
        }
        "0" {
            Write-Host "Skipping IOC processing for Tenant ID $($currentTenantId)..." -ForegroundColor Yellow
            continue # Move to the next tenant
        }
        default {
            Write-Host "Invalid choice. Skipping IOC processing for Tenant ID $($currentTenantId)..." -ForegroundColor Red
            continue # Move to the next tenant
        }
    }
    
    Write-Host "`n"

    if ($userIOCs.Count -gt 0) {
        # Initialize counters for the current tenant
        $totalIOCs = $userIOCs.Count
        $submittedIOCs = 0
        $skippedIOCs = 0
        $failedIOCs = 0

        foreach ($ioc in $userIOCs) {
            Write-Host "`n--- Processing IOC: $($ioc.Value) (Type: $($ioc.Type)) for Tenant $($currentTenantId) ---" -ForegroundColor DarkCyan
            $originalValue = $ioc.Value
            $repairedValue = Repair-DefangedIOC -DefangedIOC $originalValue
            
            if ($originalValue -ne $repairedValue) {
                Write-Host "  Additional repair needed for IOC: $originalValue -> $repairedValue" -ForegroundColor Cyan
                $ioc.Value = $repairedValue
            }
            
            Write-Host "  Checking if IOC already exists..." -ForegroundColor Gray
            if (Test-IOCExists -Token $token -IndicatorValue $ioc.Value -IndicatorType $ioc.Type) {
                Write-Host "  IOC already exists, skipping: $($ioc.Value)" -ForegroundColor Yellow
                $skippedIOCs++
                continue
            }
            
            Write-Host "  Submitting IOC..." -ForegroundColor Gray
            $result = Submit-IOC -Token $token -IndicatorValue $ioc.Value -IndicatorType $ioc.Type -Title $ioc.Title -Description $ioc.Description
            
            if ($result) {
                Write-Host "  IOC $($ioc.Value) submitted successfully." -ForegroundColor Green
                $submittedIOCs++
            } else {
                Write-Host "  IOC $($ioc.Value) submission failed (no explicit API error caught)." -ForegroundColor Red
                $failedIOCs++
            }
        }
        
        # Show final summary for the current tenant
        Show-FinalSummary -TotalIOCs $totalIOCs -SubmittedIOCs $submittedIOCs -SkippedIOCs $skippedIOCs -FailedIOCs $failedIOCs
    } else {
        Write-Host "No IOCs to process for Tenant ID $($currentTenantId)." -ForegroundColor Yellow
    }
}

# COMPLETION STAGE (Overall)
Write-Host "`n"
Write-Host $bannerLine -ForegroundColor Green
Write-Host "=                           OVERALL COMPLETION STAGE                        =" -ForegroundColor Green
Write-Host $bannerLine -ForegroundColor Green
Write-Host "`nScript execution completed for all configured tenants!" -ForegroundColor Green

'''

    return powershell_code

def get_tenant_details():
    """Prompts the user for tenant ID, application ID, and application secret."""
    tenant_id = input("Enter the Tenant ID: ").strip()
    app_id = input("Enter the Application ID: ").strip()
    app_secret = input("Enter the Application Secret: ").strip()
    return {"tenantId": tenant_id, "appId": app_id, "appSecret": app_secret}

def main():
    print("--------------------------------------------------------------------------------------")
    print("         Welcome to Wizard-Octopus main PowerShell IOC Blocker Script Generator       ")
    print("--------------------------------------------------------------------------------------")
    print("This tool will help you generate a PowerShell script to block Indicators of Compromise (IOCs).")
    print("You can configure it for a single Microsoft Defender tenant or multiple tenants.")
    print("\nLet's get started!\n")

    tenant_type = ""
    while tenant_type not in ["1", "2"]:
        tenant_type = input("Are you setting this up for a **single tenant** or **multi-tenants**?\n"
                            "1. Single Tenant\n"
                            "2. Multi-Tenant (up to 30 tenants)\n"
                            "Enter your choice (1 or 2): ").strip()

        if tenant_type not in ["1", "2"]:
            print("Invalid choice. Please enter '1' for Single Tenant or '2' for Multi-Tenant.\n")

    tenant_configs = []

    if tenant_type == "1":
        print("\n--- Single Tenant Configuration ---")
        config = get_tenant_details()
        tenant_configs.append(config)
        print("\nReview your configuration:")
        print(f"  Tenant ID:   {config['tenantId']}")
        print(f"  App ID:      {config['appId']}")
        print(f"  App Secret:  {'*' * len(config['appSecret'])}") # Mask secret for display
        confirm = input("Does this look correct? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("Configuration not confirmed. Exiting.")
            return

    else: # Multi-Tenant
        print("\n--- Multi-Tenant Configuration ---")
        for i in range(1, 31):
            print(f"\n--- Tenant {i} Details ---")
            config = get_tenant_details()
            tenant_configs.append(config)
            print(f"Tenant {i} added.")

            if i < 30:
                add_more = input("Do you want to add details for another tenant? (yes/no): ").strip().lower()
                if add_more != 'yes':
                    break
            else:
                print("Maximum number of tenants (30) reached.")

        if not tenant_configs:
            print("No tenants configured. Exiting.")
            return

        print("\n--- All Configured Tenants ---")
        for i, config in enumerate(tenant_configs):
            print(f"Tenant {i+1}:")
            print(f"  Tenant ID:   {config['tenantId']}")
            print(f"  App ID:      {config['appId']}")
            print(f"  App Secret:  {'*' * len(config['appSecret'])}")
        
        confirm_all = input("\nDo all tenant configurations look correct? (yes/no): ").strip().lower()
        if confirm_all != 'yes':
            print("Configurations not confirmed. Exiting.")
            return

    print("\n--- Generating PowerShell Script ---")
    generated_ps_code = generate_powershell_script(tenant_configs)

    output_filename = "Block_IOCs.ps1"
    try:
        with open(output_filename, "w") as f:
            f.write(generated_ps_code)
        print(f"\nYour PowerShell script has been generated and saved to '{output_filename}'!")
        print("\nTo use the script:")
        print(f"1. Open PowerShell as an administrator.")
        print(f"2. Navigate to the directory where you saved '{output_filename}'.")
        print(f"3. Run the script using: `. .\\{output_filename}`")
        print("\nWARNING: This script contains hardcoded credentials. Handle the generated .ps1 file with extreme care and ensure it is stored securely.")
    except IOError as e:
        print(f"\nError: Could not write the PowerShell script to file '{output_filename}'.")
        print(f"Please check your permissions or disk space. Error details: {e}")
        print("\nHere is the generated script content to copy manually:")
        print("\n" + "="*80 + "\n")
        print(generated_ps_code)
        print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    main()