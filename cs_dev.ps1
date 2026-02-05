#Requires -Version 3.0

# set the $proxyserver to $null if no proxy is needed or in case proxy connection is needed then set it as $proxyserver = "http://svr001-e1-svr.zone2.proxy.allianz:8090" (change the URl and port)

$proxyserver = $null
$FalconCid = '8D1D0162E794458180D9091E71BA686F-30'
$FalconCloud = 'eu-1'
$FalconClientId='882f9239941c4865bf7d310826a12060'
$FalconClientSecret='BGZhjpWPwF0EmrgY5b9L8TVCH46M3xJ1enI7qS2z'
$SensorUpdatePolicyName='windows_n_1'
$InstallParams='/install /quiet /noreboot NoDC=1 GROUPING_TAGS=EGID-D-000002'
$DeleteInstaller = $true
$DeleteScript = $false


    if ($PSVersionTable.PSVersion -lt '3.0')
    { throw "This script requires a miniumum PowerShell 3.0" }

    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = if (!$PSScriptRoot) {
        Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    }
    else {
        $PSScriptRoot
    }

    function Write-FalconLog ([string] $Source, [string] $Message, [bool] $stdout = $true) {
        $Content = @(Get-Date -Format 'yyyy-MM-dd hh:MM:ss')
        if ($Source -notmatch '^(StartProcess|Delete(Installer|Script))$' -and
            $Falcon.ResponseHeaders.Keys -contains 'X-Cs-TraceId') {
            $Content += , "[$($Falcon.ResponseHeaders.Get('X-Cs-TraceId'))]"
        }

        "$(@($Content + $Source) -join ' '): $Message" | Out-File -FilePath $LogPath -Append -Encoding utf8

        if ($stdout) {
            Write-Output $Message
        }
    }

    function Write-VerboseLog ([psobject] $VerboseInput, [string] $PreMessage) {

        # Determine if the input is a string or an object
        if ($VerboseInput -is [string]) {
            $message = $VerboseInput
        }
        else {
            $message = $VerboseInput | ConvertTo-Json -Depth 10
        }

        # If a pre message is provided, add it to the beginning of the message
        if ($PreMessage) {
            $message = "$PreMessage`r`n$message"
        }

        # Write Verbose
        Write-Verbose $message

        # Write to log file, but not stdout
        Write-FalconLog -Source 'VERBOSE' -Message $message -stdout $false
    }

    function Get-FalconCloud ([string] $xCsRegion) {
        $Output = switch ($xCsRegion) {
            'autodiscover' { 'https://api.crowdstrike.com'; break }
            'us-1' { 'https://api.crowdstrike.com'; break }
            'us-2' { 'https://api.us-2.crowdstrike.com'; break }
            'eu-1' { 'https://api.eu-1.crowdstrike.com'; break }
            'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com'; break }
            default { throw "Provided region $xCsRegion is invalid. Please set FalconCloud to a valid region or 'autodiscover'"; break }
        }
        return $Output
    }

    function Invoke-FalconAuth([string] $BaseUrl, [hashtable] $Body, [string] $FalconCloud) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
        $Headers.Add('User-Agent', 'crowdstrike-falcon-scripts/1.1.7')
        try {
            
            if ($proxyServer -ne $null) { $response = Invoke-WebRequest -Proxy $proxyserver -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body }
            else { $response = Invoke-WebRequest -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body   }

            $content = ConvertFrom-Json -InputObject $response.Content
            Write-VerboseLog -VerboseInput $content -PreMessage 'Invoke-FalconAuth - $content:'

            if ([string]::IsNullOrEmpty($content.access_token)) {
                $message = 'Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again.'
                throw $message
            }

            $Headers.Add('Authorization', "bearer $($content.access_token)")
        }
        catch {
            # Handle redirects
            Write-Verbose "Invoke-FalconAuth - CAUGHT EXCEPTION - `$_.Exception.Message`r`n$($_.Exception.Message)"
            $response = $_.Exception.Response

            if (!$response) {
                $message = "Unhandled error occurred while authenticating to the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                throw $message
            }

            if ($response.StatusCode -in @(301, 302, 303, 307, 308)) {
                # If autodiscover is enabled, try to get the correct cloud
                if ($FalconCloud -eq 'autodiscover') {
                    if ($response.Headers.Contains('X-Cs-Region')) {
                        $region = $response.Headers.GetValues('X-Cs-Region')[0]
                        Write-Verbose "Received a redirect to $region. Setting FalconCloud to $region"
                    }
                    else {
                        $message = 'Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region.'
                        Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                        throw $message
                    }

                    $BaseUrl = Get-FalconCloud($region)
                    $BaseUrl, $Headers = Invoke-FalconAuth -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud

                }
                else {
                    $message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                    throw $message
                }
            }
            else {
                $message = "Received a $($response.StatusCode) response from $($BaseUrl)oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
                Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                throw $message
            }
        }

        return $BaseUrl, $Headers
    }

    function Test-FalconCredential([string] $FalconClientId , [string] $FalconClientSecret ) {
        if ($FalconClientId -and $FalconClientSecret) {
            return $true
        }
        else {
            return $false
        }
    }

    $WinSystem = [Environment]::GetFolderPath('System')
    $WinTemp = $WinSystem -replace 'system32', 'Temp'
    if (!$LogPath) {
        $LogPath = Join-Path -Path $WinTemp -ChildPath 'InstallFalcon.log'
    }

    function Format-403Error([string] $url, [hashtable] $scope) {
        $message = "Insufficient permission error when calling $($url). Verify the following scopes are included in the API key:"
        foreach ($key in $scope.Keys) {
            $message += "`r`n`t '$($key)' with: $($scope[$key])"
        }
        return $message
    }

    function Format-FalconResponseError($errors) {
        $message = ''
        foreach ($error in $errors) {
            $message += "`r`n`t $($error.message)"
        }
        return $message
    }

    function Get-ResourceContent([string] $url, [string] $logKey, [hashtable] $scope, [string] $errorMessage) {
        try {
            
            if ($proxyServer -ne $null) { $response = Invoke-WebRequest -Proxy $proxyserver -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -MaximumRedirection 0 }
            else { $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -MaximumRedirection 0   }
            
            $content = ConvertFrom-Json -InputObject $response.Content
            Write-VerboseLog -VerboseInput $content -PreMessage 'Get-ResourceContent - $content:'

            if ($content.errors) {
                $message = "Error when getting content: "
                $message += Format-FalconResponseError -errors $content.errors
                Write-FalconLog $logKey $message
                throw $message
            }

            if ($content.resources) {
                return $content.resources
            }
            else {
                $message = $errorMessage
                throw $message
            }
        }
        catch {
            Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'Get-ResourceContent - CAUGHT EXCEPTION - $_.Exception:'
            $response = $_.Exception.Response

            if (!$response) {
                $message = "Unhandled error occurred. Error: $($_.Exception.Message)"
                throw $message
            }

            if ($response.StatusCode -eq 403) {
                $message = Format-403Error -url $url -scope $scope
                Write-FalconLog $logKey $message
                throw $message
            }
            else {
                $message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
                Write-FalconLog $logKey $message
                throw $message
            }
        }
    }

    function Get-InstallerHash ([string] $Path) {
        $Output = if (Test-Path $Path) {
            $Algorithm = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")
            $Hash = [System.BitConverter]::ToString(
                $Algorithm.ComputeHash([System.IO.File]::ReadAllBytes($Path)))
            if ($Hash) {
                $Hash.Replace('-', '')
            }
            else {
                $null
            }
        }
        return $Output
    }

    function Invoke-FalconDownload ([string] $url, [string] $Outfile) {
        try {
            $ProgressPreference = 'SilentlyContinue'
            if ($proxyServer -ne $null) { $response = Invoke-WebRequest -Proxy $proxyserver -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -OutFile $Outfile  }
            else { $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -OutFile $Outfile   }
        }
        catch {
            $response = $_.Exception.Response
            if (!$response) {
                $message = "Unhandled error occurred. Error: $($_.Exception.Message)"
                Write-FalconLog 'DownloadFile' $message
                throw $message
            }
            if ($response.StatusCode -eq 403) {
                $scope = @{
                    'Sensor Download' = @('Read')
                }
                $message = Format-403Error -url $url -scope $scope
                Write-FalconLog 'Permissions' $message
                throw $message
            }
            else {
                $message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
                Write-FalconLog 'DownloadFile' $message
                throw $message
            }
        }
    }

    if (!$SensorUpdatePolicyName) {
        $SensorUpdatePolicyName = 'platform_default'
    }
    if (!$InstallParams) {
        $InstallParams = '/install /quiet /noreboot'
    }
#########################

    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
        $message = 'Unable to proceed without administrative privileges'
        Write-FalconLog 'CheckAdmin' $message
        throw $message
    }
    elseif (Get-Service | Where-Object { $_.Name -eq 'CSFalconService' }) {
        $message = "'CSFalconService' running. Falcon sensor is already installed."
        Write-FalconLog 'CheckService' $message
        exit 0
    }

    else {
        $credsProvided = Test-FalconCredential $FalconClientId $FalconClientSecret
        if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            }
            catch {
                $message = $_
                Write-FalconLog 'TlsCheck' $message
                throw $message
            }
        }
        if (!($PSVersionTable.CLRVersion.ToString() -ge 3.5)) {
            $message = '.NET Framework 3.5 or newer is required'
            Write-FalconLog 'NetCheck' $message
            throw $message
        }
    }

    # Configure OAuth2 authentication
    if ($credsProvided) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
        $BaseUrl = Get-FalconCloud $FalconCloud

        $Body = @{}
        $Body['client_id'] = $FalconClientId
        $Body['client_secret'] = $FalconClientSecret

        if ($MemberCid) {
            $Body['member_cid'] = $MemberCid
        }

        $BaseUrl, $Headers = Invoke-FalconAuth -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud
        $Headers['Content-Type'] = 'application/json'
    }
    else {
        $message = 'Unable to proceed without valid API credentials. Ensure you pass the required parameters or define them in the script.'
        Write-FalconLog 'CheckCredentials' $message
        throw $message
    }

    # Get CCID from API if not provided
    if (!$FalconCid) {
        Write-FalconLog 'GetCcid' 'No CCID provided. Attempting to retrieve from the CrowdStrike Falcon API.'
        $url = "${BaseUrl}/sensors/queries/installers/ccid/v1"
        $ccid_scope = @{
            'Sensor Download' = @('Read')
        }
        $ccid = Get-ResourceContent -url $url -logKey 'GetCcid' -scope $ccid_scope -errorMessage "Unable to grab CCID from the CrowdStrike Falcon API."

        $message = "Retrieved CCID: $ccid"
        Write-FalconLog 'GetCcid' $message
        $InstallParams += " CID=$ccid"
    }
    else {
        $message = "Using provided CCID: $FalconCid"
        Write-FalconLog 'GetCcid' $message
        $InstallParams += " CID=$FalconCid"
    }

    # Get sensor version from policy
    $message = "Retrieving sensor policy details for '$($SensorUpdatePolicyName)'"
    Write-FalconLog 'GetPolicy' $message
    $filter = "platform_name:'Windows'+name.raw:'$($SensorUpdatePolicyName.ToLower())'"
    $url = "${BaseUrl}/policy/combined/sensor-update/v2?filter=$([System.Web.HttpUtility]::UrlEncode($filter)))"
    $policy_scope = @{
        'Sensor update policies' = @('Read')
    }
    $policyDetails = Get-ResourceContent -url $url -logKey 'GetPolicy' -scope $policy_scope -errorMessage "Unable to fetch policy details from the CrowdStrike Falcon API."
    $policyId = $policyDetails.id
    $build = $policyDetails[0].settings.build
    $version = $policyDetails[0].settings.sensor_version
    $version = $version -replace '\s*\(LTS\)\s*', ''

    # Make sure we got a version from the policy
    if (!$version) {
        $message = "Unable to retrieve sensor version from policy '$($SensorUpdatePolicyName)'. Please check the policy and try again."
        Write-FalconLog 'GetPolicy' $message
        throw $message
    }

    $message = "Retrieved sensor policy details: Policy ID: $policyId, Build: $build, Version: $version"
    Write-FalconLog 'GetPolicy' $message

    # Get installer details based on policy version
    $message = "Retrieving installer details for sensor version: '$($version)'"
    Write-FalconLog 'GetInstaller' $message
    $encodedFilter = [System.Web.HttpUtility]::UrlEncode("platform:'windows'+version:'$($version)'")
    $url = "${BaseUrl}/sensors/combined/installers/v1?filter=${encodedFilter}"
    $installer_scope = @{
        'Sensor Download' = @('Read')
    }
    $installerDetails = Get-ResourceContent -url $url -logKey 'GetInstaller' -scope $installer_scope -errorMessage "Unable to fetch installer details from the CrowdStrike Falcon API."

    if ( $installerDetails.sha256 -and $installerDetails.name ) {
        $cloudHash = $installerDetails.sha256
        $cloudFile = $installerDetails.name
        $message = "Found installer: ($cloudFile) with sha256: '$cloudHash'"
        Write-FalconLog 'GetInstaller' $message
    }
    else {
        $message = "Failed to retrieve installer details."
        Write-FalconLog 'GetInstaller' $message
        throw $message
    }

    # Download the installer
    $localFile = Join-Path -Path $WinTemp -ChildPath $cloudFile
    Write-FalconLog 'DownloadFile' "Downloading installer to: '$localFile'"
    $url = "${BaseUrl}/sensors/entities/download-installer/v1?id=$cloudHash"
    Invoke-FalconDownload -url $url -Outfile $localFile

    if (Test-Path $localFile) {
        $localHash = Get-InstallerHash -Path $localFile
        $message = "Successfull downloaded installer '$localFile' ($localHash)"
        Write-FalconLog 'DownloadFile' $message
    }
    else {
        $message = "Failed to download installer."
        Write-FalconLog 'DownloadFile' $message
        throw $message
    }

    # Compare the hashes prior to installation
    if ($cloudHash -ne $localHash) {
        $message = "Hash mismatch on download (Local: $localHash, Cloud: $cloudHash)"
        Write-FalconLog 'CheckHash' $message
        throw $message
    }

    # Additional parameters
    if ($ProvToken) {
        $InstallParams += " ProvToken=$ProvToken"
    }

    if ($Tags) {
        $InstallParams += " GROUPING_TAGS=$Tags"
    }

    # Begin installation
    Write-FalconLog 'Installer' 'Installing Falcon Sensor...'
    Write-FalconLog 'StartProcess' "Starting installer with parameters: '$InstallParams'"

    $process = (Start-Process -FilePath $LocalFile -ArgumentList $InstallParams -PassThru -ErrorAction SilentlyContinue)
    Write-FalconLog 'StartProcess' "Started '$LocalFile' ($($process.Id))"
    Write-FalconLog 'StartProcess' "Waiting for the installer process to complete with PID ($($process.Id))"
    Wait-Process -Id $process.Id
    Write-FalconLog 'StartProcess' "Installer process with PID ($($process.Id)) has completed"

    # Check the exit code
    if ($process.ExitCode -ne 0) {
        Write-VerboseLog -VerboseInput $process -PreMessage 'PROCESS EXIT CODE ERROR - $process:'
        if ($process.ExitCode -eq 1244) {
            $message = "Exit code 1244: Falcon was unable to communicate with the CrowdStrike cloud. Please check your installation token and try again."
            Write-FalconLog 'InstallerProcess' $message
            throw $message
        }
        else {
            $errOut = $process.StandardError.ReadToEnd()
            $message = "Falcon installer exited with code $($process.ExitCode). Error: $errOut"
            Write-FalconLog 'InstallerProcess' $message
            throw $message
        }
    }

    @('DeleteInstaller', 'DeleteScript') | ForEach-Object {
        if ((Get-Variable $_).Value -eq $true) {
            $FilePath = if ($_ -eq 'DeleteInstaller') {
                $LocalFile
            }
            else {
                Join-Path -Path $ScriptPath -ChildPath $ScriptName
            }
            Remove-Item -Path $FilePath -Force
            if (Test-Path $FilePath) {
                Write-FalconLog $_ "Failed to delete '$FilePath'"
            }
            else {
                Write-FalconLog $_ "Deleted '$FilePath'"
            }
       }
    }

    Write-FalconLog 'InstallerProcess' 'Falcon sensor installed successfully.'


    Write-FalconLog 'EndScript' 'Script completed.'
    $message = "`r`nSee the full log contents at: '$($LogPath)'"
    Write-Output $message