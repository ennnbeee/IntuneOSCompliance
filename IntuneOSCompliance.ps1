<#PSScriptInfo

.VERSION 0.1.2
.GUID 5101b3d0-e968-4607-8b90-2562bfcb703f
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Android iOS macOS Apps Compliance
.LICENSEURI https://github.com/ennnbeee/IntuneOSCompliance/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/IntuneOSCompliance
.ICONURI https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/ioc-icon.png
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.1.2 - Updated logo source and formatting
v0.1.1 - Added support for Windows App Protection Policies and Windows 10
v0.1.0 - Initial release.

.PRIVATEDATA
#>
<#
.SYNOPSIS


.DESCRIPTION


.PARAMETER notification
Set to $true to send a Microsoft Teams notification if any policies were updated. Default is $true.

.PARAMETER teamsWebHook
Provide the Microsoft Teams webhook URL to send notifications to. If not provided, notifications will not be sent.

.PARAMETER tenantId
Provide the Id of the Entra ID tenant to connect to.

.PARAMETER appId
Provide the Id of the Entra App registration to be used for authentication.

.PARAMETER appSecret
Provide the App secret to allow for authentication to graph

.EXAMPLE
Interactive Authentication
.\IntuneOSCompliance.ps1

.EXAMPLE
Pass through Authentication
.\IntuneOSCompliance.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099'

.EXAMPLE
App Authentication
.\IntuneOSCompliance.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e72-baaf-a35126464d67' -appSecret 'g708Q~uof4xo9dU_1EjGQIuUr0UyBHNZmY2m3dy6'

#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(

    [Parameter(Mandatory = $false, HelpMessage = 'Sets whether a Microsoft Teams notification should be sent if any policies were updated')]
    [bool]$teamsNotify = $true,

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the Microsoft Teams webhook URL to send notifications to')]
    [String]$teamsWebHook,

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the Id of the Entra ID tenant to connect to')]
    [ValidateLength(36, 36)]
    [String]$tenantId,

    [Parameter(Mandatory = $false, ParameterSetName = 'appAuth', HelpMessage = 'Provide the Id of the Entra App registration to be used for authentication')]
    [ValidateLength(36, 36)]
    [String]$appId,

    [Parameter(Mandatory = $true, ParameterSetName = 'appAuth', HelpMessage = 'Provide the App secret to allow for authentication to graph')]
    [ValidateNotNullOrEmpty()]
    [String]$appSecret

)

#region functions
function Test-JSONData {

    param (
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $TestJSON | Out-Null
        $validJson = $true
    }
    catch {
        $validJson = $false
        Write-Error $_.Exception.Message
        throw
    }
    if (!$validJson) {
        Write-Error $_.Exception.Message
        throw
    }
}
function Connect-ToGraph {

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$tenantId,
        [Parameter(Mandatory = $false)] [string]$appId,
        [Parameter(Mandatory = $false)] [string]$appSecret,
        [Parameter(Mandatory = $false)] [string[]]$scopes
    )

    process {
        Import-Module Microsoft.Graph.Authentication
        $osVersion = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

        if ($AppId -ne '') {
            $body = @{
                grant_type    = 'client_credentials';
                client_id     = $appId;
                client_secret = $appSecret;
                scope         = 'https://graph.microsoft.com/.default';
            }

            $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
            $accessToken = $response.access_token

            if ($osVersion -eq 2) {
                Write-Output 'Version 2 module detected'
                $accessTokenFinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                Write-Output 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
                $accessTokenFinal = $accessToken
            }
            $graph = Connect-MgGraph -AccessToken $accessTokenFinal
            Write-Output "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($osVersion -eq 2) {
                Write-Output 'Version 2 module detected'
            }
            else {
                Write-Output 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -Scopes $scopes -TenantId $tenantId
            Write-Output "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}
function Get-DeviceCompliancePolicy {

    [cmdletbinding()]
    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -OutputType PSObject

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }
        $results
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
function Set-DeviceCompliancePolicy() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]
    param
    (
        [Parameter(Mandatory = $true)]
        $Id,

        [Parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $resource = "deviceManagement/deviceCompliancePolicies/$id"
    if ($PSCmdlet.ShouldProcess('Compliance Policy', 'Update')) {
        try {

            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Patch -Body $JSON -ContentType 'application/json'

        }
        catch {
            Write-Error $_.Exception.Message
            throw
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output "Compliance Policy $Id would have been updated"
    }
    else {
        Write-Output "Compliance Policy $Id was not updated"
    }

}
function Get-AppProtectionPolicy {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('iOS', 'Android', 'Windows')]
        [string]$os
    )

    $graphApiVersion = 'Beta'
    if ($os -eq 'Android') {
        $Resource = 'deviceAppManagement/androidManagedAppProtections'
    }
    elseif ($os -eq 'iOS') {
        $Resource = 'deviceAppManagement/iosManagedAppProtections'
    }
    elseif ($os -eq 'Windows') {
        $Resource = 'deviceAppManagement/windowsManagedAppProtections'
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -OutputType PSObject

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }
        $results
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
function Set-AppProtectionPolicy() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]
    param
    (

        [Parameter(Mandatory = $true)]
        [ValidateSet('iOS', 'Android', 'Windows')]
        [string]$os,

        [Parameter(Mandatory = $true)]
        $Id,

        [Parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'

    if ($os -eq 'iOS') {
        $resource = "deviceAppManagement/iosManagedAppProtections/$id"
    }
    elseif ($os -eq 'Android') {
        $resource = "deviceAppManagement/androidManagedAppProtections/$id"
    }
    elseif ($os -eq 'Windows') {
        $resource = "deviceAppManagement/windowsManagedAppProtections/$id"
    }

    if ($PSCmdlet.ShouldProcess('App Protection Policy', 'Update')) {
        try {

            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Patch -Body $JSON -ContentType 'application/json'

        }
        catch {
            Write-Error $_.Exception.Message
            throw
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output "App Protection Policy $Id would have been updated"
    }
    else {
        Write-Output "App Protection Policy $Id was not updated"
    }

}
function Get-WindowsUpdateBuild() {

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $osVersion
    )
    try {

        if ($osVersion -like '19*') {
            $uri = 'https://support.microsoft.com/en-us/feed/atom/6ae59d69-36fc-8e4d-23dd-631d98bf74a9'
        }
        else {
            $uri = 'https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92'
        }

        [xml]$osUpdates = (Invoke-WebRequest -Uri $uri -UseBasicParsing -ContentType 'application/xml').Content -replace '[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000-x10FFFF]', ''

        $buildVersions = @()
        foreach ($osUpdate in $osUpdates.feed.entry) {
            if ($osUpdate.title.'#text' -like "*$osVersion*" -and $osUpdate.title.'#text' -notlike '*Preview*' -and $update.title.'#text' -notlike '*Out-of-band*') {
                $buildVersions += $osUpdate.title.'#text'
            }
        }
        $buildVersion = $buildVersions[0].Substring($BuildVersions[0].LastIndexOf('.')) -replace '[^0-9]'
        $osBuildVersion = '10.0.' + $osVersion + '.' + $buildVersion
        return $osBuildVersion
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
function Get-AppleUpdateBuild() {

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('iOS', 'macOS', 'iPadOS')]
        $OS,
        [Parameter(Mandatory = $true)]
        $osVersion
    )

    try {
        #$uri = 'https://developer.apple.com/news/releases/rss/releases.rss'
        $uri = 'https://sofafeed.macadmins.io/v1/rss_feed.xml'
        [xml]$Updates = (Invoke-WebRequest -Uri $uri -UseBasicParsing -ContentType 'application/xml').Content -replace '[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000-x10FFFF]', ''

        $buildVersions = @()
        foreach ($update in $Updates.rss.channel.Item) {
            if (($update.title -like "*$OS*" -and $update.title -like "*$osVersion*") -and ($update.title -notlike '*beta*' -and $update.title -notlike '*RC*')) {
                $buildVersions += $Update.title
            }
        }
        $osBuildVersion = ($buildVersions[0] -split ' ')[-1]

        return $osBuildVersion
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
function Get-AndroidUpdateBuild() {

    try {
        $uri = 'https://source.android.com/docs/security/bulletin/asb-overview'
        $html = (Invoke-WebRequest -Uri $uri -UseBasicParsing).Content

        $tableMatch = [regex]::Match($html, '(?is)<table[^>]*>.*?Security patch level.*?</table>')
        if (-not $tableMatch.Success) { throw "Could not find the table containing 'Security patch level'." }
        $tableHtml = $tableMatch.Value

        $rowMatch = [regex]::Match($tableHtml, '(?is)<tr[^>]*>\s*<td[^>]*>.*?</tr>')
        if (-not $rowMatch.Success) { throw 'Could not find the first data row in the security bulletin table.' }
        $firstDataRow = $rowMatch.Value

        $cells = [regex]::Matches($firstDataRow, '(?is)<td[^>]*>(?<cell>.*?)</td>') | ForEach-Object { $_.Groups['cell'].Value }
        if ($cells.Count -lt 4) { throw 'First data row did not contain at least 4 columns.' }
        $patchCellHtml = $cells[3]

        $dates = [regex]::Matches($patchCellHtml, '\b\d{4}-\d{2}-\d{2}\b') | ForEach-Object { $_.Value }
        if ($dates.Count -lt 2) { throw 'Could not find two patch level dates inside the Security patch level cell.' }

        $patchLevel1 = ([datetime]$dates[0]).ToString('yyyy-MM-dd')
        #$patchLevel2 = ([datetime]$dates[1]).ToString('dd-MM-yyyy')

        # Optional guard rails, warnings only
        if ($dates[0] -notmatch '-01$') { Write-Warning "PatchLevel1 does not end with '-01' ($($dates[0]))" }
        if ($dates[1] -notmatch '-05$') { Write-Warning "PatchLevel2 does not end with '-05' ($($dates[1]))" }

        return $patchLevel1
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
function Get-EndOfLifeDate {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('iOS', 'Android')]
        [string]$os
    )

    if ($os -eq 'Android') {
        $Resource = 'products/android'
    }
    elseif ($os -eq 'iOS') {
        $Resource = 'products/ipados'
    }

    try {
        $uri = "https://endoflife.date/api/v1/$($Resource)"
        $eolResults = Invoke-RestMethod -Uri $uri -Method Get
        $results = $eolResults.result.releases | Where-Object { $_.isEol -eq $false } | ForEach-Object { $_.name } | Sort-Object -Descending
        $results
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
#endregion

#region variables
$androidLogo = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/android.png'
$macOSLogo = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/apple.png'
$iOSLogo = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/apple.png'
$windowsLogo = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/windows.png'
$scopes = @('DeviceManagementApps.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All')
$teamsItems = @()
$dateTime = Get-Date -Format 'HH:mm:ss dd/MM/yyyy'
$rndWait = Get-Random -Minimum 1 -Maximum 2
#endregion

#region intro
Clear-Host
Write-Host '
░▀█▀░█▀█░▀█▀░█░█░█▀█░█▀▀
░░█░░█░█░░█░░█░█░█░█░█▀▀
░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀░▀▀▀' -ForegroundColor Cyan
Write-Host '
░█▀█░█▀▀
░█░█░▀▀█
░▀▀▀░▀▀▀' -ForegroundColor Red
Write-Host '
░█▀▀░█▀█░█▄█░█▀█░█░░░▀█▀░█▀█░█▀█░█▀▀░█▀▀
░█░░░█░█░█░█░█▀▀░█░░░░█░░█▀█░█░█░█░░░█▀▀
░▀▀▀░▀▀▀░▀░▀░▀░░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀▀▀░▀▀▀' -ForegroundColor DarkRed

Write-Host "`nIntuneOSCompliance - Automatic update of Microsoft Intune operating system compliance and app protection policies." -ForegroundColor Green
Write-Host "`nNick Benton - oddsandendpoints.co.uk" -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.1.2 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2026-05-07' -ForegroundColor Magenta
Write-Host "`nIf you have any feedback, open an issue at https://github.com/ennnbeee/IntuneOSCompliance/issues" -ForegroundColor Cyan
Start-Sleep -Seconds $rndWait
#endregion

#region module check
$modules = @('Microsoft.Graph.Authentication')
foreach ($module in $modules) {
    Write-Host "`nChecking for $module PowerShell module..." -ForegroundColor Cyan
    if (!(Get-Module -Name $module -ListAvailable)) {
        Install-Module -Name $module -Scope CurrentUser -AllowClobber
    }
    Write-Host "PowerShell Module $module found." -ForegroundColor Green
    if (!([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object FullName -Like "*$module*")) {
        Import-Module -Name $module -Force
    }
}
#endregion

#region app auth
try {
    if (!$tenantId) {
        Write-Host 'Connecting using interactive authentication' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    else {
        if ((!$appId -and !$appSecret) -or ($appId -and !$appSecret) -or (!$appId -and $appSecret)) {
            Write-Host 'Missing App Details, connecting using user authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -Scopes $scopes -ErrorAction Stop
        }
        else {
            Write-Host 'Connecting using App authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -appId $appId -appSecret $appSecret -ErrorAction Stop
        }
    }
    $context = Get-MgContext
    Write-Host "`nSuccessfully connected to Microsoft Graph tenant $($context.TenantId)." -ForegroundColor Green
}
catch {
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        Write-Host $_.ErrorDetails.Message -ForegroundColor Red
    }
    else {
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    exit
}
#endregion

#region scopes
$currentScopes = $context.Scopes
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Yellow
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "`nEnsure these permissions are granted to the app registration for full functionality." -ForegroundColor Yellow
    exit
}
else {
    Write-Host "`nAll required scope permissions are present." -ForegroundColor Green
}
Start-Sleep -Seconds $rndWait
#endregion

#region compliance
$policyType = 'Compliance'
$compliancePolicies = Get-DeviceCompliancePolicy
if ($null -ne $compliancePolicies) {
    #region Windows
    $os = 'Windows'
    $osImageUrl = $windowsLogo
    $windowsCompliancePolicies = $compliancePolicies | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.windows10CompliancePolicy' -and ($_.validOperatingSystemBuildRanges -ne $null -or $_.osMinimumVersion -ne $null) }
    Write-Host "`nFound $($windowsCompliancePolicies.Count) $os $policyType Policies with build ranges or Minimum versions." -ForegroundColor Green

    if ($null -ne $windowsCompliancePolicies) {
        $windowsVersions = @()
        $windowsBuilds = @()
        $windowsCompliancePolicies.osMinimumVersion | ForEach-Object {
            if ($null -ne $_) {
                $windowsVersions += $_.split('.')[2]
            }
        }
        $windowsCompliancePolicies.validOperatingSystemBuildRanges.lowestVersion | ForEach-Object {
            $windowsVersions += $_.split('.')[2]
        }
        $windowsVersions | Sort-Object -Unique | ForEach-Object {
            $windowsBuilds += [PSCustomObject]@{
                version     = $_
                latestBuild = Get-WindowsUpdateBuild -osVersion $_
            }
        }
        foreach ($compliancePolicy in $windowsCompliancePolicies) {
            $policyChange = $false
            $minVersion = $null
            $policyDisplayName = $compliancePolicy.displayName
            Write-Host "Checking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            if (![string]::IsNullOrEmpty($compliancePolicy.osMinimumVersion)) {
                $minVersion = $compliancePolicy.osMinimumVersion
                $osVersion = $minVersion.Split('.')[2]
                $latestBuild = $windowsBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
                if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                    $policyChange = $true
                    $compliancePolicy.osMinimumVersion = $latestBuild
                    $teamsItems += @{
                        items          = @(
                            @{
                                columns = @(
                                    @{
                                        items = @(
                                            @{
                                                type = 'Image'
                                                url  = "$osImageUrl"
                                                size = 'Medium'
                                            }
                                        )
                                        type  = 'Column'
                                        width = 'auto'
                                    }
                                    @{
                                        items = @(
                                            @{
                                                isSubtle = $true
                                                size     = 'Small'
                                                text     = "$policyType - $os"
                                                wrap     = $true
                                                type     = 'TextBlock'
                                            }
                                            @{
                                                text    = "$policyDisplayName"
                                                weight  = 'Bolder'
                                                wrap    = $true
                                                type    = 'TextBlock'
                                                spacing = 'None'
                                            }
                                            @{
                                                text    = "Minimum operating system build version updated from $minVersion to $latestBuild"
                                                wrap    = $true
                                                type    = 'TextBlock'
                                                spacing = 'None'
                                            }
                                        )
                                        type  = 'Column'
                                        width = 'stretch'
                                    }
                                )
                                type    = 'ColumnSet'
                            }
                        )
                        style          = 'emphasis'
                        spacing        = 'Small'
                        targetWidth    = 'atLeast:Narrow'
                        type           = 'Container'
                        roundedCorners = $true
                        showBorder     = $true
                    }
                }
            }
            if (![string]::IsNullOrEmpty($compliancePolicy.validOperatingSystemBuildRanges)) {
                foreach ($buildRange in $compliancePolicy.validOperatingSystemBuildRanges) {
                    $minVersion = $buildRange.lowestVersion
                    $osVersion = $minVersion.Split('.')[2]
                    $latestBuild = $windowsBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
                    if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                        $policyChange = $true
                        $buildRange.lowestVersion = $latestBuild
                        $teamsItems += @{
                            items          = @(
                                @{
                                    columns = @(
                                        @{
                                            items = @(
                                                @{
                                                    type = 'Image'
                                                    url  = "$osImageUrl"
                                                    size = 'Medium'
                                                }
                                            )
                                            type  = 'Column'
                                            width = 'auto'
                                        }
                                        @{
                                            items = @(
                                                @{
                                                    isSubtle = $true
                                                    size     = 'Small'
                                                    text     = "$policyType - $os"
                                                    wrap     = $true
                                                    type     = 'TextBlock'
                                                }
                                                @{
                                                    text    = "$policyDisplayName"
                                                    weight  = 'Bolder'
                                                    wrap    = $true
                                                    type    = 'TextBlock'
                                                    spacing = 'None'
                                                }
                                                @{
                                                    text    = "Minimum operating system version updated from $minVersion to $latestBuild"
                                                    wrap    = $true
                                                    type    = 'TextBlock'
                                                    spacing = 'None'
                                                }
                                            )
                                            type  = 'Column'
                                            width = 'stretch'
                                        }
                                    )
                                    type    = 'ColumnSet'
                                }
                            )
                            style          = 'emphasis'
                            spacing        = 'Small'
                            targetWidth    = 'atLeast:Narrow'
                            type           = 'Container'
                            roundedCorners = $true
                            showBorder     = $true
                        }
                    }
                }
            }
            if ($policyChange -eq $true) {

                Write-Host "Updating $os $policyType policy from $minVersion to $latestBuild" -ForegroundColor Magenta
                $jsonBody = $compliancePolicy | Select-Object -Property * -ExcludeProperty createdDateTime, lastModifiedDateTime | ConvertTo-Json -Depth 10
                Start-Sleep -Seconds $(Get-Random -Minimum 1 -Maximum 5)
                try {
                    Set-DeviceCompliancePolicy -Id $compliancePolicy.id -JSON $jsonBody
                }
                catch {
                    Write-Error "Failed to update $os $policyType policy - $_.Exception.Message"
                    continue
                }
            }
            else {
                Write-Host "No update needed for $os $policyType policy" -ForegroundColor Yellow
            }
        }
    }
    #endregion

    #region macOS
    $os = 'macOS'
    $osImageUrl = $macOSLogo
    $macOSCompliancePolicies = $compliancePolicies | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.macOSCompliancePolicy' -and $_.osMinimumVersion -ne $null }
    Write-Host "`nFound $($macOSCompliancePolicies.Count) $os $policyType Policies with Minimum OS Version." -ForegroundColor Green

    if ($null -ne $macOSCompliancePolicies) {
        $macOSVersions = @()
        $macOSBuilds = @()
        $macOSCompliancePolicies.osMinimumVersion | ForEach-Object {
            $macOSVersions += $_.Split('.')[0]
        }
        $macOSVersions | Sort-Object -Unique | ForEach-Object {
            $macOSBuilds += [PSCustomObject]@{
                version     = $_
                latestBuild = Get-AppleUpdateBuild -OS 'macOS' -osVersion $_
            }
        }
        foreach ($compliancePolicy in $macOSCompliancePolicies) {
            $policyChange = $false
            $policyDisplayName = $compliancePolicy.displayName
            Write-Host "Checking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minVersion = $compliancePolicy.osMinimumVersion
            $osVersion = $minVersion.Split('.')[0]
            $latestBuild = $macOSBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
            if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                $policyChange = $true
                $compliancePolicy.osMinimumVersion = $latestBuild
                $teamsItems += @{
                    items          = @(
                        @{
                            columns = @(
                                @{
                                    items = @(
                                        @{
                                            type = 'Image'
                                            url  = "$osImageUrl"
                                            size = 'Medium'
                                        }
                                    )
                                    type  = 'Column'
                                    width = 'auto'
                                }
                                @{
                                    items = @(
                                        @{
                                            isSubtle = $true
                                            size     = 'Small'
                                            text     = "$policyType - $os"
                                            wrap     = $true
                                            type     = 'TextBlock'
                                        }
                                        @{
                                            text    = "$policyDisplayName"
                                            weight  = 'Bolder'
                                            wrap    = $true
                                            type    = 'TextBlock'
                                            spacing = 'None'
                                        }
                                        @{
                                            text    = "Minimum operating system version updated from $minVersion to $latestBuild"
                                            wrap    = $true
                                            type    = 'TextBlock'
                                            spacing = 'None'
                                        }
                                    )
                                    type  = 'Column'
                                    width = 'stretch'
                                }
                            )
                            type    = 'ColumnSet'
                        }
                    )
                    style          = 'emphasis'
                    spacing        = 'Small'
                    targetWidth    = 'atLeast:Narrow'
                    type           = 'Container'
                    roundedCorners = $true
                    showBorder     = $true
                }
            }
            if ($policyChange -eq $true) {

                Write-Host "Updating $os $policyType policy from $minVersion to $latestBuild" -ForegroundColor Magenta
                $jsonBody = $compliancePolicy | Select-Object -Property * -ExcludeProperty createdDateTime, lastModifiedDateTime | ConvertTo-Json -Depth 10
                Start-Sleep -Seconds $(Get-Random -Minimum 1 -Maximum 5)
                try {
                    Set-DeviceCompliancePolicy -Id $compliancePolicy.id -JSON $jsonBody
                }
                catch {
                    Write-Error "Failed to update $os $policyType policy - $_.Exception.Message"
                    continue
                }
            }
            else {
                Write-Host "No update needed for $os $policyType policy" -ForegroundColor Yellow
            }
        }
    }
    #endregion

    #region Apple mobile
    $os = 'Apple mobile'
    $osImageUrl = $iOSLogo
    $iOSCompliancePolicies = $compliancePolicies | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.iosCompliancePolicy' -and $_.osMinimumVersion -ne $null }
    Write-Host "`nFound $($iOSCompliancePolicies.Count) $os $policyType Policies with Minimum OS Version." -ForegroundColor Green

    if ($null -ne $iOSCompliancePolicies) {
        $iOSVersions = @()
        $iOSBuilds = @()
        $iOSCompliancePolicies.osMinimumVersion | ForEach-Object {
            $iOSVersions += $_.Split('.')[0]
        }
        $iOSVersions | Sort-Object -Unique | ForEach-Object {
            $iOSBuilds += [PSCustomObject]@{
                version     = $_
                latestBuild = Get-AppleUpdateBuild -OS 'iOS' -osVersion $_
            }
        }
        foreach ($compliancePolicy in $iOSCompliancePolicies) {
            $policyChange = $false
            $policyDisplayName = $compliancePolicy.displayName
            Write-Host "Checking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minVersion = $compliancePolicy.osMinimumVersion
            $osVersion = $minVersion.Split('.')[0]
            $latestBuild = $iOSBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
            if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                $policyChange = $true
                $compliancePolicy.osMinimumVersion = $latestBuild
                $teamsItems += @{
                    items          = @(
                        @{
                            columns = @(
                                @{
                                    items = @(
                                        @{
                                            type = 'Image'
                                            url  = "$osImageUrl"
                                            size = 'Medium'
                                        }
                                    )
                                    type  = 'Column'
                                    width = 'auto'
                                }
                                @{
                                    items = @(
                                        @{
                                            isSubtle = $true
                                            size     = 'Small'
                                            text     = "$policyType - $os"
                                            wrap     = $true
                                            type     = 'TextBlock'
                                        }
                                        @{
                                            text    = "$policyDisplayName"
                                            weight  = 'Bolder'
                                            wrap    = $true
                                            type    = 'TextBlock'
                                            spacing = 'None'
                                        }
                                        @{
                                            text    = "Minimum operating system version updated from $minVersion to $latestBuild"
                                            wrap    = $true
                                            type    = 'TextBlock'
                                            spacing = 'None'
                                        }
                                    )
                                    type  = 'Column'
                                    width = 'stretch'
                                }
                            )
                            type    = 'ColumnSet'
                        }
                    )
                    style          = 'emphasis'
                    spacing        = 'Small'
                    targetWidth    = 'atLeast:Narrow'
                    type           = 'Container'
                    roundedCorners = $true
                    showBorder     = $true
                }
            }
            if ($policyChange -eq $true) {

                Write-Host "Updating $os $policyType policy from $minVersion to $latestBuild" -ForegroundColor Magenta
                $jsonBody = $compliancePolicy | Select-Object -Property * -ExcludeProperty createdDateTime, lastModifiedDateTime | ConvertTo-Json -Depth 10
                Start-Sleep -Seconds $(Get-Random -Minimum 1 -Maximum 5)
                try {
                    Set-DeviceCompliancePolicy -Id $compliancePolicy.id -JSON $jsonBody

                }
                catch {
                    Write-Error "Failed to update $os $policyType policy - $_.Exception.Message"
                    continue
                }
            }
            else {
                Write-Host "No update needed for $os $policyType policy" -ForegroundColor Yellow
            }
        }
    }
    #endregion

    #region Android
    $os = 'Android'
    $osImageUrl = $androidLogo
    $androidCompliancePolicies = $compliancePolicies | Where-Object { ($_.'@odata.type' -eq '#microsoft.graph.androidWorkProfileCompliancePolicy' -or $_.'@odata.type' -eq '#microsoft.graph.androidDeviceOwnerCompliancePolicy') -and $_.osMinimumVersion -ne $null }
    Write-Host "`nFound $($androidCompliancePolicies.Count) $os $policyType Policies with Minimum OS Version." -ForegroundColor Green

    if ($null -ne $androidCompliancePolicies) {
        $androidVersions = @()
        $androidBuilds = @()
        $androidPatch = Get-AndroidUpdateBuild
        $androidCompliancePolicies.osMinimumVersion | ForEach-Object {
            $androidVersions += $_
        }
        $androidVersions | Sort-Object -Unique | ForEach-Object {
            $androidBuilds += [PSCustomObject]@{
                version     = $_
                latestBuild = $androidPatch
            }
        }
        foreach ($compliancePolicy in $androidCompliancePolicies) {
            $policyChange = $false
            $policyDisplayName = $compliancePolicy.displayName
            Write-Host "Checking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minOSVersion = $compliancePolicy.osMinimumVersion
            $minVersion = $compliancePolicy.minAndroidSecurityPatchLevel
            $latestBuild = $androidBuilds | Where-Object { $_.version -eq $compliancePolicy.osMinimumVersion } | Select-Object -ExpandProperty latestBuild
            if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                $policyChange = $true
                $compliancePolicy.minAndroidSecurityPatchLevel = $latestBuild
                $teamsItems += @{
                    items          = @(
                        @{
                            columns = @(
                                @{
                                    items = @(
                                        @{
                                            type = 'Image'
                                            url  = "$osImageUrl"
                                            size = 'Medium'
                                        }
                                    )
                                    type  = 'Column'
                                    width = 'auto'
                                }
                                @{
                                    items = @(
                                        @{
                                            isSubtle = $true
                                            size     = 'Small'
                                            text     = "$policyType - $os"
                                            wrap     = $true
                                            type     = 'TextBlock'
                                        }
                                        @{
                                            text    = "$policyDisplayName"
                                            weight  = 'Bolder'
                                            wrap    = $true
                                            type    = 'TextBlock'
                                            spacing = 'None'
                                        }
                                        @{
                                            text    = "Minimum security patch level for $minOSVersion updated from $minVersion to $latestBuild"
                                            wrap    = $true
                                            type    = 'TextBlock'
                                            spacing = 'None'
                                        }
                                    )
                                    type  = 'Column'
                                    width = 'stretch'
                                }
                            )
                            type    = 'ColumnSet'
                        }
                    )
                    style          = 'emphasis'
                    spacing        = 'Small'
                    targetWidth    = 'atLeast:Narrow'
                    type           = 'Container'
                    roundedCorners = $true
                    showBorder     = $true
                }
            }
            if ($policyChange -eq $true) {

                Write-Host "Updating $os $policyType policy from $minVersion to $latestBuild" -ForegroundColor Magenta
                $jsonBody = $compliancePolicy | Select-Object -Property * -ExcludeProperty createdDateTime, lastModifiedDateTime | ConvertTo-Json -Depth 10
                Start-Sleep -Seconds $(Get-Random -Minimum 1 -Maximum 5)
                try {
                    Set-DeviceCompliancePolicy -Id $compliancePolicy.id -JSON $jsonBody
                }
                catch {
                    Write-Error "Failed to update $os $policyType policy - $_.Exception.Message"
                    continue
                }
            }
            else {
                Write-Host "No update needed for $os $policyType policy" -ForegroundColor Yellow
            }
        }
    }
    #endregion
}

#endregion

#region mam
$policyType = 'App Protection'

#region Android
$os = 'Android'
$osImageUrl = $androidLogo
$androidAppProtectionPolicies = Get-AppProtectionPolicy -os Android | Where-Object { $_.minimumRequiredOsVersion -ne $null -or $_.minimumWarningOsVersion -ne $null }
Write-Host "`nFound $($androidAppProtectionPolicies.Count) $os $policyType Policies with minimum OS version requirements." -ForegroundColor Green

if ($null -ne $androidAppProtectionPolicies) {
    $androidSupported = Get-EndOfLifeDate -os Android
    if ($androidSupported.count -eq 1) {
        $newWarning = "$($androidSupported).0"
        $newRequired = "$($($androidSupported) - 1).0"
        $newWipe = "$($($androidSupported) - 2).0"
    }
    elseif ($androidSupported.count -eq 2) {
        $newWarning = "$($androidSupported[0]).0"
        $newRequired = "$($androidSupported[1]).0"
        $newWipe = "$($($androidSupported[1]) - 1).0"
    }
    else {
        $newWarning = "$($androidSupported[0]).0"
        $newRequired = "$($androidSupported[1]).0"
        $newWipe = "$($androidSupported[2]).0"
    }

    foreach ($appProtectionPolicy in $androidAppProtectionPolicies) {
        $policyChange = $false
        $policyDisplayName = $appProtectionPolicy.displayName
        Write-Host "Checking $os $policyType Policy - $policyDisplayName" -ForegroundColor Cyan
        $minWarning = $appProtectionPolicy.minimumWarningOsVersion
        $minRequired = $appProtectionPolicy.minimumRequiredOsVersion
        $minWipe = $appProtectionPolicy.minimumWipeOsVersion

        if ($null -ne $minWarning -and $minWarning -ne $newWarning) {
            $policyChange = $true
            Write-Host "Updating $os $policyType policy minOS warning from $minWarning to $newWarning" -ForegroundColor Magenta
            $appProtectionPolicy.minimumWarningOsVersion = $newWarning
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum warning OS version updated from $minWarning to $newWarning"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }
        if ($null -ne $minRequired -and $minRequired -ne $newRequired) {
            $policyChange = $true
            Write-Host "Updating $os $policyType policy minOS block from $minRequired to $newRequired" -ForegroundColor Magenta
            $appProtectionPolicy.minimumRequiredOsVersion = $newRequired
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum blocked OS version updated from $minRequired to $newRequired"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }
        if ($null -ne $minWipe -and $minWipe -ne $newWipe) {
            $policyChange = $true
            Write-Host "Updating $os $policyType policy minOS wipe from $minWipe to $newWipe" -ForegroundColor Magenta
            $appProtectionPolicy.minimumWipeOsVersion = $newWipe
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum wipe OS version updated from $minWipe to $newWipe"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }

        if ($policyChange -eq $true) {
            $jsonBody = $appProtectionPolicy | Select-Object -Property * -ExcludeProperty createdDateTime, lastModifiedDateTime | ConvertTo-Json -Depth 10
            Start-Sleep -Seconds $(Get-Random -Minimum 1 -Maximum 5)
            try {
                Set-AppProtectionPolicy -os Android -Id $appProtectionPolicy.id -JSON $jsonBody
            }
            catch {
                Write-Error "Failed to update $os $policyType policy  - $_.Exception.Message"
                continue
            }
        }
        else {
            Write-Host "No update needed for $os $policyType policy" -ForegroundColor Yellow
        }
    }
}
#endregion

#region Apple mobile
$os = 'Apple mobile'
$osImageUrl = $iOSLogo
$iOSAppProtectionPolicies = Get-AppProtectionPolicy -os iOS | Where-Object { $_.minimumRequiredOsVersion -ne $null -or $_.minimumWarningOsVersion -ne $null }
Write-Host "`nFound $($iOSAppProtectionPolicies.Count) $os $policyType Policies with minimum OS version requirements." -ForegroundColor Green

if ($null -ne $iOSAppProtectionPolicies) {
    $iOSSupported = Get-EndOfLifeDate -os iOS
    if ($iOSSupported.Count -eq 1) {
        $newWarning = "$($iOSSupported).0.0"
        $newRequired = "$($iOSSupported - 8).0.0"
        $newWipe = "$($newRequired - 1).0.0"
    }
    elseif ($iOSSupported.Count -eq 2) {
        $newWarning = "$($iOSSupported[0]).0.0"
        $newRequired = "$($iOSSupported[1]).0.0"
        $newWipe = "$($iOSSupported[1] - 1).0.0"
    }
    else {
        $newWarning = "$($iOSSupported[0]).0.0"
        $newRequired = "$($iOSSupported[1]).0.0"
        $newWipe = "$($iOSSupported[2]).0.0"
    }

    foreach ($appProtectionPolicy in $iOSAppProtectionPolicies) {
        $policyChange = $false
        $policyDisplayName = $appProtectionPolicy.displayName
        Write-Host "Checking $os $policyType Policy - $policyDisplayName" -ForegroundColor Cyan
        $minWarning = $appProtectionPolicy.minimumWarningOsVersion
        $minRequired = $appProtectionPolicy.minimumRequiredOsVersion
        $minWipe = $appProtectionPolicy.minimumWipeOsVersion

        if ($null -ne $minWarning -and $minWarning -ne $newWarning) {
            $policyChange = $true
            Write-Host "Updating $os $policyType policy minOS warning from $minWarning to $newWarning" -ForegroundColor Magenta
            $appProtectionPolicy.minimumWarningOsVersion = $newWarning
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum warning OS version updated from $minWarning to $newWarning"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }
        if ($null -ne $minRequired -and $minRequired -ne $newRequired) {
            $policyChange = $true
            Write-Host "Updating $os $policyType policy minOS block from $minRequired to $newRequired" -ForegroundColor Magenta
            $appProtectionPolicy.minimumRequiredOsVersion = $newRequired
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum blocked OS version updated from $minRequired to $newRequired"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }
        if ($null -ne $minWipe -and $minWipe -ne $newWipe) {
            $policyChange = $true
            Write-Host "Updating $os $policyType policy minOS wipe from $minWipe to $newWipe" -ForegroundColor Magenta
            $appProtectionPolicy.minimumWipeOsVersion = $newWipe
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum wipe OS version updated from $minWipe to $newWipe"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }

        if ($policyChange -eq $true) {
            $jsonBody = $appProtectionPolicy | Select-Object -Property * -ExcludeProperty createdDateTime, lastModifiedDateTime | ConvertTo-Json -Depth 10
            Start-Sleep -Seconds $(Get-Random -Minimum 1 -Maximum 5)
            try {
                Set-AppProtectionPolicy -os iOS -Id $appProtectionPolicy.id -JSON $jsonBody
            }
            catch {
                Write-Error "Failed to update $os $policyType policy $_.Exception.Message"
                continue
            }
        }
        else {
            Write-Host "No update needed for $os $policyType policy" -ForegroundColor Yellow
        }
    }
}
#endregion

#region Windows
$os = 'Windows'
$osImageUrl = $windowsLogo
$windowsAppProtectionPolicies = Get-AppProtectionPolicy -os Windows | Where-Object { $_.minimumRequiredOsVersion -ne $null -or $_.minimumWarningOsVersion -ne $null -or $_.minimumWipeOsVersion -ne $null }
Write-Host "`nFound $($windowsAppProtectionPolicies.Count) $os App Protection Policies with minimum OS version requirements." -ForegroundColor Green

if ($null -ne $windowsAppProtectionPolicies) {
    foreach ($appProtectionPolicy in $windowsAppProtectionPolicies) {

        $policyChange = $false
        $policyDisplayName = $appProtectionPolicy.displayName
        Write-Host "Checking $os $policyType Policy - $policyDisplayName" -ForegroundColor Cyan
        $minRequired = $appProtectionPolicy.minimumRequiredOsVersion
        $minWarning = $appProtectionPolicy.minimumWarningOsVersion
        $minWipe = $appProtectionPolicy.minimumWipeOsVersion

        if ($minRequired.count -ne 0) {
            $newRequired = Get-WindowsUpdateBuild -osVersion $minRequired.split('.')[2]
        }
        if ($minWarning.count -ne 0) {
            $newWarning = Get-WindowsUpdateBuild -osVersion $minWarning.split('.')[2]
        }
        if ($minWipe.count -ne 0) {
            $newWipe = Get-WindowsUpdateBuild -osVersion $minWipe.split('.')[2]
        }

        if ($null -ne $minRequired -and $minRequired -ne $newRequired) {
            $policyChange = $true
            Write-Host "Updating policy minOS block from $minRequired to $newRequired" -ForegroundColor Cyan
            $appProtectionPolicy.minimumRequiredOsVersion = $newRequired
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum blocked OS version updated from $minRequired to $newRequired"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }
        if ($null -ne $minWarning -and $minWarning -ne $newWarning) {
            $policyChange = $true
            Write-Host "Updating policy minOS warning from $minWarning to $newWarning" -ForegroundColor Cyan
            $appProtectionPolicy.minimumWarningOsVersion = $newWarning
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum warning OS version updated from $minWarning to $newWarning"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }
        if ($null -ne $minWipe -and $minWipe -ne $newWipe) {
            $policyChange = $true
            Write-Host "Updating policy minOS wipe from $minWipe to $newWipe" -ForegroundColor Cyan
            $appProtectionPolicy.minimumWipeOsVersion = $newWipe
            $teamsItems += @{
                items          = @(
                    @{
                        columns = @(
                            @{
                                items = @(
                                    @{
                                        type = 'Image'
                                        url  = "$osImageUrl"
                                        size = 'Medium'
                                    }
                                )
                                type  = 'Column'
                                width = 'auto'
                            }
                            @{
                                items = @(
                                    @{
                                        isSubtle = $true
                                        size     = 'Small'
                                        text     = "$policyType - $os"
                                        wrap     = $true
                                        type     = 'TextBlock'
                                    }
                                    @{
                                        text    = "$policyDisplayName"
                                        weight  = 'Bolder'
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                    @{
                                        text    = "Minimum wipe OS version updated from $minWipe to $newWipe"
                                        wrap    = $true
                                        type    = 'TextBlock'
                                        spacing = 'None'
                                    }
                                )
                                type  = 'Column'
                                width = 'stretch'
                            }
                        )
                        type    = 'ColumnSet'
                    }
                )
                style          = 'emphasis'
                spacing        = 'Small'
                targetWidth    = 'atLeast:Narrow'
                type           = 'Container'
                roundedCorners = $true
                showBorder     = $true
            }
        }

        if ($policyChange -eq $true) {
            $jsonBody = $appProtectionPolicy | Select-Object -Property * -ExcludeProperty createdDateTime, lastModifiedDateTime | ConvertTo-Json -Depth 10
            Start-Sleep -Seconds $(Get-Random -Minimum 1 -Maximum 5)
            try {
                Set-AppProtectionPolicy -os Windows -Id $appProtectionPolicy.id -JSON $jsonBody
            }
            catch {
                Write-Error "Failed to update $os $policyType policy - $_.Exception.Message"
                continue
            }
        }
        else {
            Write-Host "No update needed for $os $policyType policy" -ForegroundColor Yellow
        }
    }
}
#endregion
#endregion

#region teams notification
if ($teamsNotify -eq $true) {
    $teamsNotificationJSON = @{
        type      = 'AdaptiveCard'
        '$schema' = 'https://adaptivecards.io/schemas/adaptive-card.json'
        version   = '1.5'
        speak     = 'Microsoft Intune Updates'
        body      = @(
            @{
                type   = 'TextBlock'
                size   = 'Large'
                text   = 'Microsoft Intune Updates'
                weight = 'Bolder'
                wrap   = $false
            }
            @{
                type        = 'TextBlock'
                text        = "The below policies have been automatically updated at $dateTime"
                targetWidth = 'atLeast:Narrow'
                spacing     = 'Small'
                wrap        = $true
            }
            $teamsItems
        )
        msteams   = @{
            width = 'Full'
        }
    }

    $teamsNotification = $teamsNotificationJSON | ConvertTo-Json -Depth 20
    Invoke-RestMethod -Uri $teamsWebHook -Method Post -Body $teamsNotification -ContentType 'application/json'
}
#endregion