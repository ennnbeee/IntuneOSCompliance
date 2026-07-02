#Requires -Version 7
<#PSScriptInfo

.VERSION 0.3.0
.GUID 5101b3d0-e968-4607-8b90-2562bfcb703f
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Android iOS macOS Apps Compliance
.LICENSEURI https://github.com/ennnbeee/IntuneOSCompliance/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/IntuneOSCompliance
.ICONURI https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/win-com.png
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.3.0 - Updated to support Device Platform Restrictions
v0.2.0 - Teams notification in report mode and highlighting of end-of-life operating system versions in policies
v0.1.9 - Updated to Windows build function as Microsoft changed the format of their update feed
v0.1.8 - Minor formatting updates
v0.1.7 - Added support for n-1 on versions for App Protection policies
v0.1.6 - Added notification for operating systems no longer supported
v0.1.5 - Updated notification logic to group updates
v0.1.4 - Combined notifications for Windows builds and app protection policies
v0.1.3 - Logo and output formatting updates
v0.1.2 - Updated logo source and formatting
v0.1.1 - Added support for Windows App Protection policies and Windows 10
v0.1.0 - Initial release.

.PRIVATEDATA
#>
<#
.SYNOPSIS
Updates Microsoft Intune device compliance and app protection policies to ensure the minimum operating system build versions are up to date.

.DESCRIPTION
Uses available APIs to check the latest available OS builds for supported platforms and compares these to the minimum OS build versions configured in Intune device compliance and app protection policies. If any policies are found to be out of date, they can be automatically updated with the latest build numbers.

.PARAMETER report
Set to $true to only report out of date policies in the console output without making any changes. Default is $true.

.PARAMETER teamsWebHook
Provide the Microsoft Teams webhook URL to send notifications to. If not provided, notifications will not be sent.
https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook

.PARAMETER complianceOffset
Specify whether Compliance policies require the latest version of the operating system or a version behind the latest (e.g. n-1). Default is 0 (latest version).

.PARAMETER mamOffset
Specify whether App Protection policies require the latest version of the operating system or a version behind the latest (e.g. n-1). Default is 0 (latest version).

.PARAMETER compliance
Specify whether compliance policies should be in scope of updates. Default is $true (compliance policies will be updated).

.PARAMETER appProtection
Specify whether app protection policies should be in scope of updates. Default is $true (app protection policies will be updated).

.PARAMETER platformRestrictions
Specify whether platform restrictions should be in scope of updates. Default is $false (platform restrictions will not be updated).

.PARAMETER tenantId
Provide the Id of the Entra ID tenant to connect to.

.PARAMETER appId
Provide the Id of the Entra App registration to be used for authentication.

.PARAMETER appSecret
Provide the App secret to allow for authentication to graph

.EXAMPLE
Interactive Authentication with no policy changes or notifications, just reporting out of date policies in the console output.
.\IntuneOSCompliance.ps1 -report $false

.EXAMPLE
Interactive Authentication with no policy changes reporting out of date policies in the console output and through the Teams webhook.
.\IntuneOSCompliance.ps1 -teamsWebHook 'https://customwebhookurl'

.EXAMPLE
Interactive Authentication with no policy changes or notifications, just reporting out of date policies in the console output.
Compliance policies wil be updated to two updates behind the latest version and App Protection policies will be updated to one update behind the latest version.
.\IntuneOSCompliance.ps1 -report $false -complianceOffset 2 -mamOffset 1

.EXAMPLE
Pass through Authentication with policy changes and Microsoft Teams notifications enabled.
.\IntuneOSCompliance.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099' -report $false -teamsWebHook 'https://customwebhookurl'

.EXAMPLE
App Authentication with policy changes and Microsoft Teams notifications enabled.
.\IntuneOSCompliance.ps1 -tenantId '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e72-baaf-a35126464d67' -appSecret 'g708Q~uof4xo9dU_1EjGQIuUr0UyBHNZmY2m3dy6' -report $false -teamsWebHook 'https://customwebhookurl'

#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(

    [Parameter(Mandatory = $false, HelpMessage = 'Sets whether compliance policies are in scope of updates')]
    [bool]$compliance = $true,

    [Parameter(Mandatory = $false, HelpMessage = 'Sets whether app protection policies are in scope of updates')]
    [bool]$appProtection = $true,

    [Parameter(Mandatory = $false, HelpMessage = 'Sets whether platform restrictions are in scope of updates')]
    [bool]$platformRestrictions = $false,

    [Parameter(Mandatory = $false, HelpMessage = 'Sets whether policy changes are made or just reported in the console output')]
    [bool]$report = $true,

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the Microsoft Teams webhook URL to send notifications to')]
    [String]$teamsWebHook,

    [Parameter(Mandatory = $false, HelpMessage = 'Specify whether Compliance policies require the latest version of the operating system or a minor version behind the latest (e.g. n-1)')]
    [ValidateRange(0, 2)]
    [int]$complianceOffset = 0,

    [Parameter(Mandatory = $false, HelpMessage = 'Specify whether App Protection policies require the latest version of the operating system or a major version behind the latest (e.g. n-1)')]
    [ValidateRange(0, 2)]
    [int]$mamOffset = 0,

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
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('iOS', 'Android', 'Windows', 'macOS')]
        [string]$os
    )

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

        switch ($os) {
            'iOS' { $results = $results | Where-Object { $_.'@odata.type' -like '*ios*' } }
            'Android' { $results = $results | Where-Object { $_.'@odata.type' -like '*android*' } }
            'Windows' { $results = $results | Where-Object { $_.'@odata.type' -like '*windows*' } }
            'macOS' { $results = $results | Where-Object { $_.'@odata.type' -like '*macos*' } }
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
    if ($PSCmdlet.ShouldProcess('Compliance policy', 'Update')) {
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
        Write-Output "Compliance policy $Id would have been updated"
    }
    else {
        Write-Output "Compliance policy $Id was not updated"
    }

}
function Get-EnrolmentPlatformRestriction {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('iOS', 'Android', 'Windows', 'macOS')]
        [string]$os
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceEnrollmentConfigurations'

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
        $results = $results | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration' -or $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration' }
        switch ($os) {
            'iOS' { $results = $results | Where-Object { $_.platformType -eq 'ios' -or $_.priority -eq '0' } }
            'Android' { $results = $results | Where-Object { $_.platformType -eq 'androidForWork' -or $_.priority -eq '0' } }
            'Windows' { $results = $results | Where-Object { $_.platformType -eq 'windows' -or $_.priority -eq '0' } }
            'macOS' { $results = $results | Where-Object { $_.platformType -eq 'mac' -or $_.priority -eq '0' } }
        }
        $results
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
function Set-EnrolmentPlatformRestriction() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]
    param
    (
        [Parameter(Mandatory = $true)]
        $Id,

        [Parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $resource = "deviceManagement/deviceEnrollmentConfigurations/$id"
    if ($PSCmdlet.ShouldProcess('Enrolment platform restriction', 'Update')) {
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
        Write-Output "Enrolment platform restriction $Id would have been updated"
    }
    else {
        Write-Output "Enrolment platform restriction $Id was not updated"
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

    if ($PSCmdlet.ShouldProcess('App Protection policy', 'Update')) {
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
        Write-Output "App Protection policy $Id would have been updated"
    }
    else {
        Write-Output "App Protection policy $Id was not updated"
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
            if ($osUpdate.title.'#text' -like "*$osVersion*" -and $osUpdate.title.'#text' -notlike '*Preview*' -and $osUpdate.title.'#text' -notlike '*Out-of-band*') {
                $buildVersions += $($osUpdate.title.'#text')
            }
        }
        $osBuildVersions = @()
        foreach ($build in $buildVersions) {
            $buildVersion = $build.Substring($build.LastIndexOf('.')) -replace '[^0-9]'
            $osBuildVersions += '10.0.' + $osVersion + '.' + $buildVersion
        }

        $osBuildVersionsOrdered = $osBuildVersions | Select-Object -Unique | Sort-Object -Descending
        return $osBuildVersionsOrdered
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
                $buildVersions += ($Update.title -split ' ')[-1]
            }
        }

        return $buildVersions
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

        $rowMatches = [regex]::Matches($tableHtml, '(?is)<tr[^>]*>\s*<td[^>]*>.*?</tr>')
        if ($rowMatches.Count -eq 0) { throw 'Could not find any data rows in the security bulletin table.' }

        $patchLevels = @()
        foreach ($row in $rowMatches) {
            $cells = [regex]::Matches($row.Value, '(?is)<td[^>]*>(?<cell>.*?)</td>') | ForEach-Object { $_.Groups['cell'].Value }
            if ($cells.Count -lt 4) { continue }
            $dates = [regex]::Matches($cells[3], '\b\d{4}-\d{2}-\d{2}\b') | ForEach-Object { $_.Value }
            if ($dates.Count -lt 1) { continue }
            $patchLevels += ([datetime]$dates[0]).ToString('yyyy-MM-dd')
        }

        if ($patchLevels.Count -eq 0) { throw 'Could not find any patch level dates in the security bulletin table.' }

        return $patchLevels
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
        [ValidateSet('iOS', 'Android', 'Windows', 'macOS')]
        [string]$os,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Business', 'Consumer')]
        [string]$sku

    )

    switch ($os) {
        'Windows' { $Resource = 'products/windows' }
        'macOS' { $Resource = 'products/macos' }
        'Android' { $Resource = 'products/android' }
        'iOS' { $Resource = 'products/ipados' }
    }

    try {
        $uri = "https://endoflife.date/api/v1/$($Resource)"
        $eolResults = Invoke-RestMethod -Uri $uri -Method Get
        $results = $eolResults.result.releases

        if ($os -eq 'Windows') {
            if ($sku -eq 'Consumer') {
                $filteredResults = $results | Where-Object { $_.name -notlike '*lts*' -and $_.name -notlike '*-e*' -and $_.name -notlike '*26h1*' } | Select-Object -Property name, label, isEol, @{Name = 'LatestName'; Expression = { $_.latest.name } }
            }
            else {
                $filteredResults = $results | Where-Object { $_.name -notlike '*lts*' -and $_.name -notlike '*-w*' -and $_.name -notlike '*26h1*' } | Select-Object -Property name, label, isEol, @{Name = 'LatestName'; Expression = { $_.latest.name } }
            }

        }
        else {
            $filteredResults = $results | Select-Object -Property name, label, isEol, @{Name = 'LatestName'; Expression = { $_.latest.name } }
        }

        return $filteredResults
    }
    catch {
        Write-Error $_.Exception.Message
        throw
    }
}
#endregion

#region variables
$androidCompliance = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/and-com.png'
$androidMAM = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/and-mam.png'
$iOSCompliance = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/ios-com.png'
$iOSMAM = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/ios-mam.png'
$windowsCompliance = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/win-com.png'
$windowsMAM = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/win-mam.png'
$macOSCompliance = 'https://raw.githubusercontent.com/ennnbeee/IntuneOSCompliance/refs/heads/main/img/mac-com.png'

$scopes = @()
if ($compliance -eq $true) {
    $scopes += 'DeviceManagementApps.ReadWrite.All'
}
if ($appProtection -eq $true) {
    $scopes += 'DeviceManagementApps.ReadWrite.All'
}
if ($platformRestrictions -eq $true) {
    $scopes += 'DeviceManagementServiceConfig.ReadWrite.All'
}

$teamsItems = @()
$dateTime = Get-Date -Format 'HH:mm:ss dd/MM/yyyy'
$rndWait = Get-Random -Minimum 1 -Maximum 2
$noticeText = switch ($report) {
    $true { 'should be updated from' }
    $false { 'updated from' }
}
#endregion

#region intro
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
Write-Host ' | Version' -NoNewline; Write-Host ' 0.3.0 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2026-07-02' -ForegroundColor Magenta
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
if ($compliance -eq $true) {
    $policyType = 'Compliance'

    #region Windows
    $os = 'Windows'
    $osImageUrl = $windowsCompliance
    $windowsCompliancePolicies = Get-DeviceCompliancePolicy -os Windows | Where-Object { ($_.validOperatingSystemBuildRanges -ne $null -or $_.osMinimumVersion -ne $null) }
    if ($null -ne $windowsCompliancePolicies) {
        Write-Host "`n`nFound $($windowsCompliancePolicies.Count) $os $policyType policies with operating system build ranges or minimum versions." -ForegroundColor Magenta
        $windowsSupported = Get-EndOfLifeDate -os Windows
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
            $version = $_
            $windowsBuilds += [PSCustomObject]@{
                version     = $version
                latestBuild = $(Get-WindowsUpdateBuild -osVersion $version)[$complianceOffset]
                isEol       = $windowsSupported | Where-Object { $_.LatestName -like "*$($version)*" } | Select-Object -ExpandProperty isEol
            }
        }

        foreach ($compliancePolicy in $windowsCompliancePolicies) {
            $policyChange = $false
            $minVersion = $null
            $policyDisplayName = $compliancePolicy.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan

            # OS minimum version check
            if (![string]::IsNullOrEmpty($compliancePolicy.osMinimumVersion)) {
                $minVersion = $compliancePolicy.osMinimumVersion
                $osVersion = $minVersion.Split('.')[2]
                $latestBuild = $windowsBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
                $buildEol = $windowsBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty isEol
                # end of life but up to date
                if ($buildEol -eq $true -and $null -ne $latestBuild -and $latestBuild -eq $minVersion) {
                    Write-Host "$os $policyType policy with $os $('10.0.' + $osVersion) is end-of-life and should be removed from the policy" -ForegroundColor Red
                    $updateItems += @{text = "$os $('10.0.' + $osVersion) is end-of-life and should be removed from the policy"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                    $policyChange = $true
                }

                if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                    $policyChange = $true
                    $compliancePolicy.osMinimumVersion = $latestBuild

                    if ($buildEol -eq $true) {
                        Write-Host "$os $policyType policy with $os $('10.0.' + $osVersion) (end-of-life) $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                        $updateItems += @{text = "$os $('10.0.' + $osVersion) (end-of-life) $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                    }
                    else {
                        Write-Host "$os $policyType policy with $os $('10.0.' + $osVersion) $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                        $updateItems += @{text = "$os $('10.0.' + $osVersion) $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                    }
                }
            }

            # Valid operating system build ranges check
            if (![string]::IsNullOrEmpty($compliancePolicy.validOperatingSystemBuildRanges)) {
                $minVersion = $null
                foreach ($buildRange in $compliancePolicy.validOperatingSystemBuildRanges) {
                    $minVersion = $buildRange.lowestVersion
                    $osVersion = $minVersion.Split('.')[2]
                    $latestBuild = $windowsBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
                    $buildEol = $windowsBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty isEol
                    # end of life but up to date
                    if ($buildEol -eq $true -and $null -ne $latestBuild -and $latestBuild -eq $minVersion) {
                        Write-Host "$os $policyType policy with $os $('10.0.' + $osVersion) is end-of-life and should be removed from the policy" -ForegroundColor Red
                        $updateItems += @{text = "$os $('10.0.' + $osVersion) is end-of-life and should be removed from the policy"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                        $policyChange = $true
                    }

                    if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                        $policyChange = $true
                        $buildRange.lowestVersion = $latestBuild

                        if ($buildEol -eq $true) {
                            Write-Host "$os $policyType policy with $os $('10.0.' + $osVersion) (end-of-life) $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                            $updateItems += @{text = "$os $('10.0.' + $osVersion) (end-of-life) $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                        }
                        else {
                            Write-Host "$os $policyType policy with $os $('10.0.' + $osVersion) $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                            $updateItems += @{text = "$os $('10.0.' + $osVersion) $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                        }
                    }
                }
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $false) {
                Write-Host "Updating $os $policyType policy" -ForegroundColor Magenta
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
            elseif ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy needs updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy is up-to-date" -ForegroundColor Green
            }
        }
    }
    #endregion

    #region macOS
    $os = 'macOS'
    $osImageUrl = $macOSCompliance
    $macOSCompliancePolicies = Get-DeviceCompliancePolicy -os macOS | Where-Object { $_.osMinimumVersion -ne $null }
    if ($null -ne $macOSCompliancePolicies) {
        Write-Host "`n`nFound $($macOSCompliancePolicies.Count) $os $policyType policies with Minimum OS Version." -ForegroundColor Magenta
        $macOSSupported = Get-EndOfLifeDate -os macOS
        $macOSVersions = @()
        $macOSBuilds = @()

        $macOSCompliancePolicies.osMinimumVersion | ForEach-Object {
            $macOSVersions += $_.Split('.')[0]
        }

        $macOSVersions | Sort-Object -Unique | ForEach-Object {
            $version = $_
            $macOSBuilds += [PSCustomObject]@{
                version     = $version
                latestBuild = (Get-AppleUpdateBuild -OS 'macOS' -osVersion $version)[$complianceOffset]
                isEol       = $macOSSupported | Where-Object { $_.name -eq $version } | Select-Object -ExpandProperty isEol
            }
        }

        foreach ($compliancePolicy in $macOSCompliancePolicies) {
            $policyChange = $false
            $policyDisplayName = $compliancePolicy.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minVersion = $compliancePolicy.osMinimumVersion
            $osVersion = $minVersion.Split('.')[0]
            $latestBuild = $macOSBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
            $buildEol = $macOSBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty isEol
            # end of life but up to date
            if ($buildEol -eq $true -and $null -ne $latestBuild -and $latestBuild -eq $minVersion) {
                Write-Host "$os $policyType policy with $os $osVersion is end-of-life and should be removed from the policy" -ForegroundColor Red
                $updateItems += @{text = "$os $osVersion is end-of-life and should be removed from the policy"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $policyChange = $true
            }

            if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                $policyChange = $true
                $compliancePolicy.osMinimumVersion = $latestBuild
                if ($buildEol -eq $true) {
                    Write-Host "$os $policyType policy with $os $osVersion (end-of-life) $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                    $updateItems += @{text = "$os $osVersion (end-of-life) $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                }
                else {
                    Write-Host "$os $policyType policy with $os $osVersion $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                    $updateItems += @{text = "$os $osVersion $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                }
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $false) {
                Write-Host "Updating $os $policyType policy" -ForegroundColor Magenta
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
            elseif ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy needs updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy is up-to-date" -ForegroundColor Green
            }
        }
    }
    #endregion

    #region iOS/iPadOS
    $os = 'iOS/iPadOS'
    $osImageUrl = $iOSCompliance
    $iOSCompliancePolicies = Get-DeviceCompliancePolicy -os iOS | Where-Object { $_.osMinimumVersion -ne $null }
    if ($null -ne $iOSCompliancePolicies) {
        Write-Host "`n`nFound $($iOSCompliancePolicies.Count) $os $policyType policies with Minimum OS Version." -ForegroundColor Magenta
        $iOSSupported = Get-EndOfLifeDate -os iOS
        $iOSVersions = @()
        $iOSBuilds = @()

        $iOSCompliancePolicies.osMinimumVersion | ForEach-Object {
            $iOSVersions += $_.Split('.')[0]
        }

        $iOSVersions | Sort-Object -Unique | ForEach-Object {
            $version = $_
            $iOSBuilds += [PSCustomObject]@{
                version     = $version
                latestBuild = (Get-AppleUpdateBuild -OS 'iOS' -osVersion $version)[$complianceOffset]
                isEol       = $iOSSupported | Where-Object { $_.name -eq $version } | Select-Object -ExpandProperty isEol
            }
        }

        foreach ($compliancePolicy in $iOSCompliancePolicies) {
            $policyChange = $false
            $policyDisplayName = $compliancePolicy.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minVersion = $compliancePolicy.osMinimumVersion
            $osVersion = $minVersion.Split('.')[0]
            $latestBuild = $iOSBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty latestBuild
            $buildEol = $iOSBuilds | Where-Object { $_.version -eq $osVersion } | Select-Object -ExpandProperty isEol
            if ($buildEol -eq $true -and $null -ne $latestBuild -and $latestBuild -eq $minVersion) {
                Write-Host "$os $policyType policy with $os $osVersion is end-of-life and should be removed from the policy" -ForegroundColor Red
                $updateItems += @{text = "$os $osVersion is end-of-life and should be removed from the policy"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $policyChange = $true
            }

            if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                $policyChange = $true
                $compliancePolicy.osMinimumVersion = $latestBuild
                if ($buildEol -eq $true) {
                    Write-Host "$os $policyType policy with $os $osVersion (end-of-life) $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                    $updateItems += @{text = "$os $osVersion (end-of-life) $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                }
                else {
                    Write-Host "$os $policyType policy with $os $osVersion $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                    $updateItems += @{text = "$os $osVersion $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                }
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $false) {
                Write-Host "Updating $os $policyType policy" -ForegroundColor Magenta
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
            elseif ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy needs updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy is up-to-date" -ForegroundColor Green
            }
        }
    }
    #endregion

    #region Android
    $os = 'Android'
    $osImageUrl = $androidCompliance
    $androidCompliancePolicies = Get-DeviceCompliancePolicy -os Android | Where-Object { $_.osMinimumVersion -ne $null }
    if ($null -ne $androidCompliancePolicies) {
        Write-Host "`n`nFound $($androidCompliancePolicies.Count) $os $policyType policies with Minimum OS Version." -ForegroundColor Magenta
        $androidSupported = Get-EndOfLifeDate -os Android
        $androidVersions = @()
        $androidBuilds = @()
        $androidPatch = Get-AndroidUpdateBuild

        $androidCompliancePolicies.osMinimumVersion | ForEach-Object {
            $androidVersions += $_
        }

        $androidVersions | Sort-Object -Unique | ForEach-Object {
            $version = $_
            $androidBuilds += [PSCustomObject]@{
                version     = $version
                latestBuild = $androidPatch[$complianceOffset]
                isEol       = $androidSupported | Where-Object { $($_.name + '.0') -eq "$version" -or $_.name -eq "$version" } | Select-Object -ExpandProperty isEol
            }
        }

        foreach ($compliancePolicy in $androidCompliancePolicies) {
            $policyChange = $false
            $policyDisplayName = $compliancePolicy.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $osVersion = $compliancePolicy.osMinimumVersion
            $minVersion = $compliancePolicy.minAndroidSecurityPatchLevel
            $latestBuild = $androidBuilds | Where-Object { $_.version -eq $compliancePolicy.osMinimumVersion } | Select-Object -ExpandProperty latestBuild
            $buildEol = $androidBuilds | Where-Object { $_.version -eq $compliancePolicy.osMinimumVersion } | Select-Object -ExpandProperty isEol
            if ($buildEol -eq $true -and $null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                Write-Host "$os $policyType policy with $os $osVersion is end-of-life and should be removed from the policy" -ForegroundColor Red
                $updateItems += @{text = "$os $osVersion is end-of-life and should be removed from the policy"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $policyChange = $true
            }

            if ($null -ne $latestBuild -and $latestBuild -ne $minVersion) {
                $policyChange = $true
                $compliancePolicy.minAndroidSecurityPatchLevel = $latestBuild

                if ($buildEol -eq $true) {
                    Write-Host "$os $policyType policy with $os $osVersion (end-of-life) $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                    $updateItems += @{text = "$os $osVersion (end-of-life) $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }

                }
                else {
                    Write-Host "$os $policyType policy with $os $osVersion $noticeText $minVersion to $latestBuild" -ForegroundColor Yellow
                    $updateItems += @{text = "$os $osVersion $noticeText $minVersion to $latestBuild"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                }
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $false) {
                Write-Host "Updating $os $policyType policy" -ForegroundColor Magenta
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
            elseif ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy needs updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy is up-to-date" -ForegroundColor Green
            }
        }
    }
    #endregion
}
#endregion

#region mam
if ($appProtection -eq $true) {
    $policyType = 'App Protection'

    #region Windows
    $os = 'Windows'
    $osImageUrl = $windowsMAM
    $windowsAppProtectionPolicies = Get-AppProtectionPolicy -os Windows | Where-Object { $_.minimumRequiredOsVersion -ne $null -or $_.minimumWarningOsVersion -ne $null -or $_.minimumWipeOsVersion -ne $null }
    if ($null -ne $windowsAppProtectionPolicies) {
        Write-Host "`n`nFound $($windowsAppProtectionPolicies.Count) $os $policyType policies with minimum OS version requirements." -ForegroundColor Magenta
        $windowsSupported = Get-EndOfLifeDate -os Windows -sku Consumer
        $newWarning = "$($windowsSupported.LatestName[$mamOffset]).0"
        $newRequired = "$($windowsSupported.LatestName[$mamOffset + 1]).0"
        $newWipe = "$($windowsSupported.LatestName[$mamOffset + 2]).0"

        foreach ($appProtectionPolicy in $windowsAppProtectionPolicies) {
            $policyChange = $false
            $policyDisplayName = $appProtectionPolicy.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minRequired = $appProtectionPolicy.minimumRequiredOsVersion
            $minWarning = $appProtectionPolicy.minimumWarningOsVersion
            $minWipe = $appProtectionPolicy.minimumWipeOsVersion

            if ($null -ne $minWarning -and $minWarning -ne $newWarning) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS warning from $minWarning to $newWarning" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum warning OS version $noticeText $minWarning to $newWarning"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumWarningOsVersion = $newWarning
            }

            if ($null -ne $minRequired -and $minRequired -ne $newRequired) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS required from $minRequired to $newRequired" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum required OS version $noticeText $minRequired to $newRequired"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumRequiredOsVersion = $newRequired
            }

            if ($null -ne $minWipe -and $minWipe -ne $newWipe) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS wipe from $minWipe to $newWipe" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum wipe OS version $noticeText $minWipe to $newWipe"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumWipeOsVersion = $newWipe
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $false) {

                Write-Host "Updating $os $policyType policy" -ForegroundColor Magenta
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
            elseif ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy does need updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy does not need updating" -ForegroundColor Green
            }
        }
    }
    #endregion

    #region iOS/iPadOS
    $os = 'iOS/iPadOS'
    $osImageUrl = $iOSMAM
    $iOSAppProtectionPolicies = Get-AppProtectionPolicy -os iOS | Where-Object { $_.minimumRequiredOsVersion -ne $null -or $_.minimumWarningOsVersion -ne $null }
    if ($null -ne $iOSAppProtectionPolicies) {
        Write-Host "`n`nFound $($iOSAppProtectionPolicies.Count) $os $policyType policies with minimum OS version requirements." -ForegroundColor Magenta
        $iOSSupported = Get-EndOfLifeDate -os iOS
        $newWarning = "$($iOSSupported.label[$mamOffset]).0.0"
        $newRequired = "$($iOSSupported.label[$mamOffset + 1]).0.0"
        $newWipe = "$($iOSSupported.label[$mamOffset + 2]).0.0"

        foreach ($appProtectionPolicy in $iOSAppProtectionPolicies) {
            $policyChange = $false
            $policyDisplayName = $appProtectionPolicy.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minWarning = $appProtectionPolicy.minimumWarningOsVersion
            $minRequired = $appProtectionPolicy.minimumRequiredOsVersion
            $minWipe = $appProtectionPolicy.minimumWipeOsVersion

            if ($null -ne $minWarning -and $minWarning -ne $newWarning) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS warning from $minWarning to $newWarning" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum warning OS version $noticeText $minWarning to $newWarning"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumWarningOsVersion = $newWarning
            }
            if ($null -ne $minRequired -and $minRequired -ne $newRequired) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS required from $minRequired to $newRequired" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum required OS version $noticeText $minRequired to $newRequired"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumRequiredOsVersion = $newRequired
            }
            if ($null -ne $minWipe -and $minWipe -ne $newWipe) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS wipe from $minWipe to $newWipe" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum wipe OS version $noticeText $minWipe to $newWipe"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumWipeOsVersion = $newWipe
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $false) {

                Write-Host "Updating $os $policyType policy" -ForegroundColor Magenta
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
            elseif ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy does need updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy does not need updating" -ForegroundColor Green
            }
        }
    }
    #endregion

    #region Android
    $os = 'Android'
    $osImageUrl = $androidMAM
    $androidAppProtectionPolicies = Get-AppProtectionPolicy -os Android | Where-Object { $_.minimumRequiredOsVersion -ne $null -or $_.minimumWarningOsVersion -ne $null }
    if ($null -ne $androidAppProtectionPolicies) {
        Write-Host "`n`nFound $($androidAppProtectionPolicies.Count) $os $policyType policies with minimum OS version requirements." -ForegroundColor Magenta
        $androidSupported = Get-EndOfLifeDate -os Android
        $newWarning = "$($androidSupported.name[$mamOffset]).0"
        $newRequired = "$($androidSupported.name[$mamOffset + 1]).0"
        $newWipe = "$($androidSupported.name[$mamOffset + 2]).0"

        foreach ($appProtectionPolicy in $androidAppProtectionPolicies) {
            $policyChange = $false
            $policyDisplayName = $appProtectionPolicy.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minWarning = $appProtectionPolicy.minimumWarningOsVersion
            $minRequired = $appProtectionPolicy.minimumRequiredOsVersion
            $minWipe = $appProtectionPolicy.minimumWipeOsVersion

            if ($null -ne $minWarning -and $minWarning -ne $newWarning) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS warning from $minWarning to $newWarning" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum warning OS version $noticeText $minWarning to $newWarning"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumWarningOsVersion = $newWarning
            }

            if ($null -ne $minRequired -and $minRequired -ne $newRequired) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS required from $minRequired to $newRequired" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum required OS version $noticeText $minRequired to $newRequired"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumRequiredOsVersion = $newRequired
            }

            if ($null -ne $minWipe -and $minWipe -ne $newWipe) {
                $policyChange = $true
                Write-Host "$os $policyType policy will be updated for minOS wipe from $minWipe to $newWipe" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum wipe OS version $noticeText $minWipe to $newWipe"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $appProtectionPolicy.minimumWipeOsVersion = $newWipe
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $false) {

                Write-Host "Updating $os $policyType policy" -ForegroundColor Magenta
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
            elseif ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy does need updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy does not need updating" -ForegroundColor Green
            }
        }
    }
    #endregion
}
#endregion

#region platform restrictions
if ($platformRestrictions -eq $true) {
    $policyType = 'Enrolment Platform Restriction'

    #region Windows
    $os = 'Windows'
    $osImageUrl = $windowsMAM
    $windowsPlatformRestrictions = Get-EnrolmentPlatformRestriction -os Windows | Where-Object { ($_.platformRestriction.personalDeviceEnrollmentBlocked -eq $false -and $null -ne $_.platformRestriction.osMinimumVersion) -or ($_.windowsRestriction.personalDeviceEnrollmentBlocked -eq $false -and $null -ne $_.windowsRestriction.osMinimumVersion) }
    if ($null -ne $windowsPlatformRestrictions) {
        Write-Host "`n`nFound $($windowsPlatformRestrictions.Count) $os $policyType policies allowing BYOD enrolment." -ForegroundColor Magenta
        $windowsSupported = Get-EndOfLifeDate -os Windows -sku Consumer | Where-Object { $_.isEol -eq $false }
        $newMinOS = "$($windowsSupported[-1].LatestName).0000"
        $newMaxOS = "$($windowsSupported[0].LatestName).9999"

        foreach ($platformRestriction in $windowsPlatformRestrictions) {
            $policyChange = $false
            $policyDisplayName = $platformRestriction.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minOS = $platformRestriction.platformRestriction.osMinimumVersion
            $maxOS = $platformRestriction.platformRestriction.osMaximumVersion

            if ($minOS -ne $newMinOS) {
                $policyChange = $true
                Write-Host "$os $policyType policy should be updated for minOS $minOS to $newMinOS" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum OS version **should be updated** from $minOS to $newMinOS"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $platformRestriction.platformRestriction.osMinimumVersion = $newMinOS
            }

            if ($maxOS -ne $newMaxOS) {
                $policyChange = $true
                Write-Host "$os $policyType policy should be updated for maxOS $maxOS to $newMaxOS" -ForegroundColor Yellow
                $updateItems += @{text = "Maximum OS version **should be updated** from $maxOS to $newMaxOS"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $platformRestriction.platformRestriction.osMaximumVersion = $newMaxOS
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy does need updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy does not need updating" -ForegroundColor Green
            }
        }
    }
    #endregion

    #region iOS/iPadOS
    $os = 'iOS/iPadOS'
    $osImageUrl = $iOSMAM
    $iOSPlatformRestrictions = Get-EnrolmentPlatformRestriction -os iOS | Where-Object { ($_.platformRestriction.personalDeviceEnrollmentBlocked -eq $false -and $null -ne $_.platformRestriction.osMinimumVersion) -or ($_.iosRestriction.personalDeviceEnrollmentBlocked -eq $false -and $null -ne $_.iosRestriction.osMinimumVersion) }
    if ($null -ne $iOSPlatformRestrictions) {
        Write-Host "`n`nFound $($iOSPlatformRestrictions.Count) $os $policyType policies allowing BYOD enrolment." -ForegroundColor Magenta
        $iOSSupported = Get-EndOfLifeDate -os iOS | Where-Object { $_.isEol -eq $false }
        $newMinOS = "$($iOSSupported[-1].label).0.0"
        $newMaxOS = "$($iOSSupported[0].label).99.99"

        foreach ($platformRestriction in $iOSPlatformRestrictions) {
            $policyChange = $false
            $policyDisplayName = $platformRestriction.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minOS = $platformRestriction.platformRestriction.osMinimumVersion
            $maxOS = $platformRestriction.platformRestriction.osMaximumVersion

            if ($minOS -ne $newMinOS) {
                $policyChange = $true
                Write-Host "$os $policyType policy should be updated for minOS $minOS to $newMinOS" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum OS version **should be updated** from $minOS to $newMinOS"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $platformRestriction.platformRestriction.osMinimumVersion = $newMinOS
            }

            if ($maxOS -ne $newMaxOS) {
                $policyChange = $true
                Write-Host "$os $policyType policy should be updated for maxOS $maxOS to $newMaxOS" -ForegroundColor Yellow
                $updateItems += @{text = "Maximum OS version **should be updated** from $maxOS to $newMaxOS"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $platformRestriction.platformRestriction.osMaximumVersion = $newMaxOS
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy does need updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy does not need updating" -ForegroundColor Green
            }
        }
    }
    #endregion

    #region Android
    $os = 'Android'
    $osImageUrl = $androidMAM
    $androidPlatformRestrictions = Get-EnrolmentPlatformRestriction -os Android | Where-Object { ($_.platformRestriction.personalDeviceEnrollmentBlocked -eq $false -and $null -ne $_.platformRestriction.osMinimumVersion) -or ($_.androidForWorkRestriction.personalDeviceEnrollmentBlocked -eq $false -and $null -ne $_.androidForWorkRestriction.osMinimumVersion) }
    if ($null -ne $androidPlatformRestrictions) {
        Write-Host "`n`nFound $($androidPlatformRestrictions.Count) $os $policyType policies allowing BYOD enrolment." -ForegroundColor Magenta
        $androidSupported = Get-EndOfLifeDate -os Android | Where-Object { $_.isEol -eq $false }
        $newMinOS = "$($androidSupported[-1].name).0.0"
        $newMaxOS = "$($androidSupported[0].name).99.99"

        foreach ($platformRestriction in $androidPlatformRestrictions) {
            $policyChange = $false
            $policyDisplayName = $platformRestriction.displayName
            $updateItems = @()
            $updateItems += @{isSubtle = $true ; size = 'Small'; text = "$policyType - $os"; wrap = $true ; type = 'TextBlock' }
            $updateItems += @{text = "$policyDisplayName"; weight = 'Bolder'; wrap = $true; type = 'TextBlock'; spacing = 'None' }
            Write-Host "`nChecking $os $policyType policy - $policyDisplayName" -ForegroundColor Cyan
            $minOS = $platformRestriction.platformRestriction.osMinimumVersion
            $maxOS = $platformRestriction.platformRestriction.osMaximumVersion

            if ($minOS -ne $newMinOS) {
                $policyChange = $true
                Write-Host "$os $policyType policy should be updated for minOS $minOS to $newMinOS" -ForegroundColor Yellow
                $updateItems += @{text = "Minimum OS version **should be updated** from $minOS to $newMinOS"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $platformRestriction.platformRestriction.osMinimumVersion = $newMinOS
            }

            if ($maxOS -ne $newMaxOS) {
                $policyChange = $true
                Write-Host "$os $policyType policy should be updated for maxOS $maxOS to $newMaxOS" -ForegroundColor Yellow
                $updateItems += @{text = "Maximum OS version **should be updated** from $maxOS to $newMaxOS"; wrap = $true; type = 'TextBlock'; spacing = 'None' }
                $platformRestriction.platformRestriction.osMaximumVersion = $newMaxOS
            }

            if ($policyChange -eq $true) {
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
                                    items = $updateItems
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

            if ($policyChange -eq $true -and $report -eq $true) {
                Write-Host "$os $policyType policy does need updating" -ForegroundColor Red
            }
            elseif ($policyChange -eq $false -and $report -eq $true) {
                Write-Host "$os $policyType policy does not need updating" -ForegroundColor Green
            }
        }
    }
    #endregion
}
#endregion

#region teams notification
if (![string]::IsNullOrEmpty($teamsWebHook) -and $teamsItems.Count -ne 0) {
    if ($report -eq $false) {
        $description = "The below policies have been automatically updated at $dateTime"
    }
    else {
        $description = "The below policies need updating as of $dateTime"
    }

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
                text        = "$description"
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

    try {
        $teamsNotification = $teamsNotificationJSON | ConvertTo-Json -Depth 20
        Invoke-RestMethod -Uri $teamsWebHook -Method Post -Body $teamsNotification -ContentType 'application/json'
    }
    catch {
        Write-Error "Failed to send Teams notification - $_.Exception.Message"
        exit 1
    }
}
#endregion