
<#
.SYNOPSIS
Generates a Microsoft Entra application permissions report for app registrations and enterprise apps.

.DESCRIPTION
Retrieves app registrations and enterprise apps (service principals), then collects sign-in audience,
configured permissions, granted application/delegated permissions, and secret presence.
Exports results to CSV and can optionally generate an interactive HTML report.

.PARAMETER ReportPath
Path to the CSV report output file.

.PARAMETER GenerateHtmlReport
When specified, also generates an interactive, searchable, filterable HTML report.

.PARAMETER HtmlReportPath
Optional output path for the HTML report. If not provided, the script uses the same base name as
ReportPath with an .html extension.

.EXAMPLE
.\Invoke-AppPermissionInfo.ps1

.EXAMPLE
.\Invoke-AppPermissionInfo.ps1 -ReportPath "C:\Temp\AppPermissions.csv" -GenerateHtmlReport

.NOTES
Copyright (c) 2026 Mathias Borowicz.
Licensed under GNU General Public License v3.0 (GPL-3.0).
#>

# Requires modules:
#   Microsoft.Graph.Authentication
#   Microsoft.Graph.Applications
#   Microsoft.Graph.Identity.SignIns

param(
    [string]$ReportPath = (Join-Path -Path $PSScriptRoot -ChildPath "AppPermissionReport.csv"),
    [switch]$GenerateHtmlReport,
    [string]$HtmlReportPath
)

$ErrorActionPreference = "Stop"

$requiredScopes = @(
    "Application.Read.All",
    "AppRoleAssignment.Read.All",
    "DelegatedPermissionGrant.Read.All"
)

try {
    $ctx = Get-MgContext
    if (-not $ctx) {
        Connect-MgGraph -Scopes $requiredScopes | Out-Null
    }
}
catch {
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
}

$resourceSpCache = @{}

function Get-ResourceServicePrincipal {
    param(
        [Parameter(Mandatory)]
        [string]$ServicePrincipalId
    )

    if (-not $resourceSpCache.ContainsKey($ServicePrincipalId)) {
        $resourceSpCache[$ServicePrincipalId] = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalId -Property "id,appId,displayName,appRoles,oauth2PermissionScopes"
    }

    return $resourceSpCache[$ServicePrincipalId]
}

function Get-ResourceServicePrincipalByAppId {
    param(
        [Parameter(Mandatory)]
        [string]$AppId
    )

    $resourceSp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -Property "id,appId,displayName,appRoles,oauth2PermissionScopes" | Select-Object -First 1
    if ($resourceSp -and -not $resourceSpCache.ContainsKey($resourceSp.Id)) {
        $resourceSpCache[$resourceSp.Id] = $resourceSp
    }

    return $resourceSp
}

function Convert-ToHtmlSafe {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode($Value) -replace "`r?`n", "<br>"
}

$apps = Get-MgApplication -All -Property "id,appId,displayName,signInAudience,passwordCredentials,requiredResourceAccess"
$results = [System.Collections.Generic.List[object]]::new()
$appCount = ($apps | Measure-Object).Count
$appIndex = 0

foreach ($app in $apps) {
    try {
        $appIndex += 1
        Write-Progress -Activity "Processing app registrations" -Status "$appIndex / $appCount : $($app.DisplayName)" -PercentComplete (($appIndex / [Math]::Max($appCount, 1)) * 100)

        $secretCount = ($app.PasswordCredentials | Measure-Object).Count
        $hasSecrets = $secretCount -gt 0

        $configuredPermissions = [System.Collections.Generic.List[string]]::new()
        $applicationPermissionGrants = [System.Collections.Generic.List[string]]::new()
        $delegatedPermissionGrants = [System.Collections.Generic.List[string]]::new()

        foreach ($requiredResource in $app.RequiredResourceAccess) {
            $resourceSp = Get-ResourceServicePrincipalByAppId -AppId $requiredResource.ResourceAppId
            $resourceName = if ($resourceSp -and $resourceSp.DisplayName) { $resourceSp.DisplayName } else { $requiredResource.ResourceAppId }

            foreach ($resourceAccess in $requiredResource.ResourceAccess) {
                $permissionName = $resourceAccess.Id

                if ($resourceSp) {
                    if ($resourceAccess.Type -eq "Role") {
                        $appRole = $resourceSp.AppRoles | Where-Object { $_.Id -eq $resourceAccess.Id } | Select-Object -First 1
                        if ($appRole -and $appRole.Value) {
                            $permissionName = $appRole.Value
                        }
                    }
                    elseif ($resourceAccess.Type -eq "Scope") {
                        $scope = $resourceSp.Oauth2PermissionScopes | Where-Object { $_.Id -eq $resourceAccess.Id } | Select-Object -First 1
                        if ($scope -and $scope.Value) {
                            $permissionName = $scope.Value
                        }
                    }
                }

                $configuredPermissions.Add($resourceName + ':' + $permissionName + ' (' + $resourceAccess.Type + ')')
            }
        }

        $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -Property "id,displayName" | Select-Object -First 1

        if ($servicePrincipal) {
            $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id -All
            foreach ($assignment in $appRoleAssignments) {
                $resourceSp = Get-ResourceServicePrincipal -ServicePrincipalId $assignment.ResourceId
                $appRole = $resourceSp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId } | Select-Object -First 1
                $permissionName = if ($appRole -and $appRole.Value) { $appRole.Value } else { $assignment.AppRoleId }
                $applicationPermissionGrants.Add("$($resourceSp.DisplayName):$permissionName")
            }

            $oauth2Grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($servicePrincipal.Id)'" -All
            foreach ($grant in $oauth2Grants) {
                $resourceSp = Get-ResourceServicePrincipal -ServicePrincipalId $grant.ResourceId
                foreach ($scope in ($grant.Scope -split " ")) {
                    if ($scope) {
                        $delegatedPermissionGrants.Add("$($resourceSp.DisplayName):$scope")
                    }
                }
            }
        }

        $results.Add([PSCustomObject]@{
            ReportObjectType               = "AppRegistration"
            ApplicationDisplayName          = $app.DisplayName
            ApplicationId                   = $app.AppId
            TenantObjectId                 = $app.Id
            SignInAudience                  = $app.SignInAudience
            ServicePrincipalType           = ""
            IsManagedIdentity              = $false
            HasSecrets                      = $hasSecrets
            SecretCount                     = $secretCount
            ConfiguredApiPermissions        = (($configuredPermissions | Sort-Object -Unique) -join "`n")
            GrantedApplicationPermissions   = (($applicationPermissionGrants | Sort-Object -Unique) -join "`n")
            GrantedDelegatedPermissions     = (($delegatedPermissionGrants | Sort-Object -Unique) -join "`n")
        })
    }
    catch {
        Write-Warning "Failed processing app '$($app.DisplayName)' ($($app.AppId)): $($_.Exception.Message)"
    }
}

$enterpriseApps = Get-MgServicePrincipal -All -Property "id,appId,displayName,signInAudience,passwordCredentials,servicePrincipalType"
$enterpriseAppCount = ($enterpriseApps | Measure-Object).Count
$enterpriseAppIndex = 0

foreach ($enterpriseApp in $enterpriseApps) {
    try {
        $enterpriseAppIndex += 1
        Write-Progress -Activity "Processing enterprise apps" -Status "$enterpriseAppIndex / $enterpriseAppCount : $($enterpriseApp.DisplayName)" -PercentComplete (($enterpriseAppIndex / [Math]::Max($enterpriseAppCount, 1)) * 100)

        $secretCount = ($enterpriseApp.PasswordCredentials | Measure-Object).Count
        $hasSecrets = $secretCount -gt 0
        $isManagedIdentity = $enterpriseApp.ServicePrincipalType -eq "ManagedIdentity"

        $applicationPermissionGrants = [System.Collections.Generic.List[string]]::new()
        $delegatedPermissionGrants = [System.Collections.Generic.List[string]]::new()

        $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $enterpriseApp.Id -All
        foreach ($assignment in $appRoleAssignments) {
            $resourceSp = Get-ResourceServicePrincipal -ServicePrincipalId $assignment.ResourceId
            $appRole = $resourceSp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId } | Select-Object -First 1
            $permissionName = if ($appRole -and $appRole.Value) { $appRole.Value } else { $assignment.AppRoleId }
            $applicationPermissionGrants.Add("$($resourceSp.DisplayName):$permissionName")
        }

        $oauth2Grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($enterpriseApp.Id)'" -All
        foreach ($grant in $oauth2Grants) {
            $resourceSp = Get-ResourceServicePrincipal -ServicePrincipalId $grant.ResourceId
            foreach ($scope in ($grant.Scope -split " ")) {
                if ($scope) {
                    $delegatedPermissionGrants.Add("$($resourceSp.DisplayName):$scope")
                }
            }
        }

        $results.Add([PSCustomObject]@{
            ReportObjectType               = "EnterpriseApp"
            ApplicationDisplayName         = $enterpriseApp.DisplayName
            ApplicationId                  = $enterpriseApp.AppId
            TenantObjectId                 = $enterpriseApp.Id
            SignInAudience                 = $enterpriseApp.SignInAudience
            ServicePrincipalType           = $enterpriseApp.ServicePrincipalType
            IsManagedIdentity              = $isManagedIdentity
            HasSecrets                     = $hasSecrets
            SecretCount                    = $secretCount
            ConfiguredApiPermissions       = ""
            GrantedApplicationPermissions  = (($applicationPermissionGrants | Sort-Object -Unique) -join "`n")
            GrantedDelegatedPermissions    = (($delegatedPermissionGrants | Sort-Object -Unique) -join "`n")
        })
    }
    catch {
        Write-Warning "Failed processing enterprise app '$($enterpriseApp.DisplayName)' ($($enterpriseApp.AppId)): $($_.Exception.Message)"
    }
}

Write-Progress -Activity "Processing app registrations" -Completed
Write-Progress -Activity "Processing enterprise apps" -Completed

$results |
    Sort-Object ReportObjectType, ApplicationDisplayName |
    Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

Write-Host "CSV report exported to: $ReportPath"

if ($GenerateHtmlReport) {
        if (-not $HtmlReportPath) {
                $HtmlReportPath = [System.IO.Path]::ChangeExtension($ReportPath, ".html")
        }

        $sortedResults = $results | Sort-Object ReportObjectType, ApplicationDisplayName

        $rowsHtml = foreach ($row in $sortedResults) {
            $isManagedIdentityValue = if ($row.PSObject.Properties.Match("IsManagedIdentity").Count -gt 0 -and $null -ne $row.IsManagedIdentity) { $row.IsManagedIdentity.ToString().ToLowerInvariant() } else { "false" }
            "<tr data-type='" + (Convert-ToHtmlSafe $row.ReportObjectType) + "' data-secrets='" + $row.HasSecrets.ToString().ToLowerInvariant() + "' data-managed-identity='" + $isManagedIdentityValue + "'>" +
                "<td>" + (Convert-ToHtmlSafe $row.ReportObjectType) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.ApplicationDisplayName) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.ApplicationId) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.TenantObjectId) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.SignInAudience) + "</td>" +
            "<td>" + (Convert-ToHtmlSafe $row.ServicePrincipalType) + "</td>" +
            "<td>" + (Convert-ToHtmlSafe $row.IsManagedIdentity) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.HasSecrets) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.SecretCount) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.ConfiguredApiPermissions) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.GrantedApplicationPermissions) + "</td>" +
                "<td>" + (Convert-ToHtmlSafe $row.GrantedDelegatedPermissions) + "</td>" +
                "</tr>"
        }

        $html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>App Permission Report</title>
    <style>
        :root {
            --bg: #f6f8fb;
            --panel: #ffffff;
            --text: #17202a;
            --muted: #5f6b7a;
            --accent: #0b66c3;
            --border: #d7dee7;
            --ok: #1a7f37;
            --warn: #b54708;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Segoe UI, Tahoma, sans-serif;
            background: linear-gradient(180deg, #eef3f9 0%, var(--bg) 250px);
            color: var(--text);
        }
        .container {
            max-width: 1800px;
            margin: 24px auto;
            padding: 0 16px;
        }
        .panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 8px 20px rgba(14, 30, 53, 0.08);
            overflow: hidden;
        }
        header {
            padding: 20px;
            border-bottom: 1px solid var(--border);
        }
        h1 {
            margin: 0;
            font-size: 24px;
        }
        .sub {
            margin-top: 6px;
            color: var(--muted);
            font-size: 13px;
        }
        .filters {
            padding: 16px 20px;
            display: grid;
            grid-template-columns: 1.7fr 1fr 1fr;
            gap: 12px;
            border-bottom: 1px solid var(--border);
        }
        input, select {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 14px;
            background: #fff;
            color: var(--text);
        }
        .table-wrap {
            overflow: auto;
            max-height: 72vh;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 1500px;
        }
        thead th {
            position: sticky;
            top: 0;
            background: #f2f6fb;
            z-index: 1;
            text-align: left;
            font-size: 12px;
            letter-spacing: 0.02em;
            text-transform: uppercase;
            color: #354355;
            border-bottom: 1px solid var(--border);
            padding: 10px;
        }
        tbody td {
            border-bottom: 1px solid #ecf1f6;
            padding: 10px;
            vertical-align: top;
            font-size: 13px;
            line-height: 1.45;
            white-space: pre-wrap;
            word-break: break-word;
        }
        tbody tr:hover {
            background: #f9fbfe;
        }
        .hidden {
            display: none;
        }
        .summary {
            padding: 12px 20px;
            color: var(--muted);
            font-size: 13px;
            border-top: 1px solid var(--border);
        }
        .badge-true { color: var(--warn); font-weight: 600; }
        .badge-false { color: var(--ok); font-weight: 600; }
        @media (max-width: 900px) {
            .filters { grid-template-columns: 1fr; }
            h1 { font-size: 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="panel">
            <header>
                <h1>Application and Enterprise App Permission Report</h1>
                <div class="sub">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
            </header>
            <div class="filters">
                <input id="searchInput" type="search" placeholder="Search all columns...">
                <select id="typeFilter">
                    <option value="">All object types</option>
                    <option value="AppRegistration">AppRegistration</option>
                    <option value="EnterpriseApp">EnterpriseApp</option>
                </select>
                <select id="secretFilter">
                    <option value="">Has secrets: Any</option>
                    <option value="true">Has secrets: True</option>
                    <option value="false">Has secrets: False</option>
                </select>
                <select id="managedIdentityFilter">
                    <option value="">Managed identity: Any</option>
                    <option value="true">Managed identity: True</option>
                    <option value="false">Managed identity: False</option>
                </select>
            </div>
            <div class="table-wrap">
                <table id="reportTable">
                    <thead>
                        <tr>
                            <th>ObjectType</th>
                            <th>DisplayName</th>
                            <th>ApplicationId</th>
                            <th>TenantObjectId</th>
                            <th>SignInAudience</th>
                              <th>ServicePrincipalType</th>
                              <th>IsManagedIdentity</th>
                            <th>HasSecrets</th>
                            <th>SecretCount</th>
                            <th>ConfiguredApiPermissions</th>
                            <th>GrantedApplicationPermissions</th>
                            <th>GrantedDelegatedPermissions</th>
                        </tr>
                    </thead>
                    <tbody>
                        $($rowsHtml -join "`n")
                    </tbody>
                </table>
            </div>
            <div class="summary" id="summary"></div>
        </div>
    </div>
    <script>
        (function () {
            const searchInput = document.getElementById('searchInput');
            const typeFilter = document.getElementById('typeFilter');
            const secretFilter = document.getElementById('secretFilter');
            const managedIdentityFilter = document.getElementById('managedIdentityFilter');
            const rows = Array.from(document.querySelectorAll('#reportTable tbody tr'));
            const summary = document.getElementById('summary');

            function refresh() {
                const term = (searchInput.value || '').trim().toLowerCase();
                const typeValue = typeFilter.value;
                const secretValue = secretFilter.value;
                const managedIdentityValue = managedIdentityFilter.value;
                let visible = 0;

                rows.forEach(function (row) {
                    const rowText = row.innerText.toLowerCase();
                    const rowType = row.getAttribute('data-type') || '';
                    const rowSecrets = row.getAttribute('data-secrets') || '';
                      const rowManagedIdentity = row.getAttribute('data-managed-identity') || '';

                    const matchesText = !term || rowText.indexOf(term) !== -1;
                    const matchesType = !typeValue || rowType === typeValue;
                    const matchesSecrets = !secretValue || rowSecrets === secretValue;
                      const matchesManagedIdentity = !managedIdentityValue || rowManagedIdentity === managedIdentityValue;
                      const show = matchesText && matchesType && matchesSecrets && matchesManagedIdentity;

                    row.classList.toggle('hidden', !show);

                    if (show) {
                        visible += 1;
                        const hasSecretsCell = row.children[5];
                        hasSecretsCell.className = (rowSecrets === 'true') ? 'badge-true' : 'badge-false';
                    }
                });

                summary.textContent = 'Showing ' + visible + ' of ' + rows.length + ' rows';
            }

            searchInput.addEventListener('input', refresh);
            typeFilter.addEventListener('change', refresh);
            secretFilter.addEventListener('change', refresh);
            managedIdentityFilter.addEventListener('change', refresh);
            refresh();
        })();
    </script>
</body>
</html>
"@

        Set-Content -Path $HtmlReportPath -Value $html -Encoding UTF8
        Write-Host "HTML report exported to: $HtmlReportPath"
}