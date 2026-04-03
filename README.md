# App Permission Info

[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

PowerShell report script for Microsoft Entra applications and enterprise apps.

## What this script does

- Collects App Registrations and Enterprise Apps (service principals).
- Includes key identity metadata:
  - ReportObjectType
  - ApplicationDisplayName
  - ApplicationId
  - TenantObjectId
  - SignInAudience
  - ServicePrincipalType
  - IsManagedIdentity
- Includes credential info:
  - HasSecrets
  - SecretCount
- Includes permission data:
  - ConfiguredApiPermissions (for app registrations)
  - GrantedApplicationPermissions
  - GrantedDelegatedPermissions
- Exports CSV by default.
- Optionally generates an interactive HTML report with search and filters.

## Prerequisites

Install Microsoft Graph PowerShell modules:

- Microsoft.Graph.Authentication
- Microsoft.Graph.Applications
- Microsoft.Graph.Identity.SignIns

The script connects to Graph and requests these scopes:

- Application.Read.All
- AppRoleAssignment.Read.All
- DelegatedPermissionGrant.Read.All

## Script file

Invoke-AppPermissionInfo.ps1

## Parameters

- ReportPath
  - CSV output path.
  - Default: AppPermissionReport.csv in the script folder.
- GenerateHtmlReport
  - Switch to enable HTML report generation.
- HtmlReportPath
  - Optional HTML output path.
  - If omitted, uses the same base name as ReportPath with .html extension.

## Usage examples

Run with default CSV output:

./Invoke-AppPermissionInfo.ps1

Run with custom CSV output:

./Invoke-AppPermissionInfo.ps1 -ReportPath "C:\Temp\AppPermissions.csv"

Run with CSV and HTML output:

./Invoke-AppPermissionInfo.ps1 -ReportPath "C:\Temp\AppPermissions.csv" -GenerateHtmlReport -HtmlReportPath "C:\Temp\AppPermissions.html"

## Output notes

- Terminal output shows current processing progress only.
- Full data is written to CSV.
- HTML report supports:
  - Search across all columns
  - Filter by object type
  - Filter by secrets
  - Filter by managed identity

## View help

Get script help:

Get-Help ./Invoke-AppPermissionInfo.ps1 -Full
