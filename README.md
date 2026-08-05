# 💻 IntuneOSCompliance

The IntuneOSCompliance script is a PowerShell tool designed to automatically update operating system based [compliance policies](https://learn.microsoft.com/en-us/intune/device-security/compliance/overview), [app protection](https://learn.microsoft.com/en-us/intune/app-management/overview) policies, and detail updates required to [device enrolment platform restrictions](https://learn.microsoft.com/en-us/intune/device-enrollment/restrictions) based on the latest supported released and updated Windows, Android, and Apple operating systems.

If configured the PowerShell script will also send a rich text Microsoft Teams card to an [Incoming Microsoft Teams Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) with the results of the script run.

## Compliance Updates

![Screenshot of the data sent to the Microsoft Teams incoming webhook](img/teams-ss-compliance.jpg)

## App Protection Updates

![Screenshot of the data sent to the Microsoft Teams incoming webhook](img/teams-ss-mam.png)

## Device Enrolment Platform Restriction Updates

![Screenshot of the data sent to the Microsoft Teams incoming webhook](img/teams-ss-platform.png)

## ⚠ Public Preview Notice

IntuneOSCompliance is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🌟 Features

- Uses APIs and RSS feeds to capture the latest supported build versions for Windows, Android, and Apple devices.
- Detects all Compliance policies that support minimum operating system versions or minimum operating system build versions (Windows).
- Detects all App Protection policies that support minimum operating system versions for Warning, Block, and Wipe Conditional launch actions.
- Detects all Device Enrolment Platform Restrictions that support personal device enrolment and minOS or maxOS settings
- For Compliance policies where the minimum operating systems are not current, updates the policy to the latest build version i.e. **26.0.1** to **26.3.1** or **10.0.26200.2356** to **10.0.26200.8246**
- For App Protection policies where the minimum operating systems are not current, updates the policy to the latest version i.e. **17.0.0** to **26.0.0** or **13.0** to **16.0.0**
- For App Protection policies with warning, block, and wipe actions will set the minimum operating system as n-1/n-2 behind the latest supported operating system version i.e. 16.0, 15.0, 14.0 or 26.0.0, 18.0.0, 17.0.0
- Allows you to offset your Compliance policy minimum operating system build version requirements by either n-1 or n-2 e.g. macOS 26.5.0 instead of 26.5.1
- Allows you to offset your App Protection policy minimum operating system requirements by either n-1 or n-2 e.g. Android 16 instead of Android 17
- Warns you if a compliance policy contains unsupported operating systems.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows and macOS
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Microsoft Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account

## 🔄 Updates

- **v0.5.0**
  - Moved to using Graph for Windows Update build information as Microsoft have retired the Atom RSS feeds.
  - The paramter `useGraphForWindowsUpdates` is set to `true` by default, ensure Graph permissions have been updated to support `WindowsUpdates.Read.All`
- v0.4.0
  - Option to use Graph API for Windows Updates data as is a maintained source compared to the Atom feed.
  - Use the `useGraphForWindowsUpdates` boolean parameter to use Graph API, additional permissions are required to `WindowsUpdates.Read.All`
- v0.3.0
  - Updated to support the review of Device Enrolment Platform Restrictions (no changes are made), you will need to add `DeviceManagementServiceConfig.ReadWrite.All` to the App Registration permissions
  - Added parameters to support including or excluding policy types
- v0.2.0
  - If a Teams Webhook is provided, report mode will send a notification of policies that need updating.
  - Identifies and notifies of end-of-life operating systems.
  - Uses consumer Windows editions (Home, Pro) for Windows MAM supported operating system versions.
- v0.1.9
  - Allows for offset of Compliance and App protection policies operating system versions.
- v0.1.5
  - Updated Microsoft Teams card notification method.
- v0.1.4
  - Support for Windows MAM.
  - Support for report only mode.
- v0.1.0
  - Initial release.

## ⏯ Usage

Running the script without selecting any additional parameters will run the PowerShell script in report only mode, where it will check your existing Compliance, App Protection policies, and Device Platform Enrolment Restrictions.

### Teams Web Hooks

To allow the PowerShell script to send details of any changes made to a Compliance or App Protection policy, you will need to create an [Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet) and use this URL when running the script.

```PowerShell
.\IntuneOSCompliance.ps1 -report $false -teamsWebHook 'http://yourteamswebhookurl.environment.api.powerplatform.com'
```

### Report Mode

Running the PowerShell script in report only mode (on by default) will not update any Compliance or App Protection policy but output whether policies require updating in the console.

```PowerShell
.\IntuneOSCompliance.ps1
```

### Report Mode and Teams Web Hook

Running the PowerShell script in report only mode (on by default) will send a Microsoft Teams Webhook notification detailing any updates required but not update any Compliance or App Protection policy.

```PowerShell
.\IntuneOSCompliance.ps1 -teamsWebHook 'http://yourteamswebhookurl.environment.api.powerplatform.com'
```

![Screenshot of the data sent to the Microsoft Teams incoming webhook](img/teams-ss-report.png)

### Operating System Offset

To configure an operating system offset to allow compliance policies or app protection policies to support either 1 or 2 versions behind, you can configure the below parameters.

```PowerShell
.\IntuneOSCompliance.ps1 -report $false -complianceOffset 1 -mamOffset 2
```

> Both `complianceOffset` and  `mamOffset` are set to 0 by default.
> Compliance uses minor/build OS versions, app protection use major OS versions

### Authentication

Running the script without any parameters for interactive authentication

```powershell
.\IntuneOSCompliance.ps1
```

OR

Run the script with the your Entra ID Tenant ID passed to the `tenantID` parameter

```powershell
.\IntuneOSCompliance.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099'
```

OR

Create an Entra ID App Registration with the following Graph API Application permissions:

- `DeviceManagementApps.ReadWrite.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementServiceConfig.ReadWrite.All`

Create an App Secret for the App Registration to be used when running the script.

Then run the script with the corresponding Microsoft Entra ID tenant ID, App Id and App Secret passed to the parameters

```powershell
.\IntuneOSCompliance.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e63-baaf-a35123164d78' -appSecret 'g708Q~uot4xo9dU_1TjGQIuUr0UyBHNZmY2m3cy6'
```

## Automation

To allow for the PowerShell script to be run on a schedule, you can use GitHub actions or Azure DevOps pipelines to download and run the script with configured parameters.

### GitHub Actions

Use the `GHA-IntuneOSCompliance.yml` in the automation directory as a reference to create a new [GitHub Action](https://github.com/features/actions). You will need to update the script parameters for `complianceOffset` and `mamOffset`.

Create [GitHub repository secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets) for the following after creating a new Microsoft Entra ID app registration:

- `TENANT_ID` - Microsoft Entra ID tenant Id
- `APP_ID` - App registration client Id
- `APP_SECRET` - A registration client secret
- `TEAMS_WEBHOOK` - Teams Webhook URI

### Azure DevOps

Use the `ADO-IntuneOSCompliance.yml` in the automation directory as a reference to create a new [Azure DevOps pipeline](https://azure.microsoft.com/en-us/products/devops/pipelines). You will need to update the script parameters for `complianceOffset` and `mamOffset`.

Create [pipeline variables](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch) for the following after creating a new Microsoft Entra ID app registration:

- `TENANT_ID` - Microsoft Entra ID tenant Id
- `APP_ID` - App registration client Id
- `APP_SECRET` - A registration client secret
- `TEAMS_WEBHOOK` - Teams Webhook URI

## 🎬 Demos

![Screenshot of a run of IntuneOSCompliance in Azure Dev Ops](img/ado-ss-run.png)

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/IntuneOSCompliance/issues) page
2. Open a new issue if needed

- 📝 [Submit Feedback](https://github.com/ennnbeee/IntuneOSCompliance/issues/new?labels=feedback)
- 🐛 [Report Bugs](https://github.com/ennnbeee/IntuneOSCompliance/issues/new?labels=bug)
- 💡 [Request Features](https://github.com/ennnbeee/IntuneOSCompliance/issues/new?labels=enhancement)

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
