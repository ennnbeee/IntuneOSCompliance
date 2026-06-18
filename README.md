# 💻 IntuneOSCompliance

The IntuneOSCompliance script is a PowerShell tool designed to automatically update operating system based compliance policies and app protection policies based on the latest supported released and updated Windows, Android, and Apple operating systems.

If configured the PowerShell script will also send a rich text Microsoft Teams card to an [Incoming Microsoft Teams Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) with the results of the script run.

![Screenshot of the data sent to the Microsoft Teams incoming webhook](img/teams-ss.png)

## ⚠ Public Preview Notice

IntuneOSCompliance is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🌟 Features

- Uses APIs and RSS feed to capture the latest supported build versions for Windows, Android, and Apple devices.
- Allows you to offset your Compliance policy minimum operating system build version requirements by either n-1 or n-2.
- Allows you to offset your App Protection policy minimum operating system requirements by either n-1 or n-2.
- Detects all Compliance policies that support minimum operating system versions or minimum operating system build versions (Windows).
- Detects all App Protection policies that support minimum operating system versions for Warning, Block, and Wipe Conditional launch actions.
- For Compliance policies where the minimum operating systems are not current, updates the policy to the latest build version i.e. **26.0.1** to **26.3.1** or **10.0.26200.2356** to **10.0.26200.8246**
- For App Protection policies where the minimum operating systems are not current, updates the policy to the latest version i.e. **17.0.0** to **26.0.0** or **13.0** to **16.0.0**
- For App Protection policies with warning, block, and wipe actions will set the minimum operating system as n-1 or n-1 behind the latest supported operating system version i.e. 16.0, 15.0, 14.0 or 26.0.0, 18.0.0, 17.0.0

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows and macOS
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account

## 🔄 Updates

- **v0.1.9**
  - Allows for offset of Compliance and App protection policies operating system versions
- **v0.1.5**
  - Updated Microsoft Teams card notification method
- v0.1.4
  - Support for Windows MAM
  - Support for report only mode
- v0.1.0
  - Initial release

## ⏯ Usage

Running the script without selecting any additional parameters will run the PowerShell script in report only mode, where it will check your existing Compliance and App Protection policies

### Teams Web Hooks

To allow the PowerShell script to send details of any changes made to a Compliance or App Protection policy, you will need to create an [Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet) and use this URL when running the script.

```PowerShell
.\IntuneOSCompliance.ps1 -report $false -teamsWebHook 'http://yourteamswebhookurl.environment.api.powerplatform.com'
```

### Report Mode

Running the PowerShell script in report only mode will disable sending a Microsoft Teams Webhook and disable updating any Compliance or App Protection policy.

```PowerShell
.\IntuneOSCompliance.ps1 -report $true
```

> Report mode is on by default.

### Operating System Offset

To configure an operating system offset to allow compliance policies or app protection policies to support either 1 or 2 versions behind, you can configure the below parameters.

```PowerShell
.\IntuneOSCompliance.ps1 -report $false -complianceOffset 1 -mamOffset 2
```

> Both `complianceOffset` and  `mamOffset` are set to 0 by default.

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

Create an App Secret for the App Registration to be used when running the script.

Then run the script with the corresponding Microsoft Entra ID tenant ID, AppId and AppSecret passed to the parameters

```powershell
.\IntuneOSCompliance.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099' -appId '799ebcfa-ca81-4e63-baaf-a35123164d78' -appSecret 'g708Q~uot4xo9dU_1TjGQIuUr0UyBHNZmY2m3cy6'
```

## 🎬 Demos

TBA

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
