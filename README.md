# 💻 IntuneOSCompliance

The IntuneOSCompliance script is a PowerShell tool designed to automatically update operating system based compliance policies and app protection policies based on the latest supported released and updated Windows, Android, and Apple operating systems

## ⚠ Public Preview Notice

IntuneAppAssigner is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🌟 Features

Once authenticated navigate the options to bulk assign your Android, iOS/iPadOS, macOS, or Windows apps, with the following options.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows and macOS
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account

## 🔄 Updates

- **v0.1.0**
  - Initial release

## ⏯ Usage

Running the script without any parameters for interactive authentication:

```powershell
.\IntuneOSCompliance.ps1
```

OR

Run the script with the your Entra ID Tenant ID passed to the `tenantID` parameter:

```powershell
.\IntuneOSCompliance.ps1 -tenantID '437e8ffb-3030-469a-99da-e5b527908099'
```

OR

Create an Entra ID App Registration with the following Graph API Application permissions:

- `DeviceManagementApps.ReadWrite.All`
- `DeviceManagementConfiguration.Read.All`

Create an App Secret for the App Registration to be used when running the script.

Then run the script with the corresponding Microsoft Entra ID tenant ID, AppId and AppSecret passed to the parameters:

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
