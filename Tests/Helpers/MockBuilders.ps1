#Requires -Version 5.1
<#
.SYNOPSIS
    Reusable mock builders for MDEValidator test suite.

.DESCRIPTION
    Provides factory functions that return property hashtables used as mock return values
    for the four external dependencies: Get-MpPreference, Get-MpComputerStatus,
    Get-Service, and Get-ItemProperty.

    Usage in tests:
        Mock Get-MpPreference -ModuleName MDEValidator { New-MpPreferenceMock }
        Mock Get-MpComputerStatus -ModuleName MDEValidator { New-MpComputerStatusMock }
        Mock Get-Service -ModuleName MDEValidator { New-ServiceMock -Name 'WinDefend' }
        Mock Get-ItemProperty -ModuleName MDEValidator { New-ItemPropertyMock }
#>

function New-MpPreferenceMock {
    <#
    .SYNOPSIS
        Returns a [PSCustomObject] representing a healthy Get-MpPreference baseline.

    .DESCRIPTION
        Defaults represent a correctly configured MDE endpoint. Use switch params to
        flip individual settings to their non-compliant state.

    .PARAMETER DisableRealtimeMonitoring
        Set $true to simulate real-time monitoring disabled.

    .PARAMETER DisableBehaviorMonitoring
        Set $true to simulate behavior monitoring disabled.

    .PARAMETER DisableBlockAtFirstSeen
        Set $true to simulate block-at-first-seen disabled.

    .PARAMETER MAPSReporting
        Override the MAPSReporting value. Default 2 (Advanced).

    .PARAMETER SubmitSamplesConsent
        Override SubmitSamplesConsent. Default 1 (Send safe samples).

    .PARAMETER CloudBlockLevel
        Override CloudBlockLevel. Default 2 (High).

    .PARAMETER CloudExtendedTimeout
        Override CloudExtendedTimeout. Default 50.

    .PARAMETER AllowNetworkProtectionOnWinServer
        Override AllowNetworkProtectionOnWinServer. Default $false.

    .PARAMETER EnableNetworkProtection
        Override EnableNetworkProtection. Default 1 (Enabled).

    .EXAMPLE
        # Healthy baseline
        Mock Get-MpPreference -ModuleName MDEValidator { New-MpPreferenceMock }

        # Simulate real-time monitoring disabled
        Mock Get-MpPreference -ModuleName MDEValidator { New-MpPreferenceMock -DisableRealtimeMonitoring $true }
    #>
    [OutputType([PSCustomObject])]
    param(
        [bool]$DisableRealtimeMonitoring       = $false,
        [bool]$DisableBehaviorMonitoring       = $false,
        [bool]$DisableBlockAtFirstSeen         = $false,
        [int]$MAPSReporting                    = 2,
        [int]$SubmitSamplesConsent             = 1,
        [int]$CloudBlockLevel                  = 2,
        [int]$CloudExtendedTimeout             = 50,
        [bool]$AllowNetworkProtectionOnWinServer = $false,
        [int]$EnableNetworkProtection          = 1,
        [bool]$DisableScanningNetworkFiles     = $false,
        [bool]$DisableArchiveScanning          = $false,
        [bool]$DisableCatchupQuickScan         = $true,
        [int]$RealTimeScanDirection            = 0,
        [string]$SignatureUpdateFallbackOrder  = 'MicrosoftUpdateServer|MMPC',
        [int]$SignatureUpdateInterval          = 4,
        [bool]$DisableLocalAdminMerge          = $true,
        [bool]$EnableControlledFolderAccess    = $false,
        [bool]$PUAProtection                   = $false
    )

    [PSCustomObject]@{
        DisableRealtimeMonitoring         = $DisableRealtimeMonitoring
        DisableBehaviorMonitoring         = $DisableBehaviorMonitoring
        DisableBlockAtFirstSeen           = $DisableBlockAtFirstSeen
        MAPSReporting                     = $MAPSReporting
        SubmitSamplesConsent              = $SubmitSamplesConsent
        CloudBlockLevel                   = $CloudBlockLevel
        CloudExtendedTimeout              = $CloudExtendedTimeout
        AllowNetworkProtectionOnWinServer = $AllowNetworkProtectionOnWinServer
        EnableNetworkProtection           = $EnableNetworkProtection
        DisableScanningNetworkFiles       = $DisableScanningNetworkFiles
        DisableArchiveScanning            = $DisableArchiveScanning
        DisableCatchupQuickScan           = $DisableCatchupQuickScan
        RealTimeScanDirection             = $RealTimeScanDirection
        SignatureUpdateFallbackOrder      = $SignatureUpdateFallbackOrder
        SignatureUpdateInterval           = $SignatureUpdateInterval
        DisableLocalAdminMerge            = $DisableLocalAdminMerge
        EnableControlledFolderAccess      = $EnableControlledFolderAccess
        PUAProtection                     = $PUAProtection
    }
}


function New-MpComputerStatusMock {
    <#
    .SYNOPSIS
        Returns a [PSCustomObject] representing a healthy Get-MpComputerStatus baseline.

    .DESCRIPTION
        Defaults represent a correctly running MDE endpoint. Override individual
        properties to simulate unhealthy states.

    .PARAMETER AMServiceEnabled
        Whether the AM service is enabled. Default $true.

    .PARAMETER AntispywareEnabled
        Whether antispyware is enabled. Default $true.

    .PARAMETER AntivirusEnabled
        Whether antivirus is enabled. Default $true.

    .PARAMETER RealTimeProtectionEnabled
        Whether real-time protection is on. Default $true.

    .PARAMETER AntispywareSignatureAge
        Signature age in days. Default 0.

    .PARAMETER AntivirusSignatureAge
        AV signature age in days. Default 0.

    .PARAMETER NISSignatureAge
        NIS signature age in days. Default 0.

    .PARAMETER OnboardingState
        MDE onboarding state. Default 1 (Onboarded).

    .PARAMETER DefenderSignaturesOutOfDate
        Whether signatures are out of date. Default $false.

    .EXAMPLE
        Mock Get-MpComputerStatus -ModuleName MDEValidator { New-MpComputerStatusMock }

        # Simulate AM service disabled
        Mock Get-MpComputerStatus -ModuleName MDEValidator { New-MpComputerStatusMock -AMServiceEnabled $false }
    #>
    [OutputType([PSCustomObject])]
    param(
        [bool]$AMServiceEnabled             = $true,
        [bool]$AntispywareEnabled           = $true,
        [bool]$AntivirusEnabled             = $true,
        [bool]$RealTimeProtectionEnabled    = $true,
        [bool]$BehaviorMonitorEnabled       = $true,
        [bool]$IoavProtectionEnabled        = $true,
        [int]$AntispywareSignatureAge       = 0,
        [int]$AntivirusSignatureAge         = 0,
        [int]$NISSignatureAge               = 0,
        [int]$OnboardingState               = 1,
        [bool]$DefenderSignaturesOutOfDate  = $false,
        [bool]$TamperProtectionSource       = $true,
        [string]$AMProductVersion           = '4.18.24040.4',
        [string]$AMEngineVersion            = '1.1.24040.4'
    )

    [PSCustomObject]@{
        AMServiceEnabled            = $AMServiceEnabled
        AntispywareEnabled          = $AntispywareEnabled
        AntivirusEnabled            = $AntivirusEnabled
        RealTimeProtectionEnabled   = $RealTimeProtectionEnabled
        BehaviorMonitorEnabled      = $BehaviorMonitorEnabled
        IoavProtectionEnabled       = $IoavProtectionEnabled
        AntispywareSignatureAge     = $AntispywareSignatureAge
        AntivirusSignatureAge       = $AntivirusSignatureAge
        NISSignatureAge             = $NISSignatureAge
        OnboardingState             = $OnboardingState
        DefenderSignaturesOutOfDate = $DefenderSignaturesOutOfDate
        TamperProtectionSource      = $TamperProtectionSource
        AMProductVersion            = $AMProductVersion
        AMEngineVersion             = $AMEngineVersion
    }
}


function New-ServiceMock {
    <#
    .SYNOPSIS
        Returns a [PSCustomObject] representing a Get-Service result.

    .DESCRIPTION
        Useful for mocking WinDefend, Sense, MsSense, and other Windows services.

    .PARAMETER Name
        The service name. Default 'WinDefend'.

    .PARAMETER Status
        The service status (Running, Stopped, etc.). Default 'Running'.

    .PARAMETER StartType
        The service start type (Automatic, Manual, Disabled). Default 'Automatic'.

    .PARAMETER DisplayName
        The display name of the service. Default 'Windows Defender Antivirus Service'.

    .EXAMPLE
        Mock Get-Service -ModuleName MDEValidator { New-ServiceMock }

        # Simulate stopped service
        Mock Get-Service -ModuleName MDEValidator {
            New-ServiceMock -Name 'WinDefend' -Status 'Stopped'
        }

        # Simulate MsSense service
        Mock Get-Service -ModuleName MDEValidator {
            New-ServiceMock -Name 'MsSense' -DisplayName 'Windows Defender Advanced Threat Protection Service'
        }
    #>
    [OutputType([PSCustomObject])]
    param(
        [string]$Name        = 'WinDefend',
        [string]$Status      = 'Running',
        [string]$StartType   = 'Automatic',
        [string]$DisplayName = 'Windows Defender Antivirus Service'
    )

    [PSCustomObject]@{
        Name        = $Name
        Status      = $Status
        StartType   = $StartType
        DisplayName = $DisplayName
    }
}


function New-ItemPropertyMock {
    <#
    .SYNOPSIS
        Returns a [PSCustomObject] representing a Get-ItemProperty registry result.

    .DESCRIPTION
        Used to mock registry reads for policy and configuration values.
        Build a hashtable of property names and values matching what your function
        expects, then wrap it in [PSCustomObject].

    .PARAMETER Properties
        A hashtable of registry property names and values.
        Default returns a sparse policy-compliant baseline with common keys.

    .EXAMPLE
        # Default baseline (compliant registry state)
        Mock Get-ItemProperty -ModuleName MDEValidator { New-ItemPropertyMock }

        # Custom registry values
        Mock Get-ItemProperty -ModuleName MDEValidator {
            New-ItemPropertyMock -Properties @{
                DisableRealtimeMonitoring = 0
                PUAProtection             = 1
            }
        }
    #>
    [OutputType([PSCustomObject])]
    param(
        [hashtable]$Properties = @{
            DisableRealtimeMonitoring  = 0
            DisableBehaviorMonitoring  = 0
            MAPSReporting              = 2
            SubmitSamplesConsent       = 1
            CloudBlockLevel            = 2
            CloudExtendedTimeout       = 50
            EnableNetworkProtection    = 1
            PUAProtection              = 1
            DisableLocalAdminMerge     = 1
        }
    )

    [PSCustomObject]$Properties
}


Export-ModuleMember -Function New-MpPreferenceMock, New-MpComputerStatusMock, New-ServiceMock, New-ItemPropertyMock
