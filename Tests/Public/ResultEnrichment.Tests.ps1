BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Validation result enrichment (Category / Expected / Actual)' {

    Context 'Test-MDEAntiSpywareEnabled (Device State)' {
        It 'populates Category, Expected and Actual on the pass path' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntispywareEnabled $true
            }

            $result = Test-MDEAntiSpywareEnabled

            $result.Category | Should -Be 'Device State'
            $result.Expected | Should -Be 'Enabled'
            $result.Actual   | Should -Be 'Enabled'
        }
    }

    Context 'Test-MDERealTimeProtection (Device State)' {
        It 'populates Category, Expected and Actual on the pass path' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableRealtimeMonitoring $false
            }

            $result = Test-MDERealTimeProtection

            $result.Category | Should -Be 'Device State'
            $result.Expected | Should -Be 'Enabled'
            $result.Actual   | Should -Be 'Enabled'
        }
    }

    Context 'Test-MDECloudBlockLevel (Protection Settings)' {
        It 'populates Category, Expected and Actual reflecting the detected level' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudBlockLevel 2
            }

            $result = Test-MDECloudBlockLevel

            $result.Category | Should -Be 'Protection Settings'
            $result.Expected | Should -Be 'High'
            $result.Actual   | Should -Be 'High (2)'
        }
    }

    Context 'Test-MDENetworkProtection (Network Protection)' {
        It 'populates Category, Expected and Actual on the pass path' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -EnableNetworkProtection 1
            }

            $result = Test-MDENetworkProtection

            $result.Category | Should -Be 'Network Protection'
            $result.Expected | Should -Be 'Block'
            $result.Actual   | Should -Be 'Block'
        }
    }

    Context 'Test-MDESignatureAge (Protection Settings, interpolated Actual)' {
        It 'populates Category, Expected and Actual for each signature-age result' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 0 -AntispywareSignatureAge 0
            }

            $results = Test-MDESignatureAge

            foreach ($r in $results) {
                $r.Category | Should -Be 'Protection Settings'
                $r.Expected | Should -Be '0-1 days'
                $r.Actual   | Should -Be '0 day(s)'
            }
        }
    }

    Context 'Every emitted result carries a Category' {
        It 'Test-MDEServiceStatus result has a non-empty Category' {
            $result = Test-MDEServiceStatus
            $result.Category | Should -Be 'Device State'
        }
    }
}
