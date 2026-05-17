BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Get-MDEValidationReport' {

    Context 'Object output format' {

        It 'returns array of validation result objects' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    [PSCustomObject]@{ TestName = 'Service Status'; Status = 'Pass' }
                )
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11 Enterprise 23H2' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'Intune' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Onboarded' }

            $result = Get-MDEValidationReport -OutputFormat Object

            $result | Should -Not -BeNullOrEmpty
            $result[0].Status | Should -Be 'Pass'
        }
    }

    Context 'Console output format' {

        It 'executes without error for Console format' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @([PSCustomObject]@{ TestName = 'Service Status'; Status = 'Pass'; Message = 'OK' })
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11 Enterprise' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Not Onboarded' }

            { Get-MDEValidationReport -OutputFormat Console } | Should -Not -Throw
        }
    }

    Context 'HTML output format - modernised structure' {

        BeforeAll {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    # Device State - Pass
                    [PSCustomObject]@{
                        TestName       = 'Real-Time Protection'
                        Status         = 'Pass'
                        Message        = 'Enabled'
                        Recommendation = ''
                    },
                    # Protection Settings - Fail with Recommendation
                    [PSCustomObject]@{
                        TestName       = 'Cloud Block Level'
                        Status         = 'Fail'
                        Message        = 'Low'
                        Recommendation = 'Set Cloud Block Level to High.'
                    },
                    # Network Protection - Warning
                    [PSCustomObject]@{
                        TestName       = 'Network Protection'
                        Status         = 'Warning'
                        Message        = 'Audit'
                        Recommendation = ''
                    },
                    # Info row
                    [PSCustomObject]@{
                        TestName       = 'MDE Device Tags'
                        Status         = 'Info'
                        Message        = 'No tags configured'
                        Recommendation = ''
                    },
                    # NotApplicable row
                    [PSCustomObject]@{
                        TestName       = 'Network Protection (Windows Server)'
                        Status         = 'NotApplicable'
                        Message        = 'Not a server SKU'
                        Recommendation = ''
                    },
                    # Policy Verification suffix row
                    [PSCustomObject]@{
                        TestName       = 'Real-Time Protection - Policy Registry Verification'
                        Status         = 'Pass'
                        Message        = 'Matches'
                        Recommendation = ''
                    },
                    # General / Other row (unmapped test name)
                    [PSCustomObject]@{
                        TestName       = 'Some Unmapped Test'
                        Status         = 'Pass'
                        Message        = 'ok'
                        Recommendation = ''
                    },
                    # ASR row with expander data
                    [PSCustomObject]@{
                        TestName       = 'Attack Surface Reduction Rules'
                        Status         = 'Warning'
                        Message        = '2 rules in audit'
                        Recommendation = ''
                        ASRSummary     = '5 of 16 rules in Block mode'
                        ASRRuleDetails = @('Rule A - Block', 'Rule B - Audit', 'Rule C - Block')
                    }
                )
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11 Enterprise' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Not Onboarded' }

            $tmp = Join-Path $TestDrive 'report.html'
            Get-MDEValidationReport -OutputFormat HTML -OutputPath $tmp | Out-Null
            $script:html = Get-Content $tmp -Raw
        }

        It 'renders the dark-gradient header (REPT-01)' {
            $script:html | Should -Match 'linear-gradient\(135deg,\s*#0f3460\s*0%,\s*#16213e\s*100%\)'
        }

        It 'embeds the Defender logo as base64 on the right side of the header (REPT-01, D-02)' {
            $script:html | Should -Match 'class="header-logo"'
            $script:html | Should -Match 'src="data:image/png;base64,[A-Za-z0-9+/=]{500,}"'
        }

        It 'shows Computer / OS / Managed By / MDE Onboarding / Generated in the header meta (REPT-01)' {
            foreach ($label in 'Computer:', 'OS:', 'Managed By:', 'MDE Onboarding:', 'Generated:') {
                $script:html | Should -Match ([regex]::Escape($label))
            }
        }

        It 'renders exactly 4 summary cards: Pass, Fail, Warning, Info (REPT-02)' {
            ($script:html | Select-String -Pattern 'class="summary-card ' -AllMatches).Matches.Count | Should -Be 4
            $script:html | Should -Match 'summary-card pass'
            $script:html | Should -Match 'summary-card fail'
            $script:html | Should -Match 'summary-card warn'
            $script:html | Should -Match 'summary-card info'
        }

        It 'uses Unicode status icons in place of text badges (REPT-03, D-06)' {
            $script:html | Should -Match '&#10004;'   # Pass ✔
            $script:html | Should -Match '&#10008;'   # Fail ✘
            $script:html | Should -Match '&#9888;'    # Warning ⚠
            $script:html | Should -Match '&#8505;'    # Info ℹ
            $script:html | Should -Match '&mdash;'    # NotApplicable —
        }

        It 'groups results into named section cards (REPT-04)' {
            foreach ($section in 'Device State', 'Protection Settings', 'Network Protection', 'ASR Rules', 'Policy Verification', 'General / Other') {
                $script:html | Should -Match ('<h2>\s*' + [regex]::Escape($section))
            }
        }

        It 'routes a "* - Policy Registry Verification" test into Policy Verification section (D-03 suffix rule)' {
            $script:html | Should -Match 'Real-Time Protection - Policy Registry Verification'
        }

        It 'shows per-section badge counts (REPT-05)' {
            $script:html | Should -Match 'badge badge-pass'
            $script:html | Should -Match '<h2>[^<]+<span class="badge'
        }

        It 'renders 4 table columns: Test / Expected / Actual / Status (REPT-06)' {
            $script:html | Should -Match '<th>Test</th>'
            $script:html | Should -Match '<th>Expected</th>'
            $script:html | Should -Match '<th>Actual</th>'
            $script:html | Should -Match '<th>Status</th>'
            $script:html | Should -Not -Match '<th>Details</th>'
        }

        It 'sources Expected column from the in-script lookup (REPT-06, D-05)' {
            # 'Real-Time Protection' -> 'Enabled' per Plan 01 expectedValues
            $script:html | Should -Match '<td>Enabled</td>'
            # 'Cloud Block Level' -> 'High'
            $script:html | Should -Match '<td>High</td>'
        }

        It 'shows recommendation inline below the Actual value when present (REPT-07)' {
            $script:html | Should -Match 'class="recommendation"'
            $script:html | Should -Match 'Set Cloud Block Level to High'
        }

        It 'retains the expandable ASR rule details list (REPT-08)' {
            $script:html | Should -Match 'class="expander"'
            $script:html | Should -Match 'toggleDetails\('
            $script:html | Should -Match 'Rule A - Block'
            $script:html | Should -Match 'Rule B - Audit'
        }

        It 'includes a print-friendly @media print CSS block (REPT-09)' {
            $script:html | Should -Match '@media print'
        }

        It 'HTML-encodes user-facing strings (no raw script tags in body from result data)' {
            $headStart = $script:html.IndexOf('<body>')
            $body = $script:html.Substring($headStart)
            $body | Should -Not -Match '<script'
        }
    }
}
