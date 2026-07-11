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

    Context 'JSON output format' {

        BeforeAll {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    [PSCustomObject]@{
                        TestName       = 'Real-Time Protection'
                        Category       = 'Device State'
                        Status         = 'Pass'
                        Message        = 'Enabled'
                        Expected       = 'Enabled'
                        Actual         = 'Enabled'
                        Recommendation = ''
                        Timestamp      = [datetime]'2026-01-15T10:00:00'
                    },
                    [PSCustomObject]@{
                        TestName       = 'Cloud Block Level'
                        Category       = 'Protection Settings'
                        Status         = 'Fail'
                        Message        = 'Low'
                        Expected       = 'High'
                        Actual         = 'Low'
                        Recommendation = 'Set to High'
                        Timestamp      = [datetime]'2026-01-15T10:00:01'
                    },
                    [PSCustomObject]@{
                        TestName       = 'Network Protection'
                        Category       = 'Network Protection'
                        Status         = 'Warning'
                        Message        = 'Audit only'
                        Expected       = 'Block'
                        Actual         = 'Audit'
                        Recommendation = ''
                        Timestamp      = [datetime]'2026-01-15T10:00:02'
                    }
                )
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11 Enterprise' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'Intune' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Onboarded' }
        }

        It 'returns valid JSON string when no OutputPath supplied' {
            $output = Get-MDEValidationReport -OutputFormat JSON
            { $output | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'envelope has metadata, summary, and results top-level keys' {
            $output = Get-MDEValidationReport -OutputFormat JSON
            $parsed = $output | ConvertFrom-Json
            $parsed.metadata | Should -Not -BeNullOrEmpty
            $parsed.summary  | Should -Not -BeNullOrEmpty
            $parsed.results  | Should -Not -BeNullOrEmpty
        }

        It 'metadata contains expected fields' {
            $output = Get-MDEValidationReport -OutputFormat JSON
            $parsed = $output | ConvertFrom-Json
            $parsed.metadata.computerName  | Should -Not -BeNullOrEmpty
            $parsed.metadata.os            | Should -Be 'Windows 11 Enterprise'
            $parsed.metadata.managedBy     | Should -Be 'Intune'
            $parsed.metadata.mdeOnboarding | Should -Be 'Onboarded'
            # ConvertFrom-Json may deserialise the ISO-8601 string as [DateTime]; either is acceptable
            $parsed.metadata.generated     | Should -Not -BeNullOrEmpty
            $parsed.metadata.moduleVersion | Should -Not -BeNullOrEmpty
        }

        It 'summary counts match the mocked result set' {
            $output = Get-MDEValidationReport -OutputFormat JSON
            $parsed = $output | ConvertFrom-Json
            $parsed.summary.total         | Should -Be 3
            $parsed.summary.pass          | Should -Be 1
            $parsed.summary.fail          | Should -Be 1
            $parsed.summary.warning       | Should -Be 1
            $parsed.summary.info          | Should -Be 0
            $parsed.summary.notApplicable | Should -Be 0
        }

        It 'results array contains result objects with original property names' {
            $output = Get-MDEValidationReport -OutputFormat JSON
            $parsed = $output | ConvertFrom-Json
            $parsed.results.Count | Should -Be 3
            $parsed.results[0].TestName  | Should -Be 'Real-Time Protection'
            $parsed.results[0].Category  | Should -Be 'Device State'
            $parsed.results[0].Status    | Should -Be 'Pass'
        }

        It 'Timestamp is serialised as ISO 8601 round-trip string in raw JSON' {
            $output = Get-MDEValidationReport -OutputFormat JSON
            # Verify the raw JSON contains an ISO 8601 Timestamp string (ConvertFrom-Json
            # may re-hydrate it as [DateTime], so check the raw output instead)
            $output | Should -Match '"Timestamp"\s*:\s*"2026-01-15T'
        }

        It 'writes JSON file and returns path when -OutputPath supplied' {
            $reportPath = Join-Path $TestDrive 'report.json'
            $result = Get-MDEValidationReport -OutputFormat JSON -OutputPath $reportPath
            $result | Should -Be $reportPath
            Test-Path $reportPath | Should -BeTrue
        }

        It 'written JSON file contains valid JSON with correct envelope' {
            $reportPath = Join-Path $TestDrive 'report2.json'
            Get-MDEValidationReport -OutputFormat JSON -OutputPath $reportPath | Out-Null
            $content = Get-Content $reportPath -Raw
            $parsed = $content | ConvertFrom-Json
            $parsed.summary.total | Should -Be 3
        }
    }

    Context '-AsExitCode switch' {

        BeforeAll {
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11 Enterprise' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'Intune' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Onboarded' }
        }

        It 'returns [int] 0 when no failures (Object format)' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    [PSCustomObject]@{ TestName = 'A'; Status = 'Pass'; Timestamp = Get-Date }
                    [PSCustomObject]@{ TestName = 'B'; Status = 'Warning'; Timestamp = Get-Date }
                )
            }
            $result = Get-MDEValidationReport -OutputFormat Object -AsExitCode
            $result | Should -Be 0
            $result | Should -BeOfType [int]
        }

        It 'returns [int] equal to fail count (Object format)' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    [PSCustomObject]@{ TestName = 'A'; Status = 'Pass'; Timestamp = Get-Date }
                    [PSCustomObject]@{ TestName = 'B'; Status = 'Fail'; Timestamp = Get-Date }
                    [PSCustomObject]@{ TestName = 'C'; Status = 'Fail'; Timestamp = Get-Date }
                )
            }
            $result = Get-MDEValidationReport -OutputFormat Object -AsExitCode
            $result | Should -Be 2
            $result | Should -BeOfType [int]
        }

        It 'returns [int] fail count instead of file path (JSON format with OutputPath)' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    [PSCustomObject]@{
                        TestName = 'A'; Category = 'Device State'; Status = 'Fail'
                        Message = 'x'; Expected = 'y'; Actual = 'z'; Recommendation = ''
                        Timestamp = Get-Date
                    }
                )
            }
            $reportPath = Join-Path $TestDrive 'exitcode.json'
            $result = Get-MDEValidationReport -OutputFormat JSON -OutputPath $reportPath -AsExitCode
            $result | Should -Be 1
            $result | Should -BeOfType [int]
            # File should still be written
            Test-Path $reportPath | Should -BeTrue
        }

        It 'returns [int] fail count from Console format without suppressing output' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    [PSCustomObject]@{ TestName = 'X'; Status = 'Fail'; Message = 'bad'; Recommendation = ''; Timestamp = Get-Date }
                )
            }
            $result = Get-MDEValidationReport -OutputFormat Console -AsExitCode
            $result | Should -Be 1
            $result | Should -BeOfType [int]
        }
    }

    Context 'HTML output format - modernised structure' {

        BeforeAll {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    # Device State - Pass
                    [PSCustomObject]@{
                        TestName       = 'Real-Time Protection'
                        Category       = 'Device State'
                        Status         = 'Pass'
                        Message        = 'Enabled'
                        Expected       = 'Enabled'
                        Actual         = 'Enabled'
                        Recommendation = ''
                    },
                    # Protection Settings - Fail with Recommendation
                    [PSCustomObject]@{
                        TestName       = 'Cloud Block Level'
                        Category       = 'Protection Settings'
                        Status         = 'Fail'
                        Message        = 'Low'
                        Expected       = 'High'
                        Actual         = 'Moderate (1)'
                        Recommendation = 'Set Cloud Block Level to High.'
                    },
                    # Network Protection - Warning
                    [PSCustomObject]@{
                        TestName       = 'Network Protection'
                        Category       = 'Network Protection'
                        Status         = 'Warning'
                        Message        = 'Audit'
                        Expected       = 'Block'
                        Actual         = 'Audit'
                        Recommendation = ''
                    },
                    # Info row
                    [PSCustomObject]@{
                        TestName       = 'MDE Device Tags'
                        Category       = 'Onboarding'
                        Status         = 'Info'
                        Message        = 'No tags configured'
                        Expected       = 'Configured'
                        Actual         = 'Not configured'
                        Recommendation = ''
                    },
                    # NotApplicable row
                    [PSCustomObject]@{
                        TestName       = 'Network Protection (Windows Server)'
                        Category       = 'Network Protection'
                        Status         = 'NotApplicable'
                        Message        = 'Not a server SKU'
                        Expected       = 'Block'
                        Actual         = ''
                        Recommendation = ''
                    },
                    # Policy Verification suffix row (empty Category-independent Expected)
                    [PSCustomObject]@{
                        TestName       = 'Real-Time Protection - Policy Registry Verification'
                        Category       = 'Policy Verification'
                        Status         = 'Pass'
                        Message        = 'Matches'
                        Expected       = ''
                        Actual         = '1'
                        Recommendation = ''
                    },
                    # General / Other row (empty Category falls back to the 'General / Other' bucket)
                    [PSCustomObject]@{
                        TestName       = 'Some Unmapped Test'
                        Category       = ''
                        Status         = 'Pass'
                        Message        = 'ok'
                        Expected       = ''
                        Actual         = ''
                        Recommendation = ''
                    },
                    # ASR row with expander data
                    [PSCustomObject]@{
                        TestName       = 'Attack Surface Reduction Rules'
                        Category       = 'ASR Rules'
                        Status         = 'Warning'
                        Message        = '2 rules in audit'
                        Expected       = 'All in Block mode'
                        Actual         = '5 of 16 rules in Block mode'
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

        It 'sources Expected column from each result''s Expected property (REPT-06, D-05)' {
            # 'Real-Time Protection' -> 'Enabled' from result.Expected
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

    Context '-Category and -ExcludeTest passthrough to Test-MDEConfiguration' {

        It 'forwards -Category to Test-MDEConfiguration' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator -ParameterFilter {
                $Category -contains 'ASR Rules'
            } {
                @([PSCustomObject]@{ TestName = 'Attack Surface Reduction Rules'; Status = 'Pass' })
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'Intune' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Onboarded' }
            
            $result = Get-MDEValidationReport -OutputFormat Object -Category 'ASR Rules'
            
            Should -Invoke Test-MDEConfiguration -Times 1 -ModuleName MDEValidator -ParameterFilter {
                $Category -contains 'ASR Rules'
            }
            $result[0].TestName | Should -Be 'Attack Surface Reduction Rules'
        }

        It 'forwards -ExcludeTest to Test-MDEConfiguration' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator -ParameterFilter {
                $ExcludeTest -contains '*SmartScreen*'
            } {
                @([PSCustomObject]@{ TestName = 'Service Status'; Status = 'Pass' })
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'Intune' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Onboarded' }
            
            Get-MDEValidationReport -OutputFormat Object -ExcludeTest '*SmartScreen*' | Out-Null
            
            Should -Invoke Test-MDEConfiguration -Times 1 -ModuleName MDEValidator -ParameterFilter {
                $ExcludeTest -contains '*SmartScreen*'
            }
        }
    }
}
