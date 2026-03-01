function Show-MDEValidatorUI {
    <#
    .SYNOPSIS
        Launches the MDEValidator graphical user interface.
    .DESCRIPTION
        Opens a WPF-based GUI window that allows interactive validation of
        Microsoft Defender for Endpoint configuration settings. Provides a
        DataGrid of results with color-coded status indicators, summary counts,
        and the ability to export an HTML report.

        Requires Windows Desktop PowerShell with WPF support.
    .EXAMPLE
        Show-MDEValidatorUI

        Launches the MDEValidator GUI window.
    .NOTES
        Requires Windows Desktop PowerShell with WPF support.
        This function is not available on PowerShell Core or non-Windows platforms.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Launching MDEValidator UI..."

    # --- Platform guard -----------------------------------------------------------
    try {
        Add-Type -AssemblyName PresentationFramework  -ErrorAction Stop
        Add-Type -AssemblyName PresentationCore       -ErrorAction Stop
        Add-Type -AssemblyName WindowsBase            -ErrorAction Stop
    }
    catch {
        $msg = "WPF assemblies are not available in this PowerShell session. " +
               "The MDEValidator GUI requires Windows Desktop PowerShell (powershell.exe). " +
               "Please use 'Test-MDEConfiguration' or 'Get-MDEValidationReport' from the CLI instead."
        Write-Error $msg
        return
    }

    Write-Verbose "WPF assemblies loaded successfully."

    # --- Module version -----------------------------------------------------------
    $moduleVersion = '2.0.0'
    try {
        $manifest = Get-Module -Name MDEValidator -ErrorAction SilentlyContinue |
                    Select-Object -First 1
        if ($manifest) { $moduleVersion = $manifest.Version.ToString() }
    }
    catch { <# keep default #> }

    # --- XAML definition ----------------------------------------------------------
    [xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="MDEValidator - Configuration Validation"
    Width="920" Height="720"
    WindowStartupLocation="CenterScreen"
    Background="#F0F2F5"
    ResizeMode="CanResizeWithGrip">

    <Window.Resources>
        <!-- Accent button style -->
        <Style x:Key="AccentButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="18,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#106EBE"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#A0A0A0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Export button style -->
        <Style x:Key="ExportButton" TargetType="Button">
            <Setter Property="Background" Value="#2D7D46"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="14,7"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#1E6B35"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#A0A0A0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#1B2A4A" Padding="20,14">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                    <TextBlock Text="MDEValidator" FontSize="22" FontWeight="Bold"
                               Foreground="White"/>
                    <TextBlock Text="Microsoft Defender for Endpoint — Configuration Validation"
                               FontSize="12" Foreground="#A8BFE0" Margin="0,2,0,0"/>
                </StackPanel>
                <TextBlock Grid.Column="1" Text="v$moduleVersion" FontSize="12"
                           Foreground="#7B9CC7" VerticalAlignment="Bottom" Margin="0,0,4,2"/>
            </Grid>
        </Border>

        <!-- Options bar -->
        <Border Grid.Row="1" Background="White" Padding="16,10" BorderBrush="#D8DCE3"
                BorderThickness="0,0,0,1">
            <WrapPanel VerticalAlignment="Center">
                <CheckBox x:Name="chkOnboarding" Content="Include Onboarding"
                          Margin="0,0,20,0" VerticalContentAlignment="Center" FontSize="13"/>
                <CheckBox x:Name="chkPolicyVerification" Content="Include Policy Verification"
                          Margin="0,0,20,0" VerticalContentAlignment="Center" FontSize="13"/>
                <CheckBox x:Name="chkTroubleshootingMode" Content="Include Troubleshooting Mode"
                          Margin="0,0,24,0" VerticalContentAlignment="Center" FontSize="13"
                          IsEnabled="False" ToolTip="Reserved for future use"/>
                <Button x:Name="btnRun" Content="&#x25B6;  Run Validation" Style="{StaticResource AccentButton}"/>
                <Button x:Name="btnExport" Content="&#x1F4BE;  Export HTML" Style="{StaticResource ExportButton}"
                        Margin="10,0,0,0" IsEnabled="False"/>
            </WrapPanel>
        </Border>

        <!-- DataGrid -->
        <DataGrid Grid.Row="2" x:Name="dgResults"
                  AutoGenerateColumns="False"
                  IsReadOnly="True"
                  SelectionMode="Single"
                  HeadersVisibility="Column"
                  GridLinesVisibility="Horizontal"
                  HorizontalGridLinesBrush="#E4E7EC"
                  BorderBrush="#D8DCE3"
                  BorderThickness="0,0,0,1"
                  Background="White"
                  RowHeaderWidth="0"
                  CanUserResizeRows="False"
                  Margin="0"
                  FontSize="13"
                  AlternatingRowBackground="#F7F9FB">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Status" Binding="{Binding StatusDisplay}" Width="100">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="HorizontalAlignment" Value="Center"/>
                            <Setter Property="FontWeight" Value="SemiBold"/>
                            <Setter Property="Padding" Value="6,4"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Test Name" Binding="{Binding TestName}" Width="220">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="Padding" Value="6,4"/>
                            <Setter Property="TextWrapping" Value="Wrap"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="Padding" Value="6,4"/>
                            <Setter Property="TextWrapping" Value="Wrap"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Recommendation" Binding="{Binding Recommendation}" Width="220">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock">
                            <Setter Property="Padding" Value="6,4"/>
                            <Setter Property="TextWrapping" Value="Wrap"/>
                        </Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
            </DataGrid.Columns>
        </DataGrid>

        <!-- Summary panel -->
        <Border Grid.Row="3" Background="White" Padding="16,8" BorderBrush="#D8DCE3"
                BorderThickness="0,1,0,0">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                <Border Background="#E6F4EA" CornerRadius="4" Padding="14,6" Margin="4,0">
                    <TextBlock x:Name="txtPass" Text="Pass: 0" FontWeight="SemiBold"
                               Foreground="#1E7E34" FontSize="13"/>
                </Border>
                <Border Background="#FDECEA" CornerRadius="4" Padding="14,6" Margin="4,0">
                    <TextBlock x:Name="txtFail" Text="Fail: 0" FontWeight="SemiBold"
                               Foreground="#C62828" FontSize="13"/>
                </Border>
                <Border Background="#FFF8E1" CornerRadius="4" Padding="14,6" Margin="4,0">
                    <TextBlock x:Name="txtWarning" Text="Warning: 0" FontWeight="SemiBold"
                               Foreground="#F57F17" FontSize="13"/>
                </Border>
                <Border Background="#E3F2FD" CornerRadius="4" Padding="14,6" Margin="4,0">
                    <TextBlock x:Name="txtInfo" Text="Info: 0" FontWeight="SemiBold"
                               Foreground="#1565C0" FontSize="13"/>
                </Border>
                <Border Background="#F3E5F5" CornerRadius="4" Padding="14,6" Margin="4,0">
                    <TextBlock x:Name="txtNA" Text="N/A: 0" FontWeight="SemiBold"
                               Foreground="#6A1B9A" FontSize="13"/>
                </Border>
            </StackPanel>
        </Border>

        <!-- Status bar -->
        <Border Grid.Row="4" Background="#1B2A4A" Padding="14,7">
            <TextBlock x:Name="txtStatus" Text="Ready — click Run Validation to begin."
                       Foreground="#A8BFE0" FontSize="12"/>
        </Border>
    </Grid>
</Window>
"@

    # --- Build WPF window ---------------------------------------------------------
    try {
        Write-Verbose "Parsing XAML and building WPF window..."

        $reader = [System.Xml.XmlNodeReader]::new($xaml)
        $window = [System.Windows.Markup.XamlReader]::Load($reader)

        # Retrieve named controls
        $btnRun        = $window.FindName('btnRun')
        $btnExport     = $window.FindName('btnExport')
        $dgResults     = $window.FindName('dgResults')
        $chkOnboarding = $window.FindName('chkOnboarding')
        $chkPolicyVer  = $window.FindName('chkPolicyVerification')
        $txtStatus     = $window.FindName('txtStatus')
        $txtPass       = $window.FindName('txtPass')
        $txtFail       = $window.FindName('txtFail')
        $txtWarning    = $window.FindName('txtWarning')
        $txtInfo       = $window.FindName('txtInfo')
        $txtNA         = $window.FindName('txtNA')

        # Keep validation results in a script-scope list for export
        $script:uiResults = $null

        # ----- helper: map status to display badge text -----
        function Get-StatusDisplay {
            param([string]$Status)
            switch ($Status) {
                'Pass'          { [char]0x2705 + ' Pass'    }
                'Fail'          { [char]0x274C + ' Fail'    }
                'Warning'       { [char]0x26A0 + ' Warn'    }
                'Info'          { [char]0x2139 + ' Info'    }
                'NotApplicable' { [char]0x2796 + ' N/A'     }
                default         { $Status }
            }
        }

        # ----- Run Validation click --------------------------------------------------
        $btnRun.Add_Click({
            Write-Verbose "Run Validation button clicked."

            $btnRun.IsEnabled    = $false
            $btnExport.IsEnabled = $false
            $txtStatus.Text      = "Running validation — please wait..."
            $window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{})

            try {
                # Build parameters
                $params = @{}
                if ($chkOnboarding.IsChecked -eq $true) {
                    $params['IncludeOnboarding'] = $true
                    Write-Verbose "IncludeOnboarding enabled."
                }
                if ($chkPolicyVer.IsChecked -eq $true) {
                    $params['IncludePolicyVerification'] = $true
                    Write-Verbose "IncludePolicyVerification enabled."
                }

                Write-Verbose "Calling Test-MDEConfiguration..."
                $script:uiResults = @(Test-MDEConfiguration @params)
                Write-Verbose "Received $($script:uiResults.Count) results."

                # --- Build display rows with StatusDisplay for the badge column ---
                $displayRows = foreach ($r in $script:uiResults) {
                    [PSCustomObject]@{
                        StatusDisplay  = (Get-StatusDisplay $r.Status)
                        Status         = $r.Status
                        TestName       = $r.TestName
                        Message        = $r.Message
                        Recommendation = $r.Recommendation
                    }
                }

                $dgResults.ItemsSource = $displayRows

                # --- Apply row-level background colours ---
                $window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Loaded, [Action]{
                    for ($i = 0; $i -lt $dgResults.Items.Count; $i++) {
                        $row = $dgResults.ItemContainerGenerator.ContainerFromIndex($i)
                        if ($null -ne $row) {
                            switch ($dgResults.Items[$i].Status) {
                                'Pass'          { $row.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#E6F4EA') }
                                'Fail'          { $row.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#FDECEA') }
                                'Warning'       { $row.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#FFF8E1') }
                                'Info'          { $row.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#E3F2FD') }
                                'NotApplicable' { $row.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#F3E5F5') }
                            }
                        }
                    }
                })

                # --- Update summary counts ---
                $counts = $script:uiResults | Group-Object Status -AsHashTable -AsString
                $passCount    = if ($counts -and $counts['Pass'])          { $counts['Pass'].Count }          else { 0 }
                $failCount    = if ($counts -and $counts['Fail'])          { $counts['Fail'].Count }          else { 0 }
                $warningCount = if ($counts -and $counts['Warning'])       { $counts['Warning'].Count }       else { 0 }
                $infoCount    = if ($counts -and $counts['Info'])          { $counts['Info'].Count }          else { 0 }
                $naCount      = if ($counts -and $counts['NotApplicable']) { $counts['NotApplicable'].Count } else { 0 }

                $txtPass.Text    = "Pass: $passCount"
                $txtFail.Text    = "Fail: $failCount"
                $txtWarning.Text = "Warning: $warningCount"
                $txtInfo.Text    = "Info: $infoCount"
                $txtNA.Text      = "N/A: $naCount"

                $txtStatus.Text  = "Validation complete — $($script:uiResults.Count) tests evaluated."
            }
            catch {
                $txtStatus.Text = "Error: $_"
                Write-Warning "Validation error: $_"
            }
            finally {
                $btnRun.IsEnabled    = $true
                $btnExport.IsEnabled = ($null -ne $script:uiResults -and $script:uiResults.Count -gt 0)
            }
        })

        # ----- Export HTML click ------------------------------------------------------
        $btnExport.Add_Click({
            Write-Verbose "Export HTML button clicked."

            $dialog = New-Object Microsoft.Win32.SaveFileDialog
            $dialog.Filter   = "HTML Files (*.html)|*.html|All Files (*.*)|*.*"
            $dialog.Title    = "Save MDEValidator Report"
            $dialog.FileName = "MDEValidationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

            if ($dialog.ShowDialog() -eq $true) {
                $outputPath = $dialog.FileName
                Write-Verbose "Exporting HTML report to $outputPath..."

                try {
                    $txtStatus.Text = "Exporting report..."
                    $window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{})

                    $exportParams = @{
                        OutputFormat = 'HTML'
                        OutputPath   = $outputPath
                    }
                    if ($chkOnboarding.IsChecked -eq $true) {
                        $exportParams['IncludeOnboarding'] = $true
                    }
                    if ($chkPolicyVer.IsChecked -eq $true) {
                        $exportParams['IncludePolicyVerification'] = $true
                    }

                    Get-MDEValidationReport @exportParams

                    $txtStatus.Text = "Report exported to: $outputPath"
                    [System.Windows.MessageBox]::Show(
                        "Report saved successfully to:`n$outputPath",
                        "Export Complete",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information
                    ) | Out-Null
                }
                catch {
                    $txtStatus.Text = "Export failed: $_"
                    [System.Windows.MessageBox]::Show(
                        "Failed to export report:`n$_",
                        "Export Error",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error
                    ) | Out-Null
                }
            }
        })

        # ----- Show window ------------------------------------------------------------
        Write-Verbose "Displaying MDEValidator window."
        $window.ShowDialog() | Out-Null
        Write-Verbose "MDEValidator UI closed."

    }
    catch {
        $errorMsg = "Failed to launch MDEValidator UI: $_. " +
                    "Please ensure you are running Windows Desktop PowerShell (powershell.exe). " +
                    "Use 'Test-MDEConfiguration' or 'Get-MDEValidationReport' for CLI-based validation."
        Write-Error $errorMsg
    }
}
