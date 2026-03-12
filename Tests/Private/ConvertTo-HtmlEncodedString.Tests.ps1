BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'ConvertTo-HtmlEncodedString' {

    Context 'Empty and null input' {

        It 'returns empty string when input is empty string' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString ''
                $result | Should -Be ''
            }
        }
    }

    Context 'Plain text with no HTML characters' {

        It 'returns the original string when no HTML special characters are present' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString 'Hello World'
                $result | Should -Be 'Hello World'
            }
        }
    }

    Context 'HTML special character encoding' {

        It 'encodes less-than sign' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString '<script>'
                $result | Should -Match '&lt;'
            }
        }

        It 'encodes greater-than sign' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString '<b>text</b>'
                $result | Should -Match '&gt;'
            }
        }

        It 'encodes ampersand' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString 'A & B'
                $result | Should -Match '&amp;'
            }
        }

        It 'encodes double quote' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString 'say "hello"'
                $result | Should -Match '&quot;'
            }
        }

        It 'encodes a string containing multiple HTML special characters' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString '<div class="test">A & B</div>'
                $result | Should -Match '&lt;'
                $result | Should -Match '&gt;'
                $result | Should -Match '&amp;'
                $result | Should -Match '&quot;'
            }
        }

        It 'returns a string type' {
            InModuleScope MDEValidator {
                $result = ConvertTo-HtmlEncodedString -InputString '<test>'
                $result | Should -BeOfType [string]
            }
        }
    }
}
