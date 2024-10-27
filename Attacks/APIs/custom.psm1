function Wait-KeyOrTimeOut {
    param([int] $Timeout = 1000)
    end {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            while (-not [Console]::KeyAvailable) {
                if ($stopwatch.ElapsedMilliseconds -gt $Timeout) {
                    throw 'Timeout hit'
                }
                Write-Progress -Activity "Waiting... Press key to skip..." -Status "$([int]($stopwatch.ElapsedMilliseconds/1000))/$([int]($Timeout/1000))s" -PercentComplete ([int]($stopwatch.ElapsedMilliseconds/$Timeout*100))
                Start-Sleep -Milliseconds 50
            }

            $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown') > $null
        } catch [System.NotImplementedException] {
            Read-Host -Prompt "Readkey is not supported, press enter to continue..."
        } catch [System.InvalidOperationException] {
            Write-Host "Readkey failed, waiting fixed time..."
            while ($stopwatch.ElapsedMilliseconds -lt $Timeout) {
                Write-Progress -Activity "Waiting... Press key to skip..." -Status "$([int]($stopwatch.ElapsedMilliseconds/1000))/$([int]($Timeout/1000))s" -PercentComplete ([int]($stopwatch.ElapsedMilliseconds/$Timeout*100))
                Start-Sleep -Milliseconds 50
            }
        } catch {

        } finally {
            Write-Progress -Activity "Waiting... Press key to skip..." -Status "Done" -Completed
        }
    }
}
Export-ModuleMember -Function Wait-KeyOrTimeOut

function Install-HTMLParser {
    Get-Module | Where-Object name -eq psparsehtml | Remove-Module
    $isInstalled = (Get-Module -ListAvailable -Name PSParseHTML).Count
    if ($isInstalled -eq 0) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name PSParseHTML -RequiredVersion 1.0.2 -Force -Scope AllUsers
    }

    Import-Module PSParseHTML -Force
}
Export-ModuleMember -Function Install-HTMLParser
