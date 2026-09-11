# Exp1: reproducibility + safety + timing. Resume-safe.
$ErrorActionPreference = 'Continue'
$LOG = 'C:\tmp\exp1_run.log'
"[$(Get-Date)] Exp1 start" | Tee-Object -FilePath $LOG

$VM_NAME       = 'WinAPITest'
$VM_INPUT_DIR  = 'C:\Users\WinAPITest\Desktop\Experiments\input'
$VM_RESULT_DIR = 'C:\Users\WinAPITest\Desktop\Experiments\results'
$VM_EXE        = 'C:\Users\WinAPITest\Desktop\WinAPIReplay\WinAPIReplay.exe'
$VM_SIGS       = 'C:\Users\WinAPITest\Desktop\WinAPIReplay\data\api_signatures.json'
$VM_SANDBOX    = 'C:\Sandbox'
$HOST_INPUT    = 'C:\Projects\Experiments\input'
$HOST_RESULT_R = 'C:\Projects\Experiments\results\replay'
$HOST_RESULT_E = 'C:\Projects\Experiments\results\eval'
$HOST_EXE      = 'C:\Projects\WinAPIReplay\build\WinAPIReplay.exe'
$HOST_SIGS_SRC = 'C:\Projects\WinAPIReplay\data\api_signatures.json'
$PYTHON        = 'C:\Projects\WinAPICollector\venv\Scripts\python.exe'
$EVALUATOR     = 'C:\Projects\WinAPICollector\log_evaluator.py'
$EVAL_SIGS     = 'C:\Projects\WinAPIReplay\data\api_signatures.json'
$RESULTS       = 'C:\Projects\Experiments\results'
$TIMING_CSV    = "$RESULTS\exp3_timing_raw.csv"
$SIDEEFFECT_JSON = "$RESULTS\sideeffect_raw.json"
$FAMILIES      = @('Redline', 'Agenttesla', 'Amadey', 'Berbew', 'Dacic')
$SELECTION_DIR = 'C:\tmp\sample_selection'

foreach ($d in @($HOST_RESULT_R, $HOST_RESULT_E, $RESULTS)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
if (-not (Test-Path $TIMING_CSV)) {
    'family,stem,outcome,total_events,elapsed_ms,dry_ms' | Set-Content $TIMING_CSV
}
if (-not (Test-Path $SIDEEFFECT_JSON)) { '[]' | Set-Content $SIDEEFFECT_JSON }

Write-Host '[VM] Establishing session...'
$credFile = $env:WINAPIREPLAY_VM_CRED
if (-not $credFile) { throw 'Set WINAPIREPLAY_VM_CRED to the path of your Export-Clixml credential file. See README.md.' }
if (-not (Test-Path $credFile)) { throw "Credential file not found: $credFile" }
$cred = Import-Clixml $credFile
# NOTE: -SessionOption is NOT compatible with -VMName (PowerShell Direct); it raises
# AmbiguousParameterSet. Session drops are handled by the reconnect logic in the loop.
$vmSession = New-PSSession -VMName $VM_NAME -Credential $cred
if ($vmSession.State -ne 'Opened') { Write-Host 'ERROR: VM session failed'; exit 1 }
Write-Host "[VM] Session OK: $($vmSession.State)"

Invoke-Command -Session $vmSession -ScriptBlock {
    param($i, $r)
    New-Item -ItemType Directory -Force -Path $i | Out-Null
    New-Item -ItemType Directory -Force -Path $r | Out-Null
} -ArgumentList $VM_INPUT_DIR, $VM_RESULT_DIR

Write-Host '[VM] Deploying WinAPIReplay.exe...'
Copy-Item -ToSession $vmSession -Path $HOST_EXE -Destination $VM_EXE -Force
Copy-Item -ToSession $vmSession -Path $HOST_SIGS_SRC -Destination $VM_SIGS -Force
$vmBinTime = Invoke-Command -Session $vmSession -ScriptBlock {
    param($e) (Get-Item $e).LastWriteTime
} -ArgumentList $VM_EXE
Write-Host "[VM] Deployed: $vmBinTime"
"[$(Get-Date)] Deployed: $vmBinTime" | Add-Content $LOG

$sideeffectData = Get-Content $SIDEEFFECT_JSON | ConvertFrom-Json
if ($null -eq $sideeffectData) { $sideeffectData = @() }
$seenSha = @{}
foreach ($item in $sideeffectData) {
    $key = if ($item.sha256) { $item.sha256 } else { $item.stem }
    if ($key) { $seenSha[$key] = $true }
}

$sampleNum = 0; $doneCount = 0; $errorCount = 0

foreach ($fam in $FAMILIES) {
    $selPath = Join-Path $SELECTION_DIR "$($fam.ToLower())_samples.json"
    $samples = Get-Content $selPath | ConvertFrom-Json
    Write-Host "`n====== $fam ($($samples.Count) samples) ======"
    "[$(Get-Date)] === $fam start" | Add-Content $LOG

    foreach ($sample in $samples) {
        $sampleNum++
        $sha         = $sample.sha256
        $stem        = $sha
        $hostInput   = Join-Path $HOST_INPUT "$fam\$sha.json"
        $vmInput     = "$VM_INPUT_DIR\$sha.json"
        $vmResult    = "$VM_RESULT_DIR\${sha}_result.json"
        $vmDryResult = "$VM_RESULT_DIR\${sha}_dry_result.json"
        $hostResult  = Join-Path $HOST_RESULT_R "${sha}_result.json"
        $hostEval    = Join-Path $HOST_RESULT_E "${sha}_eval.json"

        if (-not (Test-Path $hostInput)) {
            Write-Host "  [$sampleNum] SKIP (no input): $($sha.Substring(0,16))..."
            continue
        }
        $timingDone  = [bool](Select-String -Path $TIMING_CSV -Pattern ",$stem," -Quiet)
        $sideeffDone = $seenSha.ContainsKey($sha)
        if ((Test-Path $hostEval) -and $timingDone -and $sideeffDone) {
            Write-Host "  [$sampleNum] SKIP (done): $($sha.Substring(0,16))..."
            continue
        }
        # Eval + timing done but sideeffect missing (script restarted before periodic save):
        # add zero-violation placeholder instead of re-running to avoid duplicate timing entries.
        if ((Test-Path $hostEval) -and $timingDone -and (-not $sideeffDone)) {
            Write-Host "  [$sampleNum] SKIP (eval+timing done; adding sideeffect placeholder): $($sha.Substring(0,16))..."
            $seenSha[$sha] = $true
            $sideeffectData += [PSCustomObject]@{
                sha256          = $sha
                family          = $fam.ToLower()
                file_violations = 0
                reg_violations  = 0
                net_violations  = 0
            }
            continue
        }

        Write-Host "  [$sampleNum] $fam/$($sha.Substring(0,16))..." -NoNewline
        # Robust reconnect: retry with backoff so a single VM/WinRM hiccup does not
        # cascade into all remaining samples (previously one drop failed the rest).
        $reconnTries = 0
        while (($null -eq $vmSession -or $vmSession.State -ne 'Opened') -and $reconnTries -lt 6) {
            $reconnTries++
            Write-Host " [reconnect $reconnTries]" -NoNewline
            if ($vmSession) { Remove-PSSession $vmSession -ErrorAction SilentlyContinue }
            try {
                $vmSession = New-PSSession -VMName $VM_NAME -Credential $cred -ErrorAction Stop
            } catch {
                $vmSession = $null
                Start-Sleep -Seconds ([Math]::Min(10 * $reconnTries, 60))
            }
        }
        if ($null -eq $vmSession -or $vmSession.State -ne 'Opened') {
            Write-Host " ERROR: cannot establish VM session after $reconnTries tries; skipping sample"
            "$sha reconnect-failed" | Add-Content $LOG
            "$($fam.ToLower()),$stem,crash,0,0,0" | Add-Content $TIMING_CSV
            $errorCount++
            continue
        }

        try {
            Copy-Item -ToSession $vmSession -Path $hostInput -Destination $vmInput -Force

            Invoke-Command -Session $vmSession -ScriptBlock {
                Remove-Item 'C:\Sandbox\*' -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item 'HKCU:\Software\WinAPIReplaySandbox' -Recurse -Force -ErrorAction SilentlyContinue
            }

            $regBefore = Invoke-Command -Session $vmSession -ScriptBlock {
                Get-ChildItem 'HKCU:\Software\' -Recurse -ErrorAction SilentlyContinue |
                    Select-Object Name, LastWriteTime
            }

            $elapsed = Measure-Command {
                Invoke-Command -Session $vmSession -ScriptBlock {
                    param($e,$i,$s,$b,$r)
                    & $e $i --signatures $s --sandbox $b --sandbox-registry --net-sim --single-thread --no-spawn --result-json $r
                } -ArgumentList $VM_EXE,$vmInput,$VM_SIGS,$VM_SANDBOX,$vmResult
            }
            $elapsedMs = [int]$elapsed.TotalMilliseconds

            $elapsedDry = Measure-Command {
                Invoke-Command -Session $vmSession -ScriptBlock {
                    param($e,$i,$s,$b,$r)
                    & $e $i --signatures $s --sandbox $b --sandbox-registry --net-sim --single-thread --no-spawn --dry-run --result-json $r
                } -ArgumentList $VM_EXE,$vmInput,$VM_SIGS,$VM_SANDBOX,$vmDryResult
            }
            $dryMs = [int]$elapsedDry.TotalMilliseconds

            $cutoffTime = (Get-Date).AddSeconds(-($elapsedMs/1000 + $dryMs/1000 + 30))
            $fileChanges = Invoke-Command -Session $vmSession -ScriptBlock {
                param($cutoff)
                Get-ChildItem 'C:\Users\' -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff -and
                        $_.FullName -notlike '*\Sandbox\*' -and
                        $_.FullName -notlike '*\Experiments\*' }
            } -ArgumentList $cutoffTime

            $regAfter = Invoke-Command -Session $vmSession -ScriptBlock {
                Get-ChildItem 'HKCU:\Software\' -Recurse -ErrorAction SilentlyContinue |
                    Select-Object Name, LastWriteTime
            }
            $regDiff = if ($regBefore -and $regAfter) {
                Compare-Object $regBefore $regAfter -Property Name, LastWriteTime -ErrorAction SilentlyContinue
            } else { @() }
            $regChanges = ($regDiff | Where-Object { $_.Name -notlike '*WinAPIReplaySandbox*' }).Count
            $fileOutside = $fileChanges.Count
            $netOutside = (Invoke-Command -Session $vmSession -ScriptBlock {
                Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                    Where-Object { $_.RemoteAddress -ne '127.0.0.1' }
            }).Count

            $vmOk = Invoke-Command -Session $vmSession -ScriptBlock { param($p) Test-Path $p } -ArgumentList $vmResult
            if ($vmOk) { Copy-Item -FromSession $vmSession -Path $vmResult -Destination $hostResult -Force }

            $totalEvents = 0
            if (Test-Path $hostResult) {
                $rj = Get-Content $hostResult | ConvertFrom-Json
                $totalEvents = $rj.summary.total
            }

            $evalOk = $false
            if (Test-Path $hostResult) {
                & $PYTHON $EVALUATOR $hostInput $hostResult --signatures $EVAL_SIGS --json --output $hostEval 2>&1 | Out-Null
                $evalOk = (Test-Path $hostEval)
            }
            $outcome = if ($evalOk) { 'ok' } else { 'crash' }
            "$($fam.ToLower()),$stem,$outcome,$totalEvents,$elapsedMs,$dryMs" | Add-Content $TIMING_CSV

            if (-not $seenSha.ContainsKey($sha)) {
                $seenSha[$sha] = $true
                $sideeffectData += [PSCustomObject]@{
                    sha256          = $sha
                    family          = $fam.ToLower()
                    file_violations = $fileOutside
                    reg_violations  = $regChanges
                    net_violations  = $netOutside
                }
            }

            if ($evalOk) {
                $ed = Get-Content $hostEval | ConvertFrom-Json
                Write-Host " OK (${elapsedMs}ms dry=${dryMs}ms SR=$($ed.overall.success_rate)%)"
                $doneCount++
            } else {
                Write-Host ' WARN: eval failed'
                $errorCount++
            }
        } catch {
            Write-Host " ERROR: $_"
            "$sha ERROR: $_" | Add-Content $LOG
            "$($fam.ToLower()),$stem,crash,0,0,0" | Add-Content $TIMING_CSV
            $errorCount++
        }

        if ($sampleNum % 10 -eq 0) {
            ConvertTo-Json -InputObject @($sideeffectData) -Depth 3 | Set-Content $SIDEEFFECT_JSON
            "[$(Get-Date)] Progress $sampleNum ($doneCount ok, $errorCount err)" | Add-Content $LOG
            Write-Host "  [Saved at $sampleNum]"
        }
    }
    "[$(Get-Date)] === $fam done" | Add-Content $LOG
}

ConvertTo-Json -InputObject @($sideeffectData) -Depth 3 | Set-Content $SIDEEFFECT_JSON
Write-Host "`n=============================="
Write-Host "Exp1 complete. ok=$doneCount err=$errorCount total=$sampleNum"
Write-Host "  timing: $TIMING_CSV"
Write-Host "  sideeffect: $SIDEEFFECT_JSON"
Write-Host '=============================='
"[$(Get-Date)] Done ok=$doneCount err=$errorCount" | Add-Content $LOG
