# Exp1 Determinism verification (RQ6).
# Runs first 4 samples per family (= 20 total) 3 times each.
# Saves to results/det_run{1,2,3}/<sha>_result.json.
# Resume-safe: skips samples where all 3 runs already have result files.
# Uses WinMET volume scan order from C:\tmp\sample_selection\{family}_samples.json.

$ErrorActionPreference = 'Continue'
$LOG = 'C:\tmp\det_run.log'
"[$(Get-Date)] Determinism run start" | Tee-Object -FilePath $LOG

$VM_NAME       = 'WinAPITest'
$VM_INPUT_DIR  = 'C:\Users\WinAPITest\Desktop\Experiments\input'
$VM_RESULT_DIR = 'C:\Users\WinAPITest\Desktop\Experiments\results'
$VM_EXE        = 'C:\Users\WinAPITest\Desktop\WinAPIReplay\WinAPIReplay.exe'
$VM_SIGS       = 'C:\Users\WinAPITest\Desktop\WinAPIReplay\data\api_signatures.json'
$VM_SANDBOX    = 'C:\Sandbox'
$HOST_INPUT    = 'C:\Projects\Experiments\input'
$HOST_EXE      = 'C:\Projects\WinAPIReplay\build\WinAPIReplay.exe'
$HOST_SIGS_SRC = 'C:\Projects\WinAPIReplay\data\api_signatures.json'
$RESULTS       = 'C:\Projects\Experiments\results'
$SELECTION_DIR = 'C:\tmp\sample_selection'

$SAMPLES_PER_FAMILY = 4
$N_RUNS             = 3
$FAMILIES           = @('agenttesla', 'amadey', 'berbew', 'dacic', 'redline')

foreach ($run in 1..$N_RUNS) {
    $dir = "$RESULTS\det_run$run"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

Write-Host '[VM] Establishing session...'
$credFile = $env:WINAPIREPLAY_VM_CRED
if (-not $credFile) { throw 'Set WINAPIREPLAY_VM_CRED to the path of your Export-Clixml credential file. See README.md.' }
if (-not (Test-Path $credFile)) { throw "Credential file not found: $credFile" }
$cred = Import-Clixml $credFile
$vmSession = New-PSSession -VMName $VM_NAME -Credential $cred
if ($vmSession.State -ne 'Opened') { Write-Host 'ERROR: VM session failed'; exit 1 }
Write-Host "[VM] Session OK: $($vmSession.State)"

Invoke-Command -Session $vmSession -ScriptBlock {
    param($i, $r)
    New-Item -ItemType Directory -Force -Path $i | Out-Null
    New-Item -ItemType Directory -Force -Path $r | Out-Null
} -ArgumentList $VM_INPUT_DIR, $VM_RESULT_DIR

Write-Host '[VM] Deploying WinAPIReplay.exe...'
Copy-Item -ToSession $vmSession -Path $HOST_EXE  -Destination $VM_EXE  -Force
Copy-Item -ToSession $vmSession -Path $HOST_SIGS_SRC -Destination $VM_SIGS -Force
Write-Host "[VM] Deployed."

$totalSamples = 0; $totalRuns = 0; $errCount = 0

foreach ($fam in $FAMILIES) {
    $selPath = Join-Path $SELECTION_DIR "${fam}_samples.json"
    if (-not (Test-Path $selPath)) {
        Write-Host "[WARN] Selection JSON not found: $selPath"
        continue
    }
    $samples = (Get-Content $selPath | ConvertFrom-Json) | Select-Object -First $SAMPLES_PER_FAMILY
    Write-Host "`n====== $fam ($($samples.Count) samples x $N_RUNS runs) ======"

    foreach ($sample in $samples) {
        $totalSamples++
        $sha       = $sample.sha256
        $hostInput = Join-Path $HOST_INPUT "$fam\$sha.json"
        $vmInput   = "$VM_INPUT_DIR\$sha.json"

        if (-not (Test-Path $hostInput)) {
            Write-Host "  [$totalSamples] SKIP (no input): $($sha.Substring(0,16))..."
            continue
        }

        # Check if all 3 runs already complete (resume-safe)
        $allDone = $true
        foreach ($run in 1..$N_RUNS) {
            $hostRes = "$RESULTS\det_run$run\${sha}_result.json"
            if (-not (Test-Path $hostRes)) { $allDone = $false; break }
        }
        if ($allDone) {
            Write-Host "  [$totalSamples] SKIP (all $N_RUNS runs done): $($sha.Substring(0,16))..."
            continue
        }

        Write-Host "  [$totalSamples] $fam/$($sha.Substring(0,16))..." -NoNewline
        if ($vmSession.State -ne 'Opened') {
            Write-Host ' [reconnect]' -NoNewline
            $vmSession = New-PSSession -VMName $VM_NAME -Credential $cred
        }

        try {
            Copy-Item -ToSession $vmSession -Path $hostInput -Destination $vmInput -Force

            foreach ($run in 1..$N_RUNS) {
                $hostRes = "$RESULTS\det_run$run\${sha}_result.json"
                if (Test-Path $hostRes) {
                    Write-Host " run$run=cached" -NoNewline
                    continue
                }
                $vmResult = "$VM_RESULT_DIR\${sha}_det${run}_result.json"

                Invoke-Command -Session $vmSession -ScriptBlock {
                    Remove-Item 'C:\Sandbox\*' -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item 'HKCU:\Software\WinAPIReplaySandbox' -Recurse -Force -ErrorAction SilentlyContinue
                }

                Invoke-Command -Session $vmSession -ScriptBlock {
                    param($e,$i,$s,$b,$r)
                    & $e $i --signatures $s --sandbox $b --sandbox-registry --net-sim --single-thread --no-spawn --result-json $r
                } -ArgumentList $VM_EXE,$vmInput,$VM_SIGS,$VM_SANDBOX,$vmResult

                $vmOk = Invoke-Command -Session $vmSession -ScriptBlock {
                    param($p) Test-Path $p
                } -ArgumentList $vmResult
                if ($vmOk) {
                    Copy-Item -FromSession $vmSession -Path $vmResult -Destination $hostRes -Force
                    Write-Host " run${run}=OK" -NoNewline
                } else {
                    Write-Host " run${run}=FAIL" -NoNewline
                    $errCount++
                }
                $totalRuns++
            }
            Write-Host ''
        } catch {
            Write-Host " ERROR: $_"
            "$sha $fam ERROR: $_" | Add-Content $LOG
            $errCount++
        }
    }
    "[$(Get-Date)] === $fam done" | Add-Content $LOG
}

Write-Host "`n=============================="
Write-Host "Determinism runs complete."
Write-Host "  Samples processed: $totalSamples"
Write-Host "  Run executions:    $totalRuns"
Write-Host "  Errors:            $errCount"
Write-Host "=============================="
Write-Host "Run: python C:\Projects\Experiments\exp1_determinism_check.py"
"[$(Get-Date)] Done samples=$totalSamples runs=$totalRuns errors=$errCount" | Add-Content $LOG
