# =============================================================
# Exp0: Ablation Study (--no-l1-executor)
# 5 families x first 20 samples = 100 samples total.
# Run AFTER Exp1 (full-mode eval JSONs must already exist in results/eval/).
# Output:
#   results/replay_baseline/<sha>_result.json  (--no-l1-executor output)
#   results/eval_baseline/<sha>_eval.json      (log_evaluator.py output)
# Analysis: exp0_ablation_analyzer.py -> exp0_ablation.csv
# =============================================================

$ErrorActionPreference = "Continue"
$LOG = "C:\tmp\exp0_run.log"
"[$(Get-Date)] Exp0 start" | Tee-Object -FilePath $LOG

$VM_NAME       = "WinAPITest"
$VM_INPUT_DIR  = "C:\Users\WinAPITest\Desktop\Experiments\input"
$VM_RESULT_DIR = "C:\Users\WinAPITest\Desktop\Experiments\results_baseline"
$VM_EXE        = "C:\Users\WinAPITest\Desktop\WinAPIReplay\WinAPIReplay.exe"
$VM_SIGS       = "C:\Users\WinAPITest\Desktop\WinAPIReplay\data\api_signatures.json"
$VM_SANDBOX    = "C:\Sandbox"

$HOST_INPUT    = "C:\Projects\Experiments\input"
$HOST_RESULT_R = "C:\Projects\Experiments\results\replay_baseline"
$HOST_RESULT_E = "C:\Projects\Experiments\results\eval_baseline"
$HOST_EXE      = "C:\Projects\WinAPIReplay\build\WinAPIReplay.exe"
$HOST_SIGS_SRC = "C:\Projects\WinAPIReplay\data\api_signatures.json"

$PYTHON        = "C:\Projects\WinAPICollector\venv\Scripts\python.exe"
$EVALUATOR     = "C:\Projects\WinAPICollector\log_evaluator.py"
$EVAL_SIGS     = "C:\Projects\WinAPIReplay\data\api_signatures.json"

$FAMILIES      = @("Redline", "Agenttesla", "Amadey", "Berbew", "Dacic")
$SELECTION_DIR = "C:\tmp\sample_selection"
$SAMPLES_PER_FAMILY = 20

foreach ($d in @($HOST_RESULT_R, $HOST_RESULT_E)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

Write-Host "`n[VM] Establishing session..."
$credFile = $env:WINAPIREPLAY_VM_CRED
if (-not $credFile) {
    throw "Set WINAPIREPLAY_VM_CRED to the path of your Export-Clixml credential file. See README.md."
}
if (-not (Test-Path $credFile)) {
    throw "Credential file not found: $credFile"
}
$cred = Import-Clixml $credFile
# NOTE: -SessionOption is NOT compatible with -VMName (PowerShell Direct);
# it raises AmbiguousParameterSet. Reconnect logic in the loop handles drops.
$vmSession = New-PSSession -VMName $VM_NAME -Credential $cred
if ($vmSession.State -ne 'Opened') { Write-Host "ERROR: VM session failed"; exit 1 }
Write-Host "[VM] Session OK"

Invoke-Command -Session $vmSession -ScriptBlock {
    param($i, $r)
    New-Item -ItemType Directory -Force -Path $i | Out-Null
    New-Item -ItemType Directory -Force -Path $r | Out-Null
} -ArgumentList $VM_INPUT_DIR, $VM_RESULT_DIR

# Deploy binary (Exp1 already deployed; redeploy is harmless / idempotent)
Copy-Item -ToSession $vmSession -Path $HOST_EXE -Destination $VM_EXE -Force
Copy-Item -ToSession $vmSession -Path $HOST_SIGS_SRC -Destination $VM_SIGS -Force
Write-Host "[VM] Binary deployed OK"

$sampleNum = 0
$doneCount = 0

foreach ($fam in $FAMILIES) {
    $selPath = Join-Path $SELECTION_DIR "$($fam.ToLower())_samples.json"
    $samples = (Get-Content $selPath | ConvertFrom-Json) | Select-Object -First $SAMPLES_PER_FAMILY

    Write-Host "`n====== $fam ($($samples.Count) / $SAMPLES_PER_FAMILY samples) ======"

    foreach ($sample in $samples) {
        $sampleNum++
        $sha        = $sample.sha256
        $hostInput  = Join-Path $HOST_INPUT "$fam\$sha.json"
        $vmInput    = "$VM_INPUT_DIR\$sha.json"
        $vmResult   = "$VM_RESULT_DIR\${sha}_result.json"
        $hostResult = Join-Path $HOST_RESULT_R "${sha}_result.json"
        $hostEval   = Join-Path $HOST_RESULT_E "${sha}_eval.json"

        if (-not (Test-Path $hostInput)) {
            Write-Host "  [$sampleNum] SKIP (no input): $($sha.Substring(0,16))..."; continue
        }
        if (Test-Path $hostEval) {
            Write-Host "  [$sampleNum] SKIP (done): $($sha.Substring(0,16))..."; continue
        }

        Write-Host "  [$sampleNum] $fam/$($sha.Substring(0,16))..." -NoNewline

        if ($vmSession.State -ne 'Opened') {
            $vmSession = New-PSSession -VMName $VM_NAME -Credential $cred
        }

        try {
            Copy-Item -ToSession $vmSession -Path $hostInput -Destination $vmInput -Force

            # Sandbox cleanup (determinism / clean state per sample)
            Invoke-Command -Session $vmSession -ScriptBlock {
                Remove-Item C:\Sandbox\* -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item HKCU:\Software\WinAPIReplaySandbox -Recurse -Force -ErrorAction SilentlyContinue
            }

            # Run with --no-l1-executor (ablation baseline)
            Invoke-Command -Session $vmSession -ScriptBlock {
                param($exe, $inp, $sigs, $sb, $res)
                & $exe $inp --signatures $sigs --sandbox $sb `
                    --sandbox-registry --net-sim --single-thread --no-spawn `
                    --no-l1-executor --result-json $res
            } -ArgumentList $VM_EXE, $vmInput, $VM_SIGS, $VM_SANDBOX, $vmResult

            $vmResultExists = Invoke-Command -Session $vmSession -ScriptBlock {
                param($p) Test-Path $p
            } -ArgumentList $vmResult
            if ($vmResultExists) {
                Copy-Item -FromSession $vmSession -Path $vmResult -Destination $hostResult -Force
            }

            if (Test-Path $hostResult) {
                $evalArgs = @($hostInput, $hostResult, "--signatures", $EVAL_SIGS,
                              "--json", "--output", $hostEval)
                & $PYTHON $EVALUATOR @evalArgs 2>&1 | Out-Null
            }

            if (Test-Path $hostEval) {
                Write-Host " OK"
                $doneCount++
            } else {
                Write-Host " WARN: eval failed"
            }
        } catch {
            Write-Host " ERROR: $_"
            "$sha ERROR: $_" | Add-Content $LOG
        }
    }
}

Write-Host "`n=============================="
Write-Host "Exp0 done: $doneCount / $sampleNum samples"
Write-Host "  eval_baseline/ -> $HOST_RESULT_E"
Write-Host "Next:"
Write-Host "  cd C:\Projects\Experiments"
Write-Host "  python exp0_ablation_analyzer.py"
Write-Host "=============================="
"[$(Get-Date)] Exp0 done=$doneCount" | Add-Content $LOG
