# =============================================================
# Exp6: Sysmon Telemetry Automatic Generation
# 5 families x first 20 samples = 100 samples total.
# Run AFTER Exp5. Requires Sysmon64 running + sysmon_config.xml on the VM.
# (Separate from Exp1 so the Sysmon kernel driver does not perturb Exp3 timing.)
# Output:
#   results/sysmon/<sha>_sysmon.evtx         (Sysmon EVTX)
#   results/replay_sysmon/<sha>_result.json  (WinAPIReplay result, incl. transforms)
#   results/exp6_sysmon.csv                  (sysmon_analyzer.py appends per sample)
# Analysis: generate_tables_and_draft.py (fig_exp6/table_exp6) + exp7_classifier_v2.py
# =============================================================

$ErrorActionPreference = "Continue"
$LOG = "C:\tmp\exp6_run.log"
"[$(Get-Date)] Exp6 start" | Tee-Object -FilePath $LOG

$VM_NAME       = "WinAPITest"
$VM_INPUT_DIR  = "C:\Users\WinAPITest\Desktop\Experiments\input"
$VM_RESULT_DIR = "C:\Users\WinAPITest\Desktop\Experiments\results_sysmon"
$VM_SYSMON_DIR = "C:\Users\WinAPITest\Desktop\Experiments\sysmon"
$VM_EXE        = "C:\Users\WinAPITest\Desktop\WinAPIReplay\WinAPIReplay.exe"
$VM_SIGS       = "C:\Users\WinAPITest\Desktop\WinAPIReplay\data\api_signatures.json"
$VM_SANDBOX    = "C:\Sandbox"

$HOST_INPUT    = "C:\Projects\Experiments\input"
$HOST_RESULT_R = "C:\Projects\Experiments\results\replay_sysmon"
$HOST_SYSMON   = "C:\Projects\Experiments\results\sysmon"
$HOST_EXE      = "C:\Projects\WinAPIReplay\build\WinAPIReplay.exe"
$HOST_SIGS_SRC = "C:\Projects\WinAPIReplay\data\api_signatures.json"

$PYTHON          = "C:\Projects\WinAPICollector\venv\Scripts\python.exe"
$SYSMON_ANALYZER = "C:\Projects\WinAPICollector\sysmon_analyzer.py"
$EVAL_SIGS       = "C:\Projects\WinAPIReplay\data\api_signatures.json"
$EXP6_CSV        = "C:\Projects\Experiments\results\exp6_sysmon.csv"

$FAMILIES            = @("Redline", "Agenttesla", "Amadey", "Berbew", "Dacic")
$SELECTION_DIR       = "C:\tmp\sample_selection"
$SAMPLES_PER_FAMILY  = 20

foreach ($d in @($HOST_RESULT_R, $HOST_SYSMON)) {
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
    param($i, $r, $s)
    New-Item -ItemType Directory -Force -Path $i | Out-Null
    New-Item -ItemType Directory -Force -Path $r | Out-Null
    New-Item -ItemType Directory -Force -Path $s | Out-Null
} -ArgumentList $VM_INPUT_DIR, $VM_RESULT_DIR, $VM_SYSMON_DIR

# Sysmon service check
$sysmonStatus = Invoke-Command -Session $vmSession -ScriptBlock {
    (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue).Status
}
if ($sysmonStatus -ne 'Running') {
    Write-Host "WARNING: Sysmon64 is $sysmonStatus -- Exp6 data may be incomplete"
    "[$(Get-Date)] WARNING: Sysmon64 not running" | Add-Content $LOG
}

Copy-Item -ToSession $vmSession -Path $HOST_EXE -Destination $VM_EXE -Force
Copy-Item -ToSession $vmSession -Path $HOST_SIGS_SRC -Destination $VM_SIGS -Force

$sampleNum = 0
$doneCount = 0

foreach ($fam in $FAMILIES) {
    $selPath = Join-Path $SELECTION_DIR "$($fam.ToLower())_samples.json"
    $samples = (Get-Content $selPath | ConvertFrom-Json) | Select-Object -First $SAMPLES_PER_FAMILY

    Write-Host "`n====== $fam ($($samples.Count) samples) ======"

    foreach ($sample in $samples) {
        $sampleNum++
        $sha         = $sample.sha256
        $hostInput   = Join-Path $HOST_INPUT "$fam\$sha.json"
        $vmInput     = "$VM_INPUT_DIR\$sha.json"
        $vmResult    = "$VM_RESULT_DIR\${sha}_result.json"
        $vmEvtx      = "$VM_SYSMON_DIR\${sha}_sysmon.evtx"
        $hostResult      = Join-Path $HOST_RESULT_R "${sha}_result.json"
        $hostEvtx        = Join-Path $HOST_SYSMON   "${sha}_sysmon.evtx"
        $hostSysmonJson  = Join-Path $HOST_SYSMON   "${sha}_sysmon.json"

        if (-not (Test-Path $hostInput)) {
            Write-Host "  [$sampleNum] SKIP (no input): $($sha.Substring(0,16))..."; continue
        }
        if ((Test-Path $hostEvtx) -and (Test-Path $hostResult) -and (Test-Path $hostSysmonJson)) {
            Write-Host "  [$sampleNum] SKIP (done): $($sha.Substring(0,16))..."; continue
        }

        Write-Host "  [$sampleNum] $fam/$($sha.Substring(0,16))..." -NoNewline

        if ($vmSession.State -ne 'Opened') {
            $vmSession = New-PSSession -VMName $VM_NAME -Credential $cred
        }

        try {
            Copy-Item -ToSession $vmSession -Path $hostInput -Destination $vmInput -Force

            # (a) Sandbox cleanup
            Invoke-Command -Session $vmSession -ScriptBlock {
                Remove-Item C:\Sandbox\* -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item HKCU:\Software\WinAPIReplaySandbox -Recurse -Force -ErrorAction SilentlyContinue
            }

            # (b) Clear the Sysmon operational log before each run
            Invoke-Command -Session $vmSession -ScriptBlock {
                wevtutil cl "Microsoft-Windows-Sysmon/Operational" 2>$null
                Start-Sleep -Seconds 1          # ★追加：チャネル初期化を待つ
            }

            # (c) Run WinAPIReplay (full mode, transforms recorded in result JSON)
            Invoke-Command -Session $vmSession -ScriptBlock {
                param($exe, $inp, $sigs, $sb, $res)
                & $exe $inp --signatures $sigs --sandbox $sb `
                    --sandbox-registry --net-sim --single-thread --no-spawn `
                    --result-json $res
            } -ArgumentList $VM_EXE, $vmInput, $VM_SIGS, $VM_SANDBOX, $vmResult

            # ★★★ (c2) 新規：Sysmon の書き出し完了を待って検証 ★★★
            $evCheck = Invoke-Command -Session $vmSession -ScriptBlock {
                Start-Sleep -Seconds 3                      # 固定待機
                $total = 0
                $hasEvent1 = $false
                for ($i = 0; $i -lt 10; $i++) {             # 最大 10 回・待機 9 秒
                    $evts = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
                                         -ErrorAction SilentlyContinue
                    if ($evts) {
                        $total = @($evts).Count
                        $hasEvent1 = @($evts | Where-Object { $_.Id -eq 1 }).Count -gt 0
                    }
                    if ($hasEvent1) { break }
                    if ($i -lt 9) { Start-Sleep -Seconds 1 }   # 最終反復では待たない
                }
                [PSCustomObject]@{ Total = $total; HasEvent1 = $hasEvent1 }
            }

            if (-not $evCheck.HasEvent1) {
                Write-Host "  [$sampleNum] WARN: Event ID 1 not found (total=$($evCheck.Total))"
                "$sha NO_EVENT1 total=$($evCheck.Total)" | Add-Content $LOG
            }

            # (d) Export the Sysmon EVTX
            Invoke-Command -Session $vmSession -ScriptBlock {
                param($evtxPath)
                wevtutil epl "Microsoft-Windows-Sysmon/Operational" $evtxPath 2>$null
            } -ArgumentList $vmEvtx

            # (e) Copy artifacts back to host
            $hasResult = Invoke-Command -Session $vmSession -ScriptBlock {
                param($p) Test-Path $p
            } -ArgumentList $vmResult
            if ($hasResult) {
                Copy-Item -FromSession $vmSession -Path $vmResult -Destination $hostResult -Force
            }
            $hasEvtx = Invoke-Command -Session $vmSession -ScriptBlock {
                param($p) Test-Path $p
            } -ArgumentList $vmEvtx
            if ($hasEvtx) {
                Copy-Item -FromSession $vmSession -Path $vmEvtx -Destination $hostEvtx -Force
            }

            # sysmon_analyzer.py: parse EVTX, apply transforms, write JSON + append CSV
            if ((Test-Path $hostEvtx) -and (Test-Path $hostResult)) {
                $analyzeArgs = @($hostEvtx, $hostResult,
                    "--output", $hostSysmonJson,
                    "--csv", $EXP6_CSV,
                    "--sample-id", $sha,
                    "--family", $fam.ToLower())
                $analyzeOut = & $PYTHON $SYSMON_ANALYZER @analyzeArgs 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path $hostSysmonJson)) {
                    Write-Host " OK"
                    $doneCount++
                } else {
                    Write-Host " WARN: sysmon_analyzer failed (exit=$LASTEXITCODE)"
                    $analyzeOut | Add-Content $LOG
                }
            } else {
                Write-Host " WARN: missing evtx or result"
            }
        } catch {
            Write-Host " ERROR: $_"
            "$sha ERROR: $_" | Add-Content $LOG
        }
    }
}

Write-Host "`n=============================="
Write-Host "Exp6 done: $doneCount / $sampleNum samples"
Write-Host "  exp6_sysmon.csv -> $EXP6_CSV"
Write-Host "Next:"
Write-Host "  cd C:\Projects\Experiments"
Write-Host "  python generate_tables_and_draft.py"
Write-Host "  python exp7_classifier_v2.py"
Write-Host "=============================="
"[$(Get-Date)] Exp6 done=$doneCount" | Add-Content $LOG
