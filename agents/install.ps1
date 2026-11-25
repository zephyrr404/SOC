param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,
    [string]$ApiBase = "http://localhost:8000",
    [string[]]$EventLogs = @("Security", "Application", "System"),
    [int]$FlushInterval = 1,
    [int]$HeartbeatInterval = 30
)

$ErrorActionPreference = "Stop"
$ApiBase = $ApiBase.TrimEnd('/')

$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$ip = try {
    (Get-NetIPAddress -AddressFamily IPv4 |
     Where-Object { $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and $_.IPAddress -notmatch '^169\.' } |
     Select-Object -First 1).IPAddress
} catch { "unknown" }
$fingerprint = try { (Get-CimInstance Win32_ComputerSystemProduct).UUID } catch { [System.Guid]::NewGuid().ToString() }

$enrollBody = @{
    api_key          = $ApiKey
    hostname         = $hostname
    os_type          = $os
    ip_address       = $ip
    fingerprint_seed = $fingerprint
} | ConvertTo-Json

Write-Host "Enrolling agent with SOC server at $ApiBase ..."
try {
    $enrollResult = Invoke-RestMethod -Uri "$ApiBase/agents/enroll" -Method Post -Body $enrollBody -ContentType "application/json"
    $token = $enrollResult.agent_token
    $agentId = $enrollResult.agent_id
    Write-Host "Enrolled successfully. Agent ID: $agentId"
} catch {
    $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    if ($statusCode -eq 409) {
        $errorDetail = ($_.ErrorDetails.Message | ConvertFrom-Json).detail
        Write-Host "ERROR: Already enrolled to a different system: $errorDetail"
        Write-Host "Generate a new agent key for this machine on the SOC dashboard."
        exit 1
    } else {
        Write-Host "ERROR: Enrollment failed (HTTP $statusCode): $_"
        exit 1
    }
}

$agentDir = "$env:ProgramData\SOCAgent"
if (-not (Test-Path $agentDir)) {
    New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
}

# Join log names as a simple comma-separated string - will be split inside the agent script
$logNamesStr = $EventLogs -join ","

$config = @{
    api_key                    = $ApiKey
    api_base                   = $ApiBase
    agent_token                = $token
    agent_id                   = $agentId
    flush_interval_seconds     = $FlushInterval
    heartbeat_interval_seconds = $HeartbeatInterval
} | ConvertTo-Json

Set-Content -Path "$agentDir\config.json" -Value $config -Encoding UTF8

# -- Write the agent runtime script --
$agentScript = @"
`$ErrorActionPreference = "Continue"

`$global:SocAgentDir   = "`$env:ProgramData\SOCAgent"
`$global:SocConfigPath = Join-Path `$global:SocAgentDir "config.json"
`$global:SocCursorPath = Join-Path `$global:SocAgentDir "cursor.json"

function global:Get-SocConfig {
    Get-Content `$global:SocConfigPath | ConvertFrom-Json
}

function global:Invoke-SocReEnroll {
    param(`$cfg)
    try {
        `$body = @{
            api_key          = `$cfg.api_key
            hostname         = `$env:COMPUTERNAME
            os_type          = (Get-CimInstance Win32_OperatingSystem).Caption
            ip_address       = "unknown"
            fingerprint_seed = (Get-CimInstance Win32_ComputerSystemProduct).UUID
        } | ConvertTo-Json
        `$result = Invoke-RestMethod -Uri "`$(`$cfg.api_base)/agents/enroll" -Method Post -Body `$body -ContentType "application/json"
        `$updated = Get-Content `$global:SocConfigPath | ConvertFrom-Json
        `$updated.agent_token = `$result.agent_token
        `$updated | ConvertTo-Json | Set-Content `$global:SocConfigPath -Encoding UTF8
        Write-Host "[SOCAgent] Re-enrolled, new token obtained."
        return `$result.agent_token
    } catch {
        Write-Host "[SOCAgent] Re-enrollment failed: `$_"
        return `$null
    }
}

function global:Send-SocBulk {
    param(`$body)
    `$cfg = Get-SocConfig
    try {
        Invoke-RestMethod -Uri "`$(`$cfg.api_base)/agents/logs/bulk" -Method Post -Body `$body -ContentType "application/json" -Headers @{ "Authorization" = "Bearer `$(`$cfg.agent_token)" } | Out-Null
        return `$true
    } catch {
        `$statusCode = if (`$_.Exception.Response) { [int]`$_.Exception.Response.StatusCode } else { 0 }
        if (`$statusCode -eq 401) {
            Write-Host "[SOCAgent] Token expired, re-enrolling..."
            Invoke-SocReEnroll -cfg `$cfg | Out-Null
        } else {
            Write-Host "[SOCAgent] Bulk send failed (HTTP `$statusCode): `$_"
        }
        return `$false
    }
}

`$config  = Get-SocConfig
`$queue   = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
`$global:SocCursors = [Hashtable]::Synchronized(@{})

# Load existing cursors
if (Test-Path `$global:SocCursorPath) {
    try {
        `$data = Get-Content `$global:SocCursorPath | ConvertFrom-Json
        foreach (`$prop in `$data.PSObject.Properties) {
            `$global:SocCursors[`$prop.Name] = [long]`$prop.Value
        }
    } catch { }
}

# Split log names from config string
`$logNames = "$logNamesStr" -split ","

function global:Save-SocCursors {
    `$snap = @{}
    `$global:SocCursors.GetEnumerator() | ForEach-Object { `$snap[`$_.Key] = `$_.Value }
    `$snap | ConvertTo-Json | Set-Content -Path `$global:SocCursorPath -Encoding UTF8
}

# -- Initial catch-up: send recent events since last cursor (oldest-first so cursor advances monotonically) --
foreach (`$logn in `$logNames) {
    `$lastId = if (`$global:SocCursors.ContainsKey(`$logn)) { [long]`$global:SocCursors[`$logn] } else { 0 }
    `$events = try {
        @(Get-WinEvent -FilterXPath "*[System[(EventRecordID > `$lastId)]]" -LogName `$logn -MaxEvents 100 -Oldest -ErrorAction Stop)
    } catch { @() }
    foreach (`$evt in `$events) {
        `$queue.Enqueue(@{
            level   = "info"
            stage   = "event_log"
            message = (`$evt.Message -replace "`r`n","`n")
            meta    = @{
                log_name     = `$logn
                event_id     = [string]`$evt.Id
                record_id    = [string]`$evt.RecordId
                level_name   = `$evt.LevelDisplayName
                provider     = `$evt.ProviderName
                time_created = `$evt.TimeCreated.ToString("o")
            }
        })
        `$global:SocCursors[`$logn] = `$evt.RecordId
    }
}

# Flush initial catch-up batch
`$batch = @(); `$item = `$null
while (`$queue.TryDequeue([ref]`$item)) { `$batch += `$item }
if (`$batch.Count -gt 0) {
    `$bodyJson = @{ entries = `$batch } | ConvertTo-Json -Depth 10
    if (Send-SocBulk -body `$bodyJson) { Save-SocCursors }
}

# -- Flush timer --
`$flushTimer = New-Object System.Timers.Timer(`$config.flush_interval_seconds * 1000)
`$flushTimer.AutoReset = `$true
Register-ObjectEvent `$flushTimer "Elapsed" -MessageData @{ queue = `$queue } -Action {
    `$md = `$Event.MessageData
    `$q = `$md.queue
    `$batch = @(); `$item = `$null
    while (`$q.TryDequeue([ref]`$item)) { `$batch += `$item }
    if (`$batch.Count -eq 0) { return }
    `$bodyJson = @{ entries = `$batch } | ConvertTo-Json -Depth 10
    if (Send-SocBulk -body `$bodyJson) { Save-SocCursors }
} | Out-Null
`$flushTimer.Start()
Write-Host "[SOCAgent] Flush timer active."

# -- Heartbeat timer --
`$heartbeatTimer = New-Object System.Timers.Timer(`$config.heartbeat_interval_seconds * 1000)
`$heartbeatTimer.AutoReset = `$true
Register-ObjectEvent `$heartbeatTimer "Elapsed" -Action {
    `$cfg = Get-SocConfig
    `$body = @{ level = "info"; stage = "heartbeat"; message = "Heartbeat"; meta = @{} } | ConvertTo-Json -Depth 5
    try {
        Invoke-RestMethod -Uri "`$(`$cfg.api_base)/agents/logs" -Method Post -Body `$body -ContentType "application/json" -Headers @{ "Authorization" = "Bearer `$(`$cfg.agent_token)" } | Out-Null
    } catch {
        `$statusCode = if (`$_.Exception.Response) { [int]`$_.Exception.Response.StatusCode } else { 0 }
        if (`$statusCode -eq 401) { Invoke-SocReEnroll -cfg `$cfg | Out-Null }
    }
} | Out-Null
`$heartbeatTimer.Start()
Write-Host "[SOCAgent] Heartbeat timer active."

# -- Poll timer: check for new events every 2 seconds (oldest-first so cursor advances monotonically) --
`$pollTimer = New-Object System.Timers.Timer(2000)
`$pollTimer.AutoReset = `$true
Register-ObjectEvent `$pollTimer "Elapsed" -MessageData @{ logNames = `$logNames; queue = `$queue; cursors = `$global:SocCursors } -Action {
    `$md = `$Event.MessageData
    foreach (`$logn in `$md.logNames) {
        `$lastId = if (`$md.cursors.ContainsKey(`$logn)) { [long]`$md.cursors[`$logn] } else { 0 }
        `$events = try {
            @(Get-WinEvent -FilterXPath "*[System[(EventRecordID > `$lastId)]]" -LogName `$logn -MaxEvents 50 -Oldest -ErrorAction Stop)
        } catch { @() }
        foreach (`$evt in `$events) {
            `$md.queue.Enqueue(@{
                level   = "info"
                stage   = "event_log"
                message = (`$evt.Message -replace "`r`n","`n")
                meta    = @{
                    log_name     = `$logn
                    event_id     = [string]`$evt.Id
                    record_id    = [string]`$evt.RecordId
                    level_name   = `$evt.LevelDisplayName
                    provider     = `$evt.ProviderName
                    time_created = `$evt.TimeCreated.ToString("o")
                }
            })
            `$md.cursors[`$logn] = `$evt.RecordId
        }
    }
} | Out-Null
`$pollTimer.Start()
Write-Host "[SOCAgent] Poll timer active."

# -- Activity monitoring: process starts, USB devices, active window --
`$excludedProcesses = @("svchost.exe","conhost.exe","dllhost.exe","RuntimeBroker.exe","backgroundTaskHost.exe","SearchIndexer.exe","SearchFilterHost.exe","fontdrvhost.exe","sihost.exe","taskhostw.exe","dwm.exe","explorer.exe","ctfmon.exe","StartMenuExperienceHost.exe","ShellExperienceHost.exe","TextInputHost.exe")

try {
    Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier SocProcStart -MessageData @{ queue = `$queue; excluded = `$excludedProcesses } -Action {
        `$md = `$Event.MessageData
        try {
            `$n = `$Event.SourceEventArgs.NewEvent
            `$name = `$n.ProcessName
            if (`$md.excluded -contains `$name) { return }
            `$owner = try { (Get-CimInstance Win32_Process -Filter "ProcessId=`$(`$n.ProcessID)").GetOwner().User } catch { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
            `$md.queue.Enqueue(@{
                level   = "info"
                stage   = "activity"
                message = "Process started: `$name (PID `$(`$n.ProcessID)) by `$owner"
                meta    = @{
                    activity     = "process_start"
                    process      = `$name
                    pid          = [string]`$n.ProcessID
                    user         = `$owner
                    time_created = (Get-Date).ToString("o")
                }
            })
        } catch { }
    }
    Write-Host "[SOCAgent] Process-start watcher active."
} catch {
    Write-Host "[SOCAgent] Process-start watcher failed: `$_"
}

try {
    Register-CimIndicationEvent -ClassName Win32_VolumeChangeEvent -SourceIdentifier SocUsbChange -MessageData @{ queue = `$queue } -Action {
        `$md = `$Event.MessageData
        try {
            `$n = `$Event.SourceEventArgs.NewEvent
            if (`$n.EventType -eq 2 -and `$n.DriveType -eq 2) {
                `$md.queue.Enqueue(@{
                    level   = "info"
                    stage   = "activity"
                    message = "USB drive connected: `$(`$n.DriveName)"
                    meta    = @{ activity = "usb_connect"; drive = [string]`$n.DriveName; time_created = (Get-Date).ToString("o") }
                })
            } elseif (`$n.EventType -eq 3 -and `$n.DriveType -eq 2) {
                `$md.queue.Enqueue(@{
                    level   = "info"
                    stage   = "activity"
                    message = "USB drive removed: `$(`$n.DriveName)"
                    meta    = @{ activity = "usb_disconnect"; drive = [string]`$n.DriveName; time_created = (Get-Date).ToString("o") }
                })
            }
        } catch { }
    }
    Write-Host "[SOCAgent] USB watcher active."
} catch {
    Write-Host "[SOCAgent] USB watcher failed: `$_"
}

# Active window tracking only works in an interactive user session (not session 0)
if ((Get-Process -Id `$PID).SessionId -ne 0) {
  try {
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; using System.Text; public class SocWinTracker { [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow(); [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid); }'
  } catch { }
  `$winTimer = New-Object System.Timers.Timer(2000)
  `$winTimer.AutoReset = `$true
  try {
    Register-ObjectEvent `$winTimer "Elapsed" -MessageData @{ queue = `$queue; last = @{ key = "" } } -Action {
        `$md = `$Event.MessageData
        try {
            `$hwnd = [SocWinTracker]::GetForegroundWindow()
            if (`$hwnd -eq [IntPtr]::Zero) { return }
            `$sb = New-Object System.Text.StringBuilder 512
            [SocWinTracker]::GetWindowText(`$hwnd, `$sb, 512) | Out-Null
            `$title = `$sb.ToString().Trim()
            if (`$title.Length -eq 0) { return }
            `$procId = 0
            [SocWinTracker]::GetWindowThreadProcessId(`$hwnd, [ref]`$procId) | Out-Null
            `$procName = try { (Get-Process -Id `$procId -ErrorAction Stop).ProcessName } catch { "unknown" }
            `$key = "`$procName|`$title"
            if (`$key -ne `$md.last.key) {
                `$md.last.key = `$key
                `$md.queue.Enqueue(@{
                    level   = "info"
                    stage   = "activity"
                    message = "Active window: `$title (`$procName)"
                    meta    = @{
                        activity     = "window_focus"
                        process      = `$procName
                        window       = `$title
                        pid          = [string]`$procId
                        time_created = (Get-Date).ToString("o")
                    }
                })
            }
        } catch { }
    } | Out-Null
    Write-Host "[SOCAgent] Window tracker active."
  } catch {
    Write-Host "[SOCAgent] Window tracker failed: `$_"
  }
  `$winTimer.Start()
}

Write-Host "[SOCAgent] Agent running. Monitoring: $logNamesStr + activity (process/usb/window)"
while (`$true) { Start-Sleep -Seconds 3600 }
"@

Set-Content -Path "$agentDir\agent.ps1" -Value $agentScript -Encoding UTF8

$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile("$agentDir\agent.ps1", [ref]$null, [ref]$errors) | Out-Null
if ($errors -and $errors.Count -gt 0) {
    Write-Host "ERROR: Generated agent.ps1 has syntax errors:"
    $errors | ForEach-Object { Write-Host "  Line $($_.Extent.StartLineNumber): $($_.Message)" }
    exit 1
}

$action    = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentDir\agent.ps1`""
$isSystem = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"
if ($isSystem) {
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $trigger   = New-ScheduledTaskTrigger -AtStartup
} else {
    $userFq = "$env:COMPUTERNAME\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal -UserId $userFq -LogonType Interactive -RunLevel Highest
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $userFq
}

$existing = Get-ScheduledTask -TaskName "SOCAgentWatcher" -ErrorAction SilentlyContinue
if ($existing) {
    Stop-ScheduledTask -TaskName "SOCAgentWatcher" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "SOCAgentWatcher" -Confirm:$false
}

Register-ScheduledTask -TaskName "SOCAgentWatcher" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "SOCAgentWatcher"


Write-Host "SOC Agent installed and started successfully!"
Write-Host "  Agent ID  : $agentId"
Write-Host "  Server    : $ApiBase"
Write-Host "  Log Names : $($EventLogs -join ', ')"
Write-Host ""
Write-Host "The agent is now running as a scheduled task (SOCAgentWatcher)."
Write-Host "Activity monitoring: process starts, USB devices, active window."
Write-Host "Events will appear in the Live Events dashboard within a few seconds."
