param([Parameter(Mandatory=$true)][string]$CaptureDirectory)
$ErrorActionPreference='Stop'
$lifetimes=Get-Content -LiteralPath (Join-Path $CaptureDirectory 'target-process-lifetimes.json') -Raw | ConvertFrom-Json
$ranges=@{}
foreach($life in $lifetimes){$id=[long]$life.Pid;if(!$ranges.ContainsKey($id)){$ranges[$id]=@()};$ranges[$id]+=$life}
function Target([long]$owner,[datetime]$when){
    foreach($life in $ranges[$owner]){if($when -ge [datetime]$life.Start -and $when -le [datetime]$life.End){return $true}}
    return $false
}
$probes=@{}
foreach($name in @('guard-probes.json','positive-control.json')){
    $p=Get-Content -LiteralPath (Join-Path $CaptureDirectory $name) -Raw | ConvertFrom-Json
    $probes[[long]$p.pid]=[PSCustomObject]@{Start=[DateTimeOffset]::UnixEpoch.AddSeconds([double]$p.start-2).UtcDateTime;End=[DateTimeOffset]::UnixEpoch.AddSeconds([double]$p.end+2).UtcDateTime}
}
$net='Microsoft-Windows-Kernel-Network';$dns='Microsoft-Windows-DNS-Client';$afd='Microsoft-Windows-Winsock-AFD'
$files=@(Get-ChildItem -LiteralPath $CaptureDirectory -Filter '*.etl' | Sort-Object LastWriteTime | Select-Object -ExpandProperty FullName)
$query="*[System[Provider[@Name='$net'] or Provider[@Name='$dns'] or (Provider[@Name='$afd'] and EventID=1000)]]"
$targetWriter=[IO.StreamWriter]::new((Join-Path $CaptureDirectory 'target-events.xml'),$false,[Text.UTF8Encoding]::new($false))
$probeWriter=[IO.StreamWriter]::new((Join-Path $CaptureDirectory 'probe-events.xml'),$false,[Text.UTF8Encoding]::new($false))
$targetCount=0;$probeCount=0;$socketCount=0;$counts=@{};$total=0
try {
    Get-WinEvent -Path $files -Oldest -FilterXPath $query | ForEach-Object {
        $e=$_;$total++;$owner=[long]$e.ProcessId;$when=$e.TimeCreated.ToUniversalTime()
        $key=$e.ProviderName+':'+$e.Id;if(!$counts.ContainsKey($key)){$counts[$key]=0};$counts[$key]++
        if($e.ProviderName -eq $net){
            if($e.Id -eq 17){return} # This event has no owning PID; do not guess.
            $owner=[long]$e.Properties[0].Value
        } elseif($e.ProviderName -eq $afd){
            if($e.Version -ne 0){throw 'Unexpected AFD socket-create schema'}
            $owner=[long]$e.Properties[7].Value
        }
        if(Target $owner $when){
            $targetWriter.WriteLine($e.ToXml());$targetCount++
            if($e.ProviderName -eq $afd){$socketCount++}
        }
        $probe=$probes[$owner]
        if($probe -and $when -ge $probe.Start -and $when -le $probe.End){$probeWriter.WriteLine($e.ToXml());$probeCount++}
    }
} finally {$targetWriter.Dispose();$probeWriter.Dispose()}
$summary=[ordered]@{Method='Process sequence/lifetime ownership; Kernel-Network owner PID, DNS caller PID, AFD socket-create explicit ProcessId';TraceFiles=$files;TargetProcessLifetimes=$lifetimes.Count;ExaminedNetworkDnsSocketCreateEvents=$total;TargetEvents=$targetCount;TargetSocketCreateEvents=$socketCount;ProbeEvents=$probeCount;ProviderEventCounts=$counts;ThreadContextOnlyNotifications='Not treated as owner evidence; AFD completions may execute on unrelated threads'}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $CaptureDirectory 'event-export-summary.json') -Encoding utf8
[PSCustomObject]$summary | Select-Object ExaminedNetworkDnsSocketCreateEvents,TargetEvents,TargetSocketCreateEvents,ProbeEvents | ConvertTo-Json
