param([Parameter(Mandatory=$true)][string]$CaptureDirectory,
      [string]$TracePattern='runtime*.etl', [long[]]$AdditionalProbePid=@(), [switch]$LifetimesOnly)
$ErrorActionPreference='Stop'
$traces=@(Get-ChildItem -LiteralPath $CaptureDirectory -Filter $TracePattern | Sort-Object LastWriteTime)
if (!$traces) { throw 'No runtime ETL files' }
$processProvider='Microsoft-Windows-Kernel-Process'
$networkProvider='Microsoft-Windows-Kernel-Network'
$dnsProvider='Microsoft-Windows-DNS-Client'
$afdProvider='Microsoft-Windows-Winsock-AFD'
function EventData($event) {
    $xml=[xml]$event.ToXml()
    $values=@{}
    foreach($value in $xml.Event.EventData.Data) { $values[$value.Name]=$value.InnerText }
    return $values
}
function Number($value) {
    if ($null -eq $value -or $value -eq '') { return 0L }
    if ($value -is [string] -and $value.StartsWith('0x')) { return [Convert]::ToInt64($value.Substring(2),16) }
    return [long]$value
}
$allProcesses=[Collections.Generic.List[object]]::new()
foreach($trace in $traces) {
    $query="*[System[Provider[@Name='$processProvider'] and (EventID=1 or EventID=2)]]"
    Get-WinEvent -Path $trace.FullName -Oldest -FilterXPath $query -ErrorAction SilentlyContinue | ForEach-Object {
        $data=EventData $_
        $allProcesses.Add([PSCustomObject]@{Utc=$_.TimeCreated.ToUniversalTime().ToString('o');EventId=$_.Id;Pid=(Number $data.ProcessID);ParentPid=(Number $data.ParentProcessID);Image=$data.ImageName;Sequence=$data.ProcessSequenceNumber;ParentSequence=$data.ParentProcessSequenceNumber})
    }
}
$targetIds=[Collections.Generic.HashSet[long]]::new()
$targetSequences=[Collections.Generic.HashSet[string]]::new()
$lifetimes=@{}
foreach($item in ($allProcesses | Sort-Object Utc)) {
    if($item.EventId -eq 1) {
        $lifetimes[$item.Sequence]=[PSCustomObject]@{Pid=$item.Pid;Start=[datetime]$item.Utc;End=[datetime]::MaxValue;Image=$item.Image;Sequence=$item.Sequence;ParentSequence=$item.ParentSequence;Target=$false}
        if(($item.Image -match '\\HuoChat\\(HuoChatOffline-v1-single\\|火柴单文件版\.exe$)') -or $targetSequences.Contains([string]$item.ParentSequence)) {
            $null=$targetSequences.Add([string]$item.Sequence);$null=$targetIds.Add($item.Pid)
            $lifetimes[$item.Sequence].Target=$true
        }
    } elseif($lifetimes.ContainsKey($item.Sequence)) {$lifetimes[$item.Sequence].End=[datetime]$item.Utc}
}
$ranges=@{}
foreach($life in $lifetimes.Values) {
    if(!$ranges.ContainsKey($life.Pid)) {$ranges[$life.Pid]=[Collections.Generic.List[object]]::new()}
    $ranges[$life.Pid].Add($life)
}
function IsTarget([long]$owner,[datetime]$when) {
    foreach($life in $ranges[$owner]) {
        if($life.Target -and $when -ge $life.Start -and $when -le $life.End) {return $true}
    }
    return $false
}
$probeIds=[Collections.Generic.HashSet[long]]::new()
$probeRanges=@{}
foreach($probeId in $AdditionalProbePid) {$null=$probeIds.Add($probeId)}
foreach($file in @('guard-probes.json','positive-control.json')) {
    $path=Join-Path $CaptureDirectory $file
    if(Test-Path -LiteralPath $path) {
        $probe=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $null=$probeIds.Add([long]$probe.pid)
        $probeRanges[[long]$probe.pid]=[PSCustomObject]@{Start=[DateTimeOffset]::UnixEpoch.AddSeconds([double]$probe.start-2).UtcDateTime;End=[DateTimeOffset]::UnixEpoch.AddSeconds([double]$probe.end+2).UtcDateTime}
    }
}
function IsProbe([long]$owner,[datetime]$when) {
    if($owner -in $AdditionalProbePid) {return $true}
    $range=$probeRanges[$owner]
    return $range -and $when -ge $range.Start -and $when -le $range.End
}
$selectedProcesses=@($allProcesses | Where-Object { $targetSequences.Contains([string]$_.Sequence) -or (IsProbe $_.Pid ([datetime]$_.Utc)) } | Sort-Object Utc)
$selectedProcesses | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $CaptureDirectory 'process-events.json') -Encoding utf8
$lifetimes.Values | Where-Object Target | Select-Object Pid,Start,End,Image,Sequence,ParentSequence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $CaptureDirectory 'target-process-lifetimes.json') -Encoding utf8
if($LifetimesOnly){Write-Output ('Recorded '+$targetSequences.Count+' target process lifetimes');exit}
$templates=@{}
foreach($provider in @($networkProvider,$dnsProvider,$afdProvider)) {
    foreach($definition in (Get-WinEvent -ListProvider $provider).Events) {
        $indexes=@{};$index=0
        if($definition.Template) {
            $template=[xml]$definition.Template
            foreach($field in $template.DocumentElement.ChildNodes) {
                if($field.LocalName -eq 'data') { $indexes[$field.name]=$index;$index++ }
            }
        }
        $templates[$provider+':'+$definition.Id+':'+$definition.Version]=$indexes
    }
}
$counts=@{};$processPointers=@{};$targetCount=0;$probeCount=0;$unknownAfd=0;$contextCount=0
# Read socket creations once to map kernel process pointers to real owner PIDs.
# Querying every unrelated send/receive event is unnecessarily expensive.
foreach($trace in $traces) {
    $query="*[System[Provider[@Name='$afdProvider'] and EventID=1000]]"
    Get-WinEvent -Path $trace.FullName -Oldest -FilterXPath $query -ErrorAction SilentlyContinue | ForEach-Object {
        $fields=$templates[$afdProvider+':'+$_.Id+':'+$_.Version]
        if($fields.ContainsKey('ProcessId') -and $fields.ContainsKey('Process')) {
            $pointer=$_.Properties[$fields['Process']].Value.ToString()
            $owner=Number $_.Properties[$fields['ProcessId']].Value
            if($processPointers.ContainsKey($pointer) -and $processPointers[$pointer] -ne $owner) {$processPointers[$pointer]=-1L}
            else {$processPointers[$pointer]=$owner}
        }
    }
}
$selectedIds=[Collections.Generic.HashSet[long]]::new()
foreach($id in $targetIds){$null=$selectedIds.Add($id)}
foreach($id in $probeIds){$null=$selectedIds.Add($id)}
$selectedPointers=@($processPointers.Keys | Where-Object {$selectedIds.Contains($processPointers[$_])})
$seen=[Collections.Generic.HashSet[string]]::new()
$targetWriter=[IO.StreamWriter]::new((Join-Path $CaptureDirectory 'target-events.xml'),$false,[Text.UTF8Encoding]::new($false))
$probeWriter=[IO.StreamWriter]::new((Join-Path $CaptureDirectory 'probe-events.xml'),$false,[Text.UTF8Encoding]::new($false))
$contextWriter=[IO.StreamWriter]::new((Join-Path $CaptureDirectory 'afd-context-only.xml'),$false,[Text.UTF8Encoding]::new($false))
try {
    foreach($trace in $traces) {
        $queries=[Collections.Generic.List[string]]::new()
        $idList=@($selectedIds)
        for($offset=0;$offset -lt $idList.Count;$offset+=4) {
            $conditions=foreach($id in $idList[$offset..([Math]::Min($offset+3,$idList.Count-1))]) {
                "System[Execution[@ProcessID='$id']] or EventData[Data[@Name='PID']='$id'] or EventData[Data[@Name='ProcessId']='$id']"
            }
            $queries.Add("*[System[Provider[@Name='$networkProvider'] or Provider[@Name='$dnsProvider'] or Provider[@Name='$afdProvider']] and ("+($conditions -join ' or ')+")]")
        }
        foreach($pointer in $selectedPointers) {
            $hex='0x'+([ulong]$pointer).ToString('x')
            $queries.Add("*[System[Provider[@Name='$afdProvider']] and EventData[Data[@Name='Process']='$hex']]")
        }
        foreach($query in $queries) {
          Get-WinEvent -Path $trace.FullName -Oldest -FilterXPath $query -ErrorAction SilentlyContinue | ForEach-Object {
            $event=$_
            if(!$seen.Add($trace.Name+':'+$event.RecordId)) {return}
            $key=$event.ProviderName+':'+$event.Id
            if(!$counts.ContainsKey($key)) {$counts[$key]=0};$counts[$key]++
            $owner=[long]$event.ProcessId
            $fields=$templates[$event.ProviderName+':'+$event.Id+':'+$event.Version]
            if($fields) {
                # Kernel-Network records the owning PID in EventData. The header
                # can instead identify a system worker delivering the event.
                foreach($name in @('PID','ProcessId')) {
                    if($fields.ContainsKey($name)) { $owner=Number $event.Properties[$fields[$name]].Value;break }
                }
                if($event.ProviderName -eq $afdProvider -and $fields.ContainsKey('Process')) {
                    $pointer=$event.Properties[$fields['Process']].Value.ToString()
                    if($fields.ContainsKey('ProcessId')) { <# Explicit owner already read above. #> }
                    elseif($processPointers.ContainsKey($pointer)) { $owner=$processPointers[$pointer] }
                    else {
                        $unknownAfd++
                        # A completion can execute on any thread. A header PID
                        # alone does not identify the socket's owner. Keep these
                        # observations separate instead of blaming the target.
                        if(IsTarget ([long]$event.ProcessId) $event.TimeCreated.ToUniversalTime()) {
                            $contextWriter.WriteLine($event.ToXml());$contextCount++
                        }
                        $owner=-1L
                    }
                }
            }
            if(IsTarget $owner $event.TimeCreated.ToUniversalTime()) {
                $targetWriter.WriteLine($event.ToXml());$targetCount++
            }
            if(IsProbe $owner $event.TimeCreated.ToUniversalTime()) {
                $probeWriter.WriteLine($event.ToXml());$probeCount++
            }
          }
        }
    }
} finally {$targetWriter.Dispose();$probeWriter.Dispose();$contextWriter.Dispose()}
$summary=[PSCustomObject]@{TraceFiles=@($traces.Name);TargetPids=@($targetIds);ProbePids=@($probeIds);SelectedEventsExamined=$seen.Count;TargetEvents=$targetCount;ProbeEvents=$probeCount;SelectedAfdEventsWithoutKnownProcessPointer=$unknownAfd;TargetThreadContextOnlyEvents=$contextCount;SelectedProviderEventCounts=$counts}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $CaptureDirectory 'event-export-summary.json') -Encoding utf8
$summary | Select-Object SelectedEventsExamined,TargetEvents,ProbeEvents,TargetThreadContextOnlyEvents | ConvertTo-Json
