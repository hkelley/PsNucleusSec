
#region private/helper stuff, no exports here
[datetime] $script:UnixEpoch = '1970-01-01 00:00:00Z'

Function Get-Headers ([Parameter(Mandatory = $true)] [string] $ApiKey) {
    return @{'x-apikey' = $ApiKey;
             accept = "application/json"
            }
}

Function Get-TotalDaysFromNow ([Parameter(Mandatory = $true)] [datetime] $eventDt) {
    $ts = New-TimeSpan -Start ([datetime]::UtcNow) -End $eventDt.ToUniversalTime()

    return [int] $ts.TotalDays
}
#endregion

Function Get-NucleusSecProject  (
	      [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [System.Uri] $ApiBaseUrl 
        , [Parameter(Mandatory = $true)] [string] $ProjectName
    )  {

    $url = "{0}/projects" -f $ApiBaseUrl
    $headers = Get-Headers -ApiKey $ApiKey

    if($projects = Invoke-RestMethod -Uri $url -Headers $headers) {
        $project = $projects | ?{$_.project_name -like $ProjectName}
        if(-not $project) {
            throw "Could not find project like '$ProjectName'"
        } elseif ($project.Count -gt 1 ) {
            throw "Multiple projects like '$ProjectName'"
        } else {
            return $project
        }
    }
}

Function Get-NucleusSecFindings (
	      [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [System.Uri] $ApiBaseUrl 
	    , [Parameter(Mandatory = $true)] [int] $ProjectId
	    , [Parameter(Mandatory = $false)] [int] $AssetId
	    , [Parameter(Mandatory = $false)] [string] $TeamName
        , [Parameter(Mandatory = $false)] [string[]] $Severities
        , [Parameter(Mandatory = $false)] [int] $ApiLimit = 1000
    ) {

    $headers = Get-Headers -ApiKey $ApiKey

    $body = [pscustomobject] @{}
    if($Asset) { $body | Add-Member -NotePropertyName asset_id -NotePropertyValue $Asset_id }
    if($Severities) { $body | Add-Member -NotePropertyName finding_severity -NotePropertyValue $Severities }
    if($TeamName) {

        # Verify we were passed a valid team name


        $body | Add-Member -NotePropertyName team -NotePropertyValue $TeamName 
    }

    if($body.psobject.Properties.Count) {
        $bodyJson = ConvertTo-Json $body
    }

    $index = 0 
    $output = @()

    do {
        # Use the findings/search endpoint
        $url = "{0}/projects/{1}/findings/search?start={2}&limit={3}" -f $ApiBaseUrl,$ProjectId,$index,$ApiLimit
        $findings = Invoke-RestMethod -Uri $url -Headers $headers -Body $bodyJson -Method Post
        foreach($finding in $findings) {
                        
            # HACK - API returns the justification_assigned_teams field as a string AND the JSON is formatted as if the instance could be assigned to multiple teams.
            # From what I can see in the UI, there be only one assigned team per instance so I'm taking the liberty to consolidate here.  1) JSONify the text.  2) Promote the first item in value prop to be the content
            $finding | Add-Member -NotePropertyName "justification_assigned_team" -NotePropertyValue (ConvertFrom-Json $finding.justification_assigned_teams)[0]
            $finding.PSObject.Properties.Remove("justification_assigned_teams")
            
            $output += $finding
        }

    } while ($findings.Count -eq $ApiLimit  -and ($index += $ApiLimit))

    return $output
}


Function Get-NucleusSecAssets (
	      [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [System.Uri] $ApiBaseUrl
	    , [Parameter(Mandatory = $true)] [int] $ProjectId
        , [Parameter(Mandatory = $false)] [string] $AssetName
        , [Parameter(Mandatory = $false)] [System.Net.IPAddress] $AssetIP
        , [Parameter(Mandatory = $false)] [int] $ApiLimit = 5000
    ) {

    $headers = Get-Headers -ApiKey $ApiKey

    $index = 0 
    $output = @()

    do {
        $url = "{0}/projects/{1}/assets?start={2}&limit={3}" -f $ApiBaseUrl,$ProjectId,$index,$ApiLimit

        if(-not [String]::IsNullOrWhiteSpace($AssetName)) {
            $url += "&asset_name={0}" -f $AssetName
        } elseif(-not [String]::IsNullOrWhiteSpace($AssetIP)) {
            $url += "&ip_address={0}" -f $AssetIP
        } else {
            # Get 'em all
        }

        $assets = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        foreach($asset in $assets) {

            # HACK - API returns this redundantly-nested teams structure.  Simplify it here by promoting the object in "team_name" up a level
            foreach($f in "owner_team","support_team") {
                $asset."$f" = $asset."$f".team_name
            }
            $output += $asset
        }

    } while ($assets.Count -eq $ApiLimit -and ($index += $ApiLimit))

    return $output
}

Function Get-NucleusSecTeam (
	      [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [System.Uri] $ApiBaseUrl 
	    , [Parameter(Mandatory = $true)] [int] $ProjectId
	    , [Parameter(Mandatory = $false)] [string] $TeamName
    ) {

    $headers = Get-Headers -ApiKey $ApiKey
    $url = "{0}/projects/{1}/teams" -f $ApiBaseUrl,$ProjectId
    $teams = Invoke-RestMethod -Uri $url -Headers $headers

    if($team = ($teams| ?{$_.team_name -eq $TeamName})) {
        return $team
    }
}

Function Get-NucleusSecTeamNotableVulns (
	      [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [System.Uri] $ApiBaseUrl 
	    , [Parameter(Mandatory = $true)] [int] $ProjectId
	    , [Parameter(Mandatory = $true)] [string] $TeamName
        , [Parameter(Mandatory = $false)] [int] $TimeWindow = 7
        , [Parameter(Mandatory = $false)] [string[]] $Severities = ("High", "Critical")
        , [Parameter(Mandatory = $false)] [int] $ApiLimit = 1000
    )   {

    # Verify this is a valid team name
    if(-not ($team = Get-NucleusSecTeam -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -ProjectId $ProjectId -TeamName $TeamName)) {
        Write-Warning "Could not find team $TeamName in project $ProjectId"
        return
    }

    # process the finding severities
    $notable_findings = @()
    $notable_findings_keys = @()
    $findings = Get-NucleusSecFindings -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -ProjectId $ProjectId -Severities $Severities -TeamName $team.team_name
        
    foreach($finding in $findings | Sort-Object due_date) {

            # Skip this finding if we've seen a previous one of this name
            if($notable_findings_keys -contains $finding.finding_name `
                -or [string]::IsNullOrWhiteSpace($finding.due_date)) {
                continue
            }

            $notable_findings_keys += $finding.finding_name
            $status_message = $null

            if((Get-TotalDaysFromNow -eventDt $finding.due_date) -lt 0 ) {
                $status_message = "Overdue"
            } elseif ((Get-TotalDaysFromNow -eventDt $finding.due_date) -lt $TimeWindow ) {
                $status_message = "Due Soon"
            } elseif ((Get-TotalDaysFromNow -eventDt $finding.finding_discovered) -ge ($TimeWindow * -1) ) {
                $status_message = "Recently Discovered"
            } else {
                continue    # skip items that aren't new or near/over SLA
            }

            $finding | Add-Member -NotePropertyName "status_message" -NotePropertyValue $status_message
            $finding | Add-Member -NotePropertyName "team_name" -NotePropertyValue $finding.justification_assigned_team.team_name
            $finding.finding_discovered = $finding.finding_discovered.Substring(0,10).Trim()

            $notable_findings += $finding
    }

    $notable_findings | Select-Object status_message,due_date,finding_discovered,finding_name,finding_severity,team_name
}


Export-ModuleMember -Function Get-NucleusSecProject
Export-ModuleMember -Function Get-NucleusSecAssets
Export-ModuleMember -Function Get-NucleusSecFindings
Export-ModuleMember -Function Get-NucleusSecTeam
Export-ModuleMember -Function Get-NucleusSecTeamNotableVulns