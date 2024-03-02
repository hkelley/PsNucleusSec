
[datetime] $script:UnixEpoch = '1970-01-01 00:00:00Z'

Function Get-Headers ([Parameter(Mandatory = $true)] [string] $ApiKey) {
    return @{'x-apikey' = $ApiKey;
             accept = "application/json"
            }
}

Function Get-NucleusSecProject  (
	      [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [string] $ProjectName
        , [Parameter(Mandatory = $true)] [System.Uri] $ApiBaseUrl 
    )  {

    $url = "{0}/projects" -f $ApiBaseUrl
    $headers = Get-Headers -ApiKey $ApiKey

    if($projects = Invoke-RestMethod -Uri $url -Headers $headers) {
        $project = $projects | ?{$_.project_name -like $ProjectName}
        if(-not $projects) {
            throw "Could not find project like '$ProjectName'"
        } elseif ($projects.Count -gt 1 ) {
            throw "Multiple projects like '$ProjectName'"
        } else {
            return $project
        }
    }
}

Export-ModuleMember -Function Get-NucleusSecProject
