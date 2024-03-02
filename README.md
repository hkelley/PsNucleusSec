# PsNucleusSec

Powershell cmdlets to simplify information collection, team management, and other functions of the https://nucleussec.com platform.

https://help.nucleussec.com/


## Quick Start

```
$par = @{ApiKey='12345';ApiBaseUrl="https://xxxx/nucleus/api"}

$project = Get-NucleusSecProject @par -ProjectName *

$findings = Get-NucleusSecFindings @par -Project $project.project_id -Severities ("Critical","High")

$finding = $findings[0]

Get-NucleusSecAssets @par -ProjectId $project.project_id  -AssetName yyyyy

```