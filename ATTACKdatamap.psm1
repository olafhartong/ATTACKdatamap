function Get-ATTACKdata {
    <#
    .SYNOPSIS
        Downloads the MITRE ATT&CK Enterprise JSON file
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> Get-ATTACKdata -AttackPath ./enterprise-attack.json
    .OUTPUTS
        $AttackPath = The location where the ATT&CK Enterprise file will be stored, default is .\enterprise-attack.json
    #>
    param (
        # Log name of where to look for the PowerShell events.
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $AttackPath = 'enterprise-attack.json'
    )
    $url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" 
      
    if(!(Split-Path -parent $AttackPath) -or !(Test-Path -pathType Container (Split-Path -parent $AttackPath))) { 
      $AttackPath = Join-Path $pwd (Split-Path -leaf $AttackPath) 
    } 
      
    Write-Host "[++] Downloading [$url]`nSaving at [$AttackPath]" -ForegroundColor Cyan
    $client = new-object System.Net.WebClient 
    $client.DownloadFile($url, $AttackPath) 
      
    $AttackPath  
}

function Invoke-ATTACKUpdateExcel {
    <#
    .SYNOPSIS
        Generates MITRE ATT&CK relevant fields into a table and creates or updates a worksheet in an Excel sheet
        Requires module ImportExcel, Install it like this PS C:\> Install-Module ImportExcel
    .DESCRIPTION
    .EXAMPLE
        PS C:\> Invoke-ATTACKUpdateExcel -AttackPath .\enterprise-attack.json -Excelfile .\mitre_data_assessment.xlsx
    .INPUTS
        AttackPath = The location of the ATT&CK Enterprise JSON file, default is .\enterprise-attack.json
    .OUTPUTS
        $Excefile = The location of the Excel file in which you want to create/update the DataSources reference workbook, default is .\mitre_data_assessment.xlsx
    .NOTES
    #>
    param (
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]    
        $Excelfile = 'mitre_data_assessment.xlsx',
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $AttackPath = 'enterprise-attack.json'
    )
    $dataset=Get-Content -Path $AttackPath | ConvertFrom-Json | Select-Object -ExpandProperty objects  | Where-Object type -eq "attack-pattern" 

    $Collection =@()
    foreach ($object in $dataset)
        {        
        $Props = @{
            'ID' = $object.external_references.'external_id'
            'Data Source' = $object.'x_mitre_data_sources'
            'Name' = $object.'name'
            'Detection' = $object.'x_mitre_detection'
            'Platforms' = $object.'x_mitre_platforms'
            'Description' = $object.'description'
            'Tactic' = $object.'kill_chain_phases'.'phase_name'
            'Defense Bypassed' = $object.'x_mitre_defense_bypassed'
            }
        $TotalObjects = New-Object PSCustomObject -Property $Props
        $Collection += $TotalObjects
        }
    
    Write-Host "[++] Updating your Data Source sheet" -ForegroundColor Cyan	
    $Collection | Select-Object  @{Name ="ID"; Expression={$_.ID -split "," }},@{Name ="Name"; Expression={$_.Name -join ","}},@{Name="Data Source";Expression={$_.'Data Source' -join ","}},@{Name="Platforms";Expression={$_.'Platforms' -join ","}},@{Name="Detection";Expression={$_.'Detection' -join ","}},@{Name="Description";Expression={$_.'Description' -join ","}},@{Name="Tactic";Expression={$_.'Tactic' -join ","}},@{Name="Defense Bypassed";Expression={$_.'Defense Bypassed' -join ","}} | Sort-Object ID | Export-Excel $Excelfile -WorksheetName REF-DataSources      
}

function Request-ATTACKjson {
    <#
    .SYNOPSIS
        Generates a JSON file to be imported into the ATT&CK Navigator. Based on a template and a filled Excel sheet
        Requires module ImportExcel, Install it like this PS C:\> Install-Module ImportExcel
    .DESCRIPTION
        Generates a JSON file to be imported into the ATT&CK Navigator. The mitre_data_assessment Excel file contains all Techniques, which can be updated via Invoke-ATTACK-UpdateExcel.
        These techniques contain DataSources, which are individually scored with a weight. The DataSourceEventTypes need to be scored per environment.
        This script multiplies the respective DataSource scores and adds them to a total technique score. The generation date is added to the description.
        
        This is all gathered into a JSON file which can be opened here;
        https://mitre-attack.github.io/attack-navigator/enterprise/
    .EXAMPLE
        PS C:\> Request-ATTACKjson -Excelfile .\mitre_data_assessment.xlsx -Template .\template.json -Output 2019-03-23-ATTACKcoverage.json 
    .INPUTS
        Excelfile = The Excel file containing all Datasource scores, default is .\mitre_data_assessment.xlsx
        Template = The ATT&CK Navigator JSON template, default is .\template.json
    .OUTPUTS
        Output = The name of the JSON file you want to generate for the ATT&CK Navigator, default is ATTACKcoverage.json
    .NOTES
    #>
    
        param (
            [Parameter(Mandatory=$false,
                       ValueFromPipelineByPropertyName=$true,
                       Position=0)]
            [string]
            $Excelfile = 'mitre_data_assessment.xlsx',
            [Parameter(Mandatory=$false,
                       ValueFromPipelineByPropertyName=$true,
                       Position=0)]
            [string]
            $Template = 'template.json',
            [Parameter(Mandatory=$false,
                       ValueFromPipelineByPropertyName=$true,
                       Position=0)]
            [string]
            $Title = 'DataCoverage',        
            [Parameter(Mandatory=$false,
                       ValueFromPipelineByPropertyName=$true,
                       Position=0)]
            [string]
            $Output = 'ATTACKcoverage.json'
        )
    
    $lookup = Import-Excel $Excelfile -WorksheetName DataSourceEvents
    $mitre = Import-Excel $Excelfile -WorksheetName TechniqueDataSourceWeights
    $JSONtemplate = (Get-Content -Raw -Path $Template | ConvertFrom-Json)
    $Date = (get-date).ToString("yyy-MM-dd")
    $finalresult = @()
    # main loop
    foreach($line in $mitre)
    {
        # Collect info
        $DataSources = $line."Data Source"
        $weights = $line.Weight -split ";"
        # Define Variables
        $techniques = @()
        $techniquescore = 0
        # Comma-separated datasources
        $i = 0;
        foreach($ds in $DataSources -split ",")
        {
            # Collect info
            $DataSourceEvents = $lookup | Where-Object DataSource -eq $ds
            $weight = ($weights[$i])  
            # Variables
            $total = 0
            $metas = @()
            # Iterate over DataSourceEvents
            foreach($f in $DataSourceEvents)
            {
                $total += ($f.Score * $weight)
                $meta = New-Object PSCustomObject -Property @{
                    "name"="$($ds):$($f.Event)";
                    "value"="Score: $($f.Score * $weight)"
                }
                $metas += $meta
            }       
            # Create technique object with technique, datasource score and events in metadata per datasource
            $technique = New-Object PSCustomObject -Property @{
                "techniqueID"=$line.ID;
                "score"=$total;
                "metadata"=$metas
            }
            # Add Technique data to technique list
            $techniques += $technique
            # Add the technique datasource score to the technique total
            $techniquescore += $total
            $i += 1
        }
        $techniqueDSscore = 0
        $techniqueMetadata = @()
        $techniques | ForEach-Object -Begin {    
        } -Process { 
            $techniqueDSscore += $_.score
            $techniqueMetadata += $_.metadata
        }
        $techniqueTotal = New-Object PSCustomObject -Property @{
            "techniqueID"=$technique.techniqueID;
            "score"=$techniqueDSscore;
            "metadata"=$techniqueMetadata
        }
        $finalresult += $techniqueTotal
    }
    $JSONtemplate.name = $Title
    $JSONtemplate.description = $Date
    # Insert the generated techniques into the json template
    $JSONtemplate.techniques = $finalresult
    # Generate the ATT&CK navigator file
    $JSONtemplate | ConvertTo-Json -Depth 5 | Out-File -Encoding ascii $Output
}


function Request-ApplicationJSON {
    <#
    .SYNOPSIS
        Generates a Applicability JSON file to be imported into the ATT&CK Navigator. Based on a template and a filled Excel sheet
        Requires module ImportExcel, Install it like this PS C:\> Install-Module ImportExcel
    .DESCRIPTION
        Generates a JSON file to be imported into the ATT&CK Navigator. The mitre_data_assessment Excel file contains all Techniques, which can be updated via Invoke-ATTACK-UpdateExcel.
        These techniques are rated on the likelihood of achieving full coverage of that technique in Alerting, Hunting and/or Forensics The generation date is added to the description.
        
        This is all gathered into a JSON file which can be opened here;
        https://mitre-attack.github.io/attack-navigator/enterprise/
    .EXAMPLE
        PS C:\> Request-ApplicationJSON -Excelfile .\mitre_data_assessment.xlsx -Template .\applicability-template.json -Type Alerting -Output ATTACKapplicability-Alerting.json
    .INPUTS
        Excelfile = The Excel file containing all Datasource scores, default is .\mitre_data_assessment.xlsx
        Template = The ATT&CK Navigator JSON template, default is .\template.json
        Type = Alerting, Hunting or Forensics, default is Alerting
    .OUTPUTS
        Output = The name of the JSON file you want to generate for the ATT&CK Navigator, default is ATTACKapplicability-TYPE.json
    .NOTES
    #>    
    param (
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [ValidateSet('Alerting','Hunting,Forensics')]                              
    [string]
    $Type = 'Alerting',        
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [string]
    $Excelfile = 'mitre_data_assessment.xlsx',
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [string]
    $Template = 'applicability-template.json',
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [string]
    $Title = ($Type+' Coverage Probability'),        
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    $Output = ('ATTACKapplicability-'+$Type+'.json')
)

$lookup = Import-Excel $Excelfile -WorksheetName TechniqueApplication
$JSONtemplate = (Get-Content -Raw -Path $Template | ConvertFrom-Json)
$Date = (get-date).ToString("yyy-MM-dd")
# Define Variables
$techniques = @()
# main loop
foreach($line in $lookup)
{
# Create technique object with technique, applicability score
$technique = New-Object PSCustomObject -Property @{
    "techniqueID"=$line.ID;
    "score"=$line.$Type;
}
$techniques += $technique
}
$JSONtemplate.name = $Title
$JSONtemplate.description = $Date
# Insert the generated techniques into the json template
$JSONtemplate.techniques = $techniques
# Generate the ATT&CK navigator file
$JSONtemplate | ConvertTo-Json -Depth 5 | Out-File -Encoding ascii $Output
}

function Request-DefenseJSON {
    <#
    .SYNOPSIS
        Generates a Defense Bypassed rating JSON file to be imported into the ATT&CK Navigator. Based on a template and a filled Excel sheet
        Requires module ImportExcel, Install it like this PS C:\> Install-Module ImportExcel
    .DESCRIPTION
        Generates a JSON file to be imported into the ATT&CK Navigator. The mitre_data_assessment Excel file contains all Techniques, which can be updated via Invoke-ATTACK-UpdateExcel.
        These techniques are rated on the likelihood of achieving a bypass of the defensive measures of that techniques. The generation date is added to the description.
        
        This is all gathered into a JSON file which can be opened here;
        https://mitre-attack.github.io/attack-navigator/enterprise/
    .EXAMPLE
        PS C:\> Request-DefenseJSON -Excelfile .\mitre_data_assessment.xlsx -Template .\defense-template.json  -Output DefenseCoverage.json
    .INPUTS
        Excelfile = The Excel file containing all Datasource scores, default is .\mitre_data_assessment.xlsx
        Template = The ATT&CK Navigator JSON template, default is .\defense-template.json
    .OUTPUTS
        Output = The name of the JSON file you want to generate for the ATT&CK Navigator, default is DefenseCoverage.json
    .NOTES
    #>    
param (
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [string]
    $Excelfile = 'mitre_data_assessment.xlsx',
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [string]
    $Template = 'defense-template.json',
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [string]
    $Title = 'Defense Coverage',        
    [Parameter(Mandatory=$false,
               ValueFromPipelineByPropertyName=$true,
               Position=0)]
    [string]
    $Output = 'DefenseCoverage.json'
)

$lookup = Import-Excel $Excelfile -WorksheetName DefenseMitigation
$mitre = Import-Excel $Excelfile -WorksheetName DefenseBypassWeights
$JSONtemplate = (Get-Content -Raw -Path $Template | ConvertFrom-Json)
$Date = (get-date).ToString("yyy-MM-dd")
$finalresult = @()
# main loop
foreach($line in $mitre)
{
# Collect info
$DataSources = $line."Defense Bypassed"
$weights = $line.Weight -split ";"
# Define Variables
$techniques = @()
$techniquescore = 0
# Comma-separated datasources
$i = 0;
foreach($ds in $DataSources -split ",")
{
    # Collect info
    $DataSourceEvents = $lookup | Where-Object Defense -eq $ds
    $weight = ($weights[$i])  
    # Variables
    $total = 0
    $metas = @()
    # Iterate over DataSourceEvents
    foreach($f in $DataSourceEvents)
    {
        $total += ($f.Score * $weight)
        $meta = New-Object PSCustomObject -Property @{
            "name"="$($ds):$($f.Event)";
            "value"="Score: $($f.Score * $weight)"
        }
        $metas += $meta
    }       
    # Create technique object with technique, datasource score and events in metadata per datasource
    if ($line.Weight -eq 0) {
        $technique = New-Object PSCustomObject -Property @{
            "techniqueID"=$line.ID;
            "score"=$total;
            "metadata"=$metas;
            "enabled"='false'
        }
    }
    else {
        $technique = New-Object PSCustomObject -Property @{
            "techniqueID"=$line.ID;
            "score"=$total;
            "metadata"=$metas;
            "enabled"='true'
        }
    }

    # Add Technique data to technique list
    $techniques += $technique
    # Add the technique datasource score to the technique total
    $techniquescore += $total
    $i += 1
}
$techniqueDSscore = 0
$techniqueMetadata = @()
$techniques | ForEach-Object -Begin {    
} -Process { 
    $techniqueDSscore += $_.score
    $techniqueMetadata += $_.metadata
}
$techniqueTotal = New-Object PSCustomObject -Property @{
    "techniqueID"=$technique.techniqueID;
    "score"=$techniqueDSscore;
    "metadata"=$techniqueMetadata;
    "enabled"=$technique.enabled
}
$finalresult += $techniqueTotal
}
$JSONtemplate.name = $Title
$JSONtemplate.description = $Date
# Insert the generated techniques into the json template
$JSONtemplate.techniques = $finalresult
# Generate the ATT&CK navigator file
$JSONtemplate | ConvertTo-Json -Depth 5 | Out-File -Encoding ascii $Output
}