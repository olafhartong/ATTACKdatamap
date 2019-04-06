# ATTACKdatamap
A datasource assessment on an event level to show potential ATT&CK coverage


# Start
This tool requires module ImportExcel, Install it like this ```PS C:\> Install-Module ImportExcel```
Import the module with ```Import-Module .\ATTACKdatamap.psd1```

## Request-ATTACKjson
Generates a JSON file to be imported into the ATT&CK Navigator. The mitre_data_assessment.xlsx file contains all Techniques, which can be updated via Invoke-ATTACK-UpdateExcel.
Each technique contains DataSources, which are individually scored by me with a weight. The DataSourceEventTypes need to be scored per environment.
This script multiplies the respective DataSource scores and adds them to a total technique score. The generation date is added to the description.

EXAMPLE
```PS C:\> Request-ATTACKjson -Excelfile .\mitre_data_assessment.xlsx -Template .\template.json -Output 2019-03-23-ATTACKcoverage.json```

This is all gathered into a JSON file which can be opened here;
[MITRE ATT&CK Navigator/enterprise/](https://mitre-attack.github.io/attack-navigator/enterprise/)

## Invoke-ATTACK-UpdateExcel
Generates MITRE ATT&CK relevant fields into a table and creates or updates a worksheet in an Excel sheet
EXAMPLE
```PS C:\> Invoke-ATTACK-UpdateExcel -AttackPath .\enterprise-attack.json -Excelfile .\mitre_data_assessment.xlsx```

## Get-ATTACKdata
Downloads the MITRE ATT&CK Enterprise JSON file
EXAMPLE
```PS C:\> Get-ATTACKdata -AttackPath ./enterprise-attack.json```