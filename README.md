[![license](https://img.shields.io/github/license/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/blob/master/license.md)
![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/olafhartong/ATTACKdatamap.svg?style=flat-square)](https://github.com/olafhartong/ATTACKdatamap/commit/master)
[![Twitter](https://img.shields.io/twitter/follow/olafhartong.svg?style=social&label=Follow)](https://twitter.com/olafhartong)

# ATTACKdatamap
A datasource assessment on an event level to show potential coverage of the "MITRE ATT&CK" framework.

This tool is developed by me and has no affiliation with "MITRE" nor with its great "ATT&CK" team, it is developed with the intention to ease the mapping of data sources to assess one's potential coverate.

More details in a blogpost [here](https://medium.com/@olafhartong/assess-your-data-potential-with-att-ck-datamap-f44884cfed11)

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
This generates all MITRE ATT&CK relevant fields into a table and creates or updates the REF-DataSources worksheet in an Excel sheet

EXAMPLE

```PS C:\> Invoke-ATTACK-UpdateExcel -AttackPath .\enterprise-attack.json -Excelfile .\mitre_data_assessment.xlsx```

The -AttackPath and -Excelfile parameters are optional

## Get-ATTACKdata
This downloads the MITRE ATT&CK Enterprise JSON file

EXAMPLE

```PS C:\> Get-ATTACKdata -AttackPath ./enterprise-attack.json```

The -AttackPath parameter is optional
