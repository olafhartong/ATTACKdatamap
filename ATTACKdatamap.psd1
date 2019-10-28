@{
    # If authoring a script module, the RootModule is the name of your .psm1 file
    RootModule = 'ATTACKdatamap.psm1'
    Author = 'Olaf Hartong <ATTACK@olafhartong.nl>'
    ModuleVersion = '1.0'
    GUID = '5436b2bb-91af-4a6e-91eb-39667a8f6b41'
    Copyright = '2019 Olaf Hartong'
    CompanyName = 'Olaf Hartong'
    Description = 'A datasource assessment on an event level to show potential ATT&CK coverage'

    # Minimum PowerShell version supported by this module (optional, recommended)
    # PowerShellVersion = ''

    # Which PowerShell Editions does this module work with? (Core, Desktop)
    CompatiblePSEditions = @('Desktop', 'Core')

    # Which PowerShell functions are exported from your module? (eg. Get-CoolObject)
    FunctionsToExport = @(
        'Request-ATTACKjson',
        'Invoke-ATTACKUpdateExcel',
        'Get-ATTACKdata',
        'Request-ApplicationJSON',
        'Request-DefenseJSON'
    )

    
    # Which PowerShell aliases are exported from your module? (eg. gco)
    AliasesToExport = @('*')

    # List of all files packaged with this module
    FileList = @(
    'ATTACKdatamap.psm1'
    )

    # Which PowerShell variables are exported from your module? (eg. Fruits, Vegetables)
    VariablesToExport = @('*')

    # PowerShell Gallery: Define your module's metadata
    PrivateData = @{
        PSData = @{
            # What keywords represent your PowerShell module? (eg. cloud, tools, framework, vendor)
            Tags = @('DFIR', 'ThreatHunting')

            # What software license is your code being released under? (see https://opensource.org/licenses)
            LicenseUri = 'https://github.com/olafhartong/ATTACKdatamap/blob/master/LICENSE'

            # What is the URL to your project's website?
            ProjectUri = 'https://github.com/olafhartong/ATTACKdatamap'

            # What is the URI to a custom icon file for your project? (optional)
            IconUri = ''

            # What new features, bug fixes, or deprecated features, are part of this release?
            ReleaseNotes = @'
'@
        }
    }

    # If your module supports updateable help, what is the URI to the help archive? (optional)
    # HelpInfoURI = ''
}