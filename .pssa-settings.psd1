# PSScriptAnalyzer Settings
# For interactive, user-facing security hardening scripts

@{
    # Severity levels to check
    Severity = @('Error', 'Warning')
    
    # Exclude rules that don't apply to interactive scripts
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',           # We NEED colored console output for users
        'PSAvoidUsingInvokeExpression',    # Used intentionally in specific contexts
        'PSUseShouldProcessForStateChangingFunctions',  # Not applicable to system hardening
        'PSAvoidUsingConvertToSecureStringWithPlainText',  # False positive: Used for cryptographically generated passwords only
        'PSUseBOMForUnicodeEncodedFile'    # UTF-8 without BOM is project standard
    )
    
    # Include specific rules
    IncludeRules = @(
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingPlainTextForPassword',
        'PSMissingModuleManifestField',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSShouldProcess',
        'PSUseCompatibleSyntax'
    )
}
