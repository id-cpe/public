## Suspicious mailbox forward OWA
ID: 40404040-4040-4040-8888-000000000000

Sigma definition:
```yaml
detection:
    selection_rightevent: #This determines the structure of the rest of the log
        Workload|startswith: 'Exchange'
        Operation:
            - 'New-InboxRule'
            - 'Set-InboxRule'
    scope_restricted: # There are substantial filters such that this does not cover all messages
        - Parameters.BodyContainsWords|re: '.{1,}'
        - Parameters.SubjectContainsWords|re: '.{1,}'
        - Parameters.SubjectOrBodyContainsWords|re: '.{1,}'
        - Parameters.From|contains: '@'
        - Parameters.MessageTypeMatches:
            - 'AutomaticReply'
            - 'AutomaticForward'
            - 'Calendaring'
            - 'CalendaringResponse'
            - 'Voicemail'
            - 'ReadReceipt'
            - 'NonDeliveryReport'
    scope_sensitivescope2: # But if the restriction is filtering for sensitive messages, we still trigger
        - Parameters.BodyContainsWords|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
            - 'hack'
            - 'virus'
            - 'malware'
        - Parameters.SubjectContainsWords|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
            - 'hack'
            - 'virus'
            - 'malware'
        - Parameters.SubjectOrBodyContainsWords|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
            - 'hack'
            - 'virus'
            - 'malware'
    action_sensitiveaction: # We use regexes to check if the fields contain an email address
        - Parameters.RedirectTo|contains: '@' #Redirect without changing any headers (in Outlook thisi is the no modify flag)
        - Parameters.ForwardTo|contains: '@'    #Forward message
        - Parameters.ForwardAsAttachmentTo|contains: '@' #Forward, attach original message as attachment
    condition: all of selection* and (not scope_restricted or scope_sensitivescope2) and any of action* and not any of filter*
```

Kibana Query Language:
```
(
    Workload:Exchange* AND (
        Operation:(New\-InboxRule OR Set\-InboxRule)
    )
) AND (
    (
        NOT (
            Parameters.BodyContainsWords:/.{1,}/ OR 
            Parameters.SubjectContainsWords:/.{1,}/ OR 
            Parameters.SubjectOrBodyContainsWords:/.{1,}/ OR 
            Parameters.From:*@* OR 
            (
                Parameters.MessageTypeMatches:(AutomaticReply OR AutomaticForward OR Calendaring OR CalendaringResponse OR Voicemail OR ReadReceipt OR NonDeliveryReport)
            )
        )
    ) OR (
        (
            Parameters.BodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
        ) OR (
            Parameters.SubjectContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
        ) OR (
            Parameters.SubjectOrBodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
        )
    )
) AND (
    Parameters.RedirectTo:*@* OR 
    Parameters.ForwardTo:*@* OR 
    Parameters.ForwardAsAttachmentTo:*@*) AND 
    (NOT ()
)
```

PowerShell:
```powershell
#(
#    Workload:Exchange* AND (
#        Operation:(New\-InboxRule OR Set\-InboxRule)
#    )
#) 
$selection_rightevent = $logRecord.Workload -like "Exchange*" -and $logRecord.Operation -in $('New-InboxRule', 'Set-InboxRule')
if (!$selection_rightevent) { return } #Speed up, does not affect result
#AND (
#     (
#         NOT (
#             Parameters.BodyContainsWords:/.{1,}/ OR 
#             Parameters.SubjectContainsWords:/.{1,}/ OR 
#             Parameters.SubjectOrBodyContainsWords:/.{1,}/ OR 
#             Parameters.From:*@* OR 
#             (
#                 Parameters.MessageTypeMatches:(AutomaticReply OR AutomaticForward OR Calendaring OR CalendaringResponse OR Voicemail OR ReadReceipt OR NonDeliveryReport)
#             )
#         )
    $scope_restricted = $logRecord.Parameters.BodyContainsWords.Length -gt 0 -or `
                $logRecord.Parameters.SubjectContainsWords.Length -gt 0 -or `
                $logRecord.Parameters.SubjectOrBodyContainsWords.Length -gt 0 -or `
                $logRecord.Parameters.From -like "*@*" -or `
                $logRecord.Parameters.MessageTypeMatches -in @('AutomaticReply', 'AutomaticForward', 'Calendaring', 'CalendaringResponse', 'Voicemail', 'ReadReceipt', 'NonDeliveryReport')
#     ) OR (
#         (
#             Parameters.BodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
#         ) OR (
#             Parameters.SubjectContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
#         ) OR (
#             Parameters.SubjectOrBodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
#         )
#     )
    $scope_sensitivescope2 = $logRecord.Parameters.BodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
                $logRecord.Parameters.SubjectContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
                $logRecord.Parameters.SubjectOrBodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware"
    # ) AND (
#     Parameters.RedirectTo:*@* OR 
#     Parameters.ForwardTo:*@* OR 
#     Parameters.ForwardAsAttachmentTo:*@*) AND 
#     (NOT ()
    $action_sensitiveaction = $logRecord.Parameters.RedirectTo -like '*@*' -or `
                $logRecord.Parameters.ForwardTo -like '*@*' -or `
                $logRecord.Parameters.ForwardAsAttachmentTo -like '*@*'
    # )

$selection_rightevent -and (!$scope_restricted -or $scope_sensitivescope2) -and $action_sensitiveaction
```

## Suspicious mailbox rule for deleting through OWA
ID: 40404040-4040-4040-8888-000000000001

Sigma definition:
```yaml
detection:
    selection_rightevent: #This determines the structure of the rest of the log
        Workload|startswith: 'Exchange'
        Operation:
            - 'New-InboxRule'
            - 'Set-InboxRule'
    scope_restricted: # There are substantial filters such that this does not cover all messages
        - Parameters.BodyContainsWords|re: '.{1,}'
        - Parameters.SubjectContainsWords|re: '.{1,}'
        - Parameters.SubjectOrBodyContainsWords|re: '.{1,}'
        - Parameters.From|contains: '@'
        - Parameters.MessageTypeMatches:
            - 'AutomaticReply'
            - 'AutomaticForward'
            - 'Calendaring'
            - 'CalendaringResponse'
            - 'Voicemail'
            - 'ReadReceipt'
            - 'NonDeliveryReport'
    scope_sensitivescope2: # But if the restriction is filtering for sensitive messages, we still trigger
        - Parameters.BodyContainsWords|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
            - 'hack'
            - 'virus'
            - 'malware'
        - Parameters.SubjectContainsWords|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
            - 'hack'
            - 'virus'
            - 'malware'
        - Parameters.SubjectOrBodyContainsWords|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
            - 'hack'
            - 'virus'
            - 'malware'
    action_sensitiveaction:
        - Parameters.DeleteMessage: true
        - Parameters.SoftDeleteMessage: true
        - Parameters.MoveToFolder|contains: 'deleted'
    condition: all of selection* and (not scope_restricted or scope_sensitivescope2) and any of action* and not any of filter*
```

Kibana Query Language:
```
(
    Workload:Exchange* AND (
        Operation:(New\-InboxRule OR Set\-InboxRule)
    )
) AND (
    (
        NOT (
            Parameters.BodyContainsWords:/.{1,}/ OR 
            Parameters.SubjectContainsWords:/.{1,}/ OR 
            Parameters.SubjectOrBodyContainsWords:/.{1,}/ OR 
            Parameters.From:*@* OR 
            (
                Parameters.MessageTypeMatches:(AutomaticReply OR AutomaticForward OR Calendaring OR CalendaringResponse OR Voicemail OR ReadReceipt OR NonDeliveryReport)
            )
        )
    ) OR (
        (
            Parameters.BodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)) OR 
            (Parameters.SubjectContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)) OR 
            (Parameters.SubjectOrBodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
        )
    )
) AND (
    Parameters.DeleteMessage:true OR 
    Parameters.SoftDeleteMessage:true OR 
    Parameters.MoveToFolder:*deleted*
) AND (
    NOT ()
)
```

PowerShell:
```powershell
# (
#     Workload:Exchange* AND (
#         Operation:(New\-InboxRule OR Set\-InboxRule)
#     )
$selection_rightevent = $logRecord.Workload -like "Exchange*" -and $logRecord.Operation -in $('New-InboxRule', 'Set-InboxRule')
if (!$selection_rightevent) { return } #Speed up, does not affect result
# ) AND (
#     (
#         NOT (
#             Parameters.BodyContainsWords:/.{1,}/ OR 
#             Parameters.SubjectContainsWords:/.{1,}/ OR 
#             Parameters.SubjectOrBodyContainsWords:/.{1,}/ OR 
#             Parameters.From:*@* OR 
#             (
#                 Parameters.MessageTypeMatches:(AutomaticReply OR AutomaticForward OR Calendaring OR CalendaringResponse OR Voicemail OR ReadReceipt OR NonDeliveryReport)
#             )
#         )
    $scope_restricted = $logRecord.Parameters.BodyContainsWords.Length -gt 0 -or `
                $logRecord.Parameters.SubjectContainsWords.Length -gt 0 -or `
                $logRecord.Parameters.SubjectOrBodyContainsWords.Length -gt 0 -or `
                $logRecord.Parameters.From -like "*@*" -or `
                $logRecord.Parameters.MessageTypeMatches -in @('AutomaticReply', 'AutomaticForward', 'Calendaring', 'CalendaringResponse', 'Voicemail', 'ReadReceipt', 'NonDeliveryReport')
#     ) OR (
#         (
#             Parameters.BodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)) OR 
#             (Parameters.SubjectContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)) OR 
#             (Parameters.SubjectOrBodyContainsWords:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
#         )
#     )
    $scope_sensitivescope2 = $logRecord.Parameters.BodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
                $logRecord.Parameters.SubjectContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
                $logRecord.Parameters.SubjectOrBodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware"
# ) AND (
#   Parameters.DeleteMessage:true OR 
#   Parameters.SoftDeleteMessage:true OR 
#   Parameters.MoveToFolder:*deleted*
    $action_sensitiveaction = $logRecord.Parameters.DeleteMessage -eq $True -or `
                $logRecord.Parameters.SoftDeleteMessage -eq $True -or `
                $logRecord.Parameters.MoveToFolder -like '*deleted*'
# ) AND (
#     NOT ()
# )
$selection_rightevent -and (!$scope_restricted -or $scope_sensitivescope2) -and $action_sensitiveaction
```

## Suspicious mailbox forward Outlook.exe
ID: 40404040-4040-4040-8888-000000000010

Sigma definition:
```yaml
detection:
    selection_rightevent: #This determines the structure of the rest of the log
        Workload|startswith: 'Exchange'
        Operation: 'UpdateInboxRules'
        OperationProperties.RuleOperation:
          - 'AddMailboxRule'
          - 'ModifyMailboxRule'
    scope_fullscope:
        OperationProperties.RuleCondition:
            - ''
            - 'MessageToMe Equal True'
    scope_sensitivescope1:
        OperationProperties.RuleCondition|contains:
            - 'SubString'
            - 'SubjectProperty'
            - 'BodyProperty'
    scope_sensitivescope2:
        OperationProperties.RuleCondition|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
    action_sensitiveaction:
        OperationProperties.RuleActions|contains:
            - 'Forward'
    condition: all of selection* and (scope_fullscope or (scope_sensitivescope1 and scope_sensitivescope2)) and any of action* and not any of filter*
```

Kibana Query Language:
```
(
    Workload:Exchange* AND 
    Operation:UpdateInboxRules AND (
        OperationProperties.RuleOperation:(AddMailboxRule OR ModifyMailboxRule)
    )
) AND (
    (
        OperationProperties.RuleCondition:("" OR "MessageToMe\ Equal\ True")
    ) OR (
        (
            OperationProperties.RuleCondition:(*SubString* OR *SubjectProperty* OR *BodyProperty*)) AND 
            (OperationProperties.RuleCondition:(*account* OR *password* OR *reset* OR *secure* OR *confidential*)
        )
    )
) AND 
OperationProperties.RuleActions:*Forward* AND
(
    NOT ()
)
```

PowerShell:
```powershell
# (
#     Workload:Exchange* AND 
#     Operation:UpdateInboxRules AND (
#         OperationProperties.RuleOperation:(AddMailboxRule OR ModifyMailboxRule)
#     )
$selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
    $logRecord.Operation -eq 'UpdateInboxRules' -and `
    $logRecord.OperationProperties.RuleOperation -in $('AddMailboxRule', 'ModifyMailboxRule')
if (!$selection_rightevent) { return } #Speed up, does not affect result
# ) AND (
#     (
#         OperationProperties.RuleCondition:("" OR "MessageToMe\ Equal\ True")
$scope_fullscope = $logRecord.OperationProperties.RuleCondition -eq '' -or `
    $logRecord.OperationProperties.RuleCondition -eq 'MessageToMe\ Equal\ True'
#     ) OR (
#         (
#             OperationProperties.RuleCondition:(*SubString* OR *SubjectProperty* OR *BodyProperty*)) AND 
#             (OperationProperties.RuleCondition:(*account* OR *password* OR *reset* OR *secure* OR *confidential*)
#         )
#     )
$scope_sensitivescope1 = $logRecord.OperationProperties.RuleCondition -match 'SubString|SubjectProperty|BodyProperty'
$scope_sensitivescope2 = $logRecord.OperationProperties.RuleCondition -match 'account|password|reset|secure|confidential'
# ) AND 
# OperationProperties.RuleActions:*Forward* AND
# (
#     NOT ()
# )
$action_sensitiveaction = $logRecord.OperationProperties.RuleActions -like '*Forward*'

$selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
```

## Suspicious mailbox rule for deleting in Outlook.exe
ID: 40404040-4040-4040-8888-000000000011

Sigma definition:
```yaml
detection:
    selection_rightevent: #This determines the structure of the rest of the log
        Workload|startswith: 'Exchange'
        Operation: 'UpdateInboxRules'
        OperationProperties.RuleOperation:
          - 'AddMailboxRule'
          - 'ModifyMailboxRule'
    scope_fullscope:
        OperationProperties.RuleCondition:
            - ''
            - 'MessageToMe Equal True'
    scope_sensitivescope1:
        OperationProperties.RuleCondition|contains:
            - 'SubString'
            - 'SubjectProperty'
            - 'BodyProperty'
    scope_sensitivescope2:
        OperationProperties.RuleCondition|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
            - 'hack'
            - 'virus'
            - 'malware'
    action_sensitiveaction:
        OperationProperties.RuleActions|contains:
            - 'Move'
            - 'Delete'
    condition: all of selection* and (scope_fullscope or (scope_sensitivescope1 and scope_sensitivescope2)) and any of action* and not any of filter*
```

Kibana Query Language:
```
(
    Workload:Exchange* AND 
    Operation:UpdateInboxRules AND (
        OperationProperties.RuleOperation:(AddMailboxRule OR ModifyMailboxRule)
    )
) AND (
    (
        OperationProperties.RuleCondition:("" OR "MessageToMe\ Equal\ True")
    ) OR (
        (
            OperationProperties.RuleCondition:(*SubString* OR *SubjectProperty* OR *BodyProperty*)
        ) AND (
            OperationProperties.RuleCondition:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
        )
    )
) AND (
    OperationProperties.RuleActions:(*Move* OR *Delete*)
) AND (
    NOT ()
)
```

PowerShell:
```powershell
# (
#     Workload:Exchange* AND 
#     Operation:UpdateInboxRules AND (
#         OperationProperties.RuleOperation:(AddMailboxRule OR ModifyMailboxRule)
#     )
$selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
    $logRecord.Operation -eq 'UpdateInboxRules' -and `
    $logRecord.OperationProperties.RuleOperation -in $('AddMailboxRule', 'ModifyMailboxRule')
if (!$selection_rightevent) { return } #Speed up, does not affect result
# ) AND (
#     (
#         OperationProperties.RuleCondition:("" OR "MessageToMe\ Equal\ True")
$scope_fullscope = $logRecord.OperationProperties.RuleCondition -eq '' -or `
    $logRecord.OperationProperties.RuleCondition -eq 'MessageToMe\ Equal\ True'
#     ) OR (
#         (
#             OperationProperties.RuleCondition:(*SubString* OR *SubjectProperty* OR *BodyProperty*)
#           ) AND ( 
#             OperationProperties.RuleCondition:(*account* OR *password* OR *reset* OR *secure* OR *confidential* OR *hack* OR *virus* OR *malware*)
#         )
#     )
$scope_sensitivescope1 = $logRecord.OperationProperties.RuleCondition -match 'SubString|SubjectProperty|BodyProperty'
$scope_sensitivescope2 = $logRecord.OperationProperties.RuleCondition -match 'account|password|reset|secure|confidential|hack|virus|malware'
# ) AND 
# OperationProperties.RuleActions:(*Move* OR *Delete*)
# (
#     NOT ()
# )
$action_sensitiveaction = $logRecord.OperationProperties.RuleActions -match 'Move|Delete'

$selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
```

## Suspicious mailbox forward Graph API
ID: 40404040-4040-4040-8888-000000000020

Sigma definition:
```yaml
detection:
    selection_rightevent: #This determines the structure of the rest of the log
        Workload|startswith: 'Exchange'
        Operation: 'UpdateInboxRules'
        OperationProperties.RuleOperation:
          - 'Create'
    scope_fullscope:
        OperationProperties.Conditions:
            - ''
    scope_sensitivescope1:
        OperationProperties.Conditions|contains:
            - 'Contains'
            - 'Subject'
            - 'Body'
    scope_sensitivescope2:
        OperationProperties.ServerRule|base64offset|contains:
            - 'account'
            - 'password'
            - 'reset'
            - 'secure'
            - 'confidential'
    action_sensitiveaction:
        OperationProperties.Actions|contains:
            - 'Forward'
    condition: all of selection* and (scope_fullscope or (scope_sensitivescope1 and scope_sensitivescope2)) and any of action* and not any of filter*
```

Kibana Query Language:
```
(
    Workload:Exchange* AND 
    Operation:UpdateInboxRules AND 
    OperationProperties.RuleOperation:Create
) AND (
    OperationProperties.Conditions:"" OR (
        (
            OperationProperties.Conditions:(*Contains* OR *Subject* OR *Body*)
        ) AND (
            OperationProperties.ServerRule:*QUNDT1VOV* OR 
            OperationProperties.ServerRule:*FDQ09VTl* OR 
            OperationProperties.ServerRule:*BQ0NPVU5U* OR 
            OperationProperties.ServerRule:*UEFTU1dPUk* OR 
            OperationProperties.ServerRule:*BBU1NXT1JE* OR 
            OperationProperties.ServerRule:*QQVNTV09SR* OR 
            OperationProperties.ServerRule:*UkVTRV* OR 
            OperationProperties.ServerRule:*JFU0VU* OR 
            OperationProperties.ServerRule:*SRVNFV* OR 
            OperationProperties.ServerRule:*U0VDVVJF* OR 
            OperationProperties.ServerRule:*NFQ1VSR* OR 
            OperationProperties.ServerRule:*TRUNVUk* OR 
            OperationProperties.ServerRule:*Q09ORklERU5USUFM* OR 
            OperationProperties.ServerRule:*NPTkZJREVOVElBT* OR 
            OperationProperties.ServerRule:*DT05GSURFTlRJQU*
        )
    )
) AND 
OperationProperties.Actions:*Forward* AND 
(NOT ())
```

PowerShell:
```powershell
# (
#     Workload:Exchange* AND 
#     Operation:UpdateInboxRules AND 
#     OperationProperties.RuleOperation:Create
# ) AND (
$selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
    $logRecord.Operation -eq 'UpdateInboxRules' -and `
    $logRecord.OperationProperties.RuleOperation -in $('Create')
if (!$selection_rightevent) { return } #Speed up, does not affect result

#     OperationProperties.Conditions:"" OR (
$scope_fullscope = $logRecord.OperationProperties.Conditions -eq ''

#         (
#             OperationProperties.Conditions:(*Contains* OR *Subject* OR *Body*)
#         ) AND (
        #     OperationProperties.ServerRule:*QUNDT1VOV* OR 
        #     OperationProperties.ServerRule:*FDQ09VTl* OR 
        #     OperationProperties.ServerRule:*BQ0NPVU5U* OR 
        #     OperationProperties.ServerRule:*UEFTU1dPUk* OR 
        #     OperationProperties.ServerRule:*BBU1NXT1JE* OR 
        #     OperationProperties.ServerRule:*QQVNTV09SR* OR 
        #     OperationProperties.ServerRule:*UkVTRV* OR 
        #     OperationProperties.ServerRule:*JFU0VU* OR 
        #     OperationProperties.ServerRule:*SRVNFV* OR 
        #     OperationProperties.ServerRule:*U0VDVVJF* OR 
        #     OperationProperties.ServerRule:*NFQ1VSR* OR 
        #     OperationProperties.ServerRule:*TRUNVUk* OR 
        #     OperationProperties.ServerRule:*Q09ORklERU5USUFM* OR 
        #     OperationProperties.ServerRule:*NPTkZJREVOVElBT* OR 
        #     OperationProperties.ServerRule:*DT05GSURFTlRJQU*
        # )
#     )
$scope_sensitivescope1 = $logRecord.OperationProperties.Conditions -match 'Contains|Subject|Body'
$scope_sensitivescope2 = $logRecord.OperationProperties.ServerRule -match 'QUNDT1VOV|FDQ09VTl|BQ0NPVU5U|UEFTU1dPUk|BBU1NXT1JE|QQVNTV09SR|UkVTRV|JFU0VU|SRVNFV|U0VDVVJF|NFQ1VSR|TRUNVUk|Q09ORklERU5USUFM|NPTkZJREVOVElBT|DT05GSURFTlRJQU'

# ) AND 
# OperationProperties.Actions:*Forward* AND 
# (NOT ())

$action_sensitiveaction = $logRecord.OperationProperties.Actions -match 'Forward'

$selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
```

## Suspicious mailbox rule for deleting Graph API
ID: 40404040-4040-4040-8888-000000000021

Sigma definition:
```yaml
detection:
    selection_rightevent: #This determines the structure of the rest of the log
        Workload|startswith: 'Exchange'
        Operation: 'UpdateInboxRules'
        OperationProperties.RuleOperation:
          - 'Create'
    scope_fullscope:
        OperationProperties.Conditions:
            - ''
    scope_sensitivescope1:
        OperationProperties.Conditions|contains:
            - 'Contains'
            - 'Subject'
            - 'Body'
    scope_sensitivescope2:
        OperationProperties.ServerRule|base64offset|contains:
            - 'ACCOUNT'
            - 'PASSWORD'
            - 'RESET'
            - 'SECURE'
            - 'CONFIDENTIAL'
            - 'HACK'
            - 'VIRUS'
            - 'MALWARE'
    action_sensitiveaction:
        OperationProperties.Actions|contains:
            - 'Move'
            - 'Delete'
    condition: all of selection* and (scope_fullscope or (scope_sensitivescope1 and scope_sensitivescope2)) and any of action* and not any of filter*
```

Kibana Query Language:
```
(
    Workload:Exchange* AND 
    Operation:UpdateInboxRules AND 
    OperationProperties.RuleOperation:Create
) AND (
    OperationProperties.Conditions:"" OR (
        (
            OperationProperties.Conditions:(*Contains* OR *Subject* OR *Body*)
        ) AND (
            OperationProperties.ServerRule:*QUNDT1VOV* OR 
            OperationProperties.ServerRule:*FDQ09VTl* OR 
            OperationProperties.ServerRule:*BQ0NPVU5U* OR 
            OperationProperties.ServerRule:*UEFTU1dPUk* OR 
            OperationProperties.ServerRule:*BBU1NXT1JE* OR 
            OperationProperties.ServerRule:*QQVNTV09SR* OR 
            OperationProperties.ServerRule:*UkVTRV* OR 
            OperationProperties.ServerRule:*JFU0VU* OR 
            OperationProperties.ServerRule:*SRVNFV* OR 
            OperationProperties.ServerRule:*U0VDVVJF* OR 
            OperationProperties.ServerRule:*NFQ1VSR* OR 
            OperationProperties.ServerRule:*TRUNVUk* OR 
            OperationProperties.ServerRule:*Q09ORklERU5USUFM* OR 
            OperationProperties.ServerRule:*NPTkZJREVOVElBT* OR 
            OperationProperties.ServerRule:*DT05GSURFTlRJQU* OR 
            OperationProperties.ServerRule:*SEFDS* OR 
            OperationProperties.ServerRule:*hBQ0* OR 
            OperationProperties.ServerRule:*IQUNL* OR 
            OperationProperties.ServerRule:*VklSVV* OR 
            OperationProperties.ServerRule:*ZJUlVT* OR 
            OperationProperties.ServerRule:*WSVJVU* OR 
            OperationProperties.ServerRule:*TUFMV0FSR* OR 
            OperationProperties.ServerRule:*1BTFdBUk* OR 
            OperationProperties.ServerRule:*NQUxXQVJF*
        )
    )
) AND (
    OperationProperties.Actions:(*Move* OR *Delete*)
) AND (
    NOT ()
)
```

PowerShell:
```powershell
# (
#     Workload:Exchange* AND 
#     Operation:UpdateInboxRules AND 
#     OperationProperties.RuleOperation:Create
$selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
    $logRecord.Operation -eq 'UpdateInboxRules' -and `
    $logRecord.OperationProperties.RuleOperation -in $('Create')
if (!$selection_rightevent) { return } #Speed up, does not affect result

# ) AND (
#     OperationProperties.Conditions:"" OR (
$scope_fullscope = $logRecord.OperationProperties.Conditions -eq ''

#         (
#             OperationProperties.Conditions:(*Contains* OR *Subject* OR *Body*)
#         ) AND (
#             OperationProperties.ServerRule:*QUNDT1VOV* OR 
#             OperationProperties.ServerRule:*FDQ09VTl* OR 
#             OperationProperties.ServerRule:*BQ0NPVU5U* OR 
#             OperationProperties.ServerRule:*UEFTU1dPUk* OR 
#             OperationProperties.ServerRule:*BBU1NXT1JE* OR 
#             OperationProperties.ServerRule:*QQVNTV09SR* OR 
#             OperationProperties.ServerRule:*UkVTRV* OR 
#             OperationProperties.ServerRule:*JFU0VU* OR 
#             OperationProperties.ServerRule:*SRVNFV* OR 
#             OperationProperties.ServerRule:*U0VDVVJF* OR 
#             OperationProperties.ServerRule:*NFQ1VSR* OR 
#             OperationProperties.ServerRule:*TRUNVUk* OR 
#             OperationProperties.ServerRule:*Q09ORklERU5USUFM* OR 
#             OperationProperties.ServerRule:*NPTkZJREVOVElBT* OR 
#             OperationProperties.ServerRule:*DT05GSURFTlRJQU* OR 
#             OperationProperties.ServerRule:*SEFDS* OR 
#             OperationProperties.ServerRule:*hBQ0* OR 
#             OperationProperties.ServerRule:*IQUNL* OR 
#             OperationProperties.ServerRule:*VklSVV* OR 
#             OperationProperties.ServerRule:*ZJUlVT* OR 
#             OperationProperties.ServerRule:*WSVJVU* OR 
#             OperationProperties.ServerRule:*TUFMV0FSR* OR 
#             OperationProperties.ServerRule:*1BTFdBUk* OR 
#             OperationProperties.ServerRule:*NQUxXQVJF*
#         )
#     )
$scope_sensitivescope1 = $logRecord.OperationProperties.Conditions -match 'Contains|Subject|Body'
$scope_sensitivescope2 = $logRecord.OperationProperties.ServerRule -match 'QUNDT1VOV|FDQ09VTl|BQ0NPVU5U|UEFTU1dPUk|BBU1NXT1JE|QQVNTV09SR|UkVTRV|JFU0VU|SRVNFV|U0VDVVJF|NFQ1VSR|TRUNVUk|Q09ORklERU5USUFM|NPTkZJREVOVElBT|DT05GSURFTlRJQU|SEFDS|hBQ0|IQUNL|VklSVV|ZJUlVT|WSVJVU|TUFMV0FSR|1BTFdBUk|NQUxXQVJF'

# ) AND (
#     OperationProperties.Actions:(*Move* OR *Delete*)
# ) AND (
#     NOT ()
# )
$action_sensitiveaction = $logRecord.OperationProperties.Actions -match 'Move|Delete'

$selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
```

