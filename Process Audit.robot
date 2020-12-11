*** Test Cases ***
Block WSL
    [Documentation]     Блокировака WSL
    [Tags]              process     not ready

    Configurate AppControl    Processes/Mask REG_QWORD 0x2      Name REG_SZ BLOCK_WSL_PROC_AUDIT
    Run Test Process          -RunProcess 2

    Check Value In Log        profile: ProfileGUID [BLOCK_WSL_PROC_AUDIT]

Block WINSTORE
    [Documentation]     Блокировака Winstore
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x1     Name REG_SZ BLOCK_WINSTORE_PROC_AUDIT
    Start Script           C:/App/Samples/Processes/winstore_sample.exe

    Check Value In Log     profile: ProfileGUID [BLOCK_WINSTORE_PROC_AUDIT]

Block Run From ADS
    [Documentation]     Блокировака запуска через ADS
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x4000      Name REG_SZ BLOCK_RUN_FROM_ADS_PROC_AUDIT
    Start Script               C:/App/Dependence/check.bat

    Check Value In Log      profile: ProfileGUID [BLOCK_RUN_FROM_ADS_PROC_AUDIT]

Block Cert Revoked
    [Documentation]     Блокировака Cert Revoked
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x20        Name REG_SZ BLOCK_CERT_REVOKED_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/revoked_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_REVOKED_PROC_AUDIT]

Block Cert Malware
    [Documentation]     Блокировака Cert Malware
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x40        Name REG_SZ BLOCK_CERT_MALWARE_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/adware_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_ADWARE_PROC_AUDIT]

Block Cert Adware
    [Documentation]     Блокировака Cert Adware
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x80        Name REG_SZ BLOCK_CERT_ADWARE_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/malware_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_MALWARE_PROC_AUDIT]

Block Cert Grey
    [Documentation]     Блокировака Cert Adware
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x100        Name REG_SZ BLOCK_CERT_GREY_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/grey_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_GREY_PROC_AUDIT]

Block Vert Hacktool
    [Documentation]     Блокировака Cert Adware
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x8000        Name REG_SZ BLOCK_CERT_HACKTOOL_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/hacktool_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_HACKTOOL_PROC_AUDIT]

Block File Run Sysint Utils
    [Documentation]     Блокировака File Run Sysint Utils
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x4        Name REG_SZ BLOCK_FILE_RUN_SYSINT_UTILS_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/sysint_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_FILE_RUN_SYSINT_UTILS_PROC_AUDIT]

Block File Run Syspic Ext
    [Documentation]     Блокировака File Run Syspic Ext
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x8        Name REG_SZ BLOCK_WITH_SUSPIC_EXT_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/suspic_sample.jpg.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_WITH_SUSPIC_EXT_PROC_AUDIT]

Block Cert Malformed
    [Documentation]     Блокировака Cert Malformed
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x200        Name REG_SZ BLOCK_CERT_MALFORMED_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/malformed_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_MALFORMED_PROC_AUDIT]

Block From Temp
    [Documentation]     Блокировака из Temp
    [Tags]              process

    Configurate AppControl    Processes/Mask REG_QWORD 0x800        Name REG_SZ BLOCK_FROM_TEMP_PROC_AUDIT

    Copy File                  C:/App/Samples/Processes/unsigned_process_sample.exe        C:/Windows/Temp

    Start Script               C:/Windows/Temp/unsigned_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_FROM_TEMP_PROC_AUDIT]

Block From Net
    [Documentation]     Блокировака из Net
    [Tags]              process

    Configurate AppControl    Processes/Mask REG_QWORD 0x1000        Name REG_SZ BLOCK_FROM_NET_PROC_AUDIT

    Copy File                  C:/App/Samples/Processes/unsigned_process_sample.exe        Z:

    Run Keyword And Ignore Error       Start Process              Z:/unsigned_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_FROM_NET_PROC_AUDIT]

Block From Removable
    [Documentation]     Блокировака из Removable
    [Tags]              process

    Configurate AppControl    Processes/Mask REG_QWORD 0x2000       Name REG_SZ BLOCK_RUN_FROM_REMOVABLE_PROC_AUDIT

    Copy File                  C:/App/Samples/Processes/unsigned_process_sample.exe        R:

    Start Script               R:/unsigned_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_RUN_FROM_REMOVABLE_PROC_AUDIT]

Block Cert Unsigned
    [Documentation]     Блокировака Cert Unsigned
    [Tags]              process     not ready

    Configurate AppControl     Processes/Mask REG_QWORD 0x10       Name REG_SZ BLOCK_CERT_UNSIGNED_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/unsigned_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_UNSIGNED_PROC_AUDIT]

Block Cert Selfsigned
    [Documentation]     Блокировака Cert Unsigned
    [Tags]              process

    Configurate AppControl     Processes/Mask REG_QWORD 0x400       Name REG_SZ BLOCK_CERT_SELFSIGNED_PROC_AUDIT
    Start Script               C:/App/Samples/Processes/self_signed_process_sample.exe

    Check Value In Log      profile: ProfileGUID [BLOCK_CERT_SELFSIGNED_PROC_AUDIT]

*** Keywords ***
Prepare environment
    Refresh Log File    dwservice.log

    Run Keyword And Ignore Error             Turn off self-protection

    Run AppControl      -Create              ProfileGUID     RuleGUID
    Run AppControl      -Activate            ProfileGUID     RuleGUID
    Run AppControl      -AddProfileValue     ProfileGUID     Processes/Enabled REG_DWORD 0x1
    Run AppControl      -AddProfileValue     ProfileGUID     TestMode REG_DWORD 0x1
*** Settings ***
Default Tags      owner-a.darkwolf
Suite Setup       Prepare environment
Suite Teardown      Restart Dwservice
Resource          appcontrol.robot