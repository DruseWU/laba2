*** Test Cases ***
Block Unsave
    [Documentation]     Блокировака небезопасных версий драйверов
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x1      Name REG_SZ BLOCK_UNSAVE
    Run Test Process          -RunDriver 1 1

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_UNSAVE]

Block Cert Unsigned
    [Documentation]     Блокировака неподписанных сертификатов
    [Tags]              driver      sc      not ready

    Configurate AppControl    Drivers/Mask REG_QWORD 0x2      Name REG_SZ BLOCK_CERT_UNSIGNED
    Run Test Process          -RunDriver 1 2

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_UNSIGNED]

Block From Temp
    [Documentation]     Блокировака самоподписанных сертификатов
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x100      Name REG_SZ BLOCK_FROM_TEMP

    Copy File                 C:/App/Samples/Drivers/unsigned_driver_sample/x64/unsigned_driver_sample_64.sys       C:/Windows/Temp
    Run Test Process          -RunDriver 1 9 C:/Windows/Temp/unsigned_driver_sample_64.sys

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_FROM_TEMP]

Block From Net
    [Documentation]     Блокировака из сетевой папки
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x200      Name REG_SZ BLOCK_FROM_NET

    Copy File                 C:/App/Samples/Drivers/unsigned_driver_sample/x64/unsigned_driver_sample_64.sys       Z:
    Run Test Process          -RunDriver 1 10 Z:/unsigned_driver_sample_64.sys

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_FROM_NET]

Block From Removable
    [Documentation]     Блокировака из удаленного диска
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x400      Name REG_SZ BLOCK_RUN_FROM_REMOVABLE

    Copy File                 C:/App/Samples/Drivers/unsigned_driver_sample/x64/unsigned_driver_sample_64.sys       R:
    Run Test Process          -RunDriver 1 11 R:/unsigned_driver_sample_64.sys

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_RUN_FROM_REMOVABLE]

Block Cert Selfsigned
    [Documentation]     Блокировака самоподписанных сертификатов
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x80      Name REG_SZ BLOCK_CERT_SELFSIGNED
    Run Test Process          -RunDriver 1 8

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_SELFSIGNED]

Block Cert Malformed
    [Documentation]     Блокировака самоподписанных сертификатов
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x40      Name REG_SZ BLOCK_CERT_MALFORMED
    Run Test Process          -RunDriver 1 7

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_MALFORMED]

Block From ADS
    [Documentation]     Блокировака из альтернативных потоков
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x800      Name REG_SZ BLOCK_RUN_FROM_ADS
    Run Test Process          -RunDriver 1 12

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_RUN_FROM_ADS]

Block Cert Revoked
    [Documentation]     Блокировака из альтернативных потоков
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x4      Name REG_SZ BLOCK_CERT_REVOKED
    Run Test Process          -RunDriver 1 3

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_REVOKED]

Block Cert Malware
    [Documentation]     Блокировака из альтернативных потоков
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x8      Name REG_SZ BLOCK_CERT_MALWARE
    Run Test Process          -RunDriver 1 4

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_MALWARE]

Block Cert Adware
    [Documentation]     Блокировака из альтернативных потоков
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x10      Name REG_SZ BLOCK_CERT_ADWARE
    Run Test Process          -RunDriver 1 5

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_ADWARE]

Block Cert Grey
    [Documentation]     Блокировака из альтернативных потоков
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x20      Name REG_SZ BLOCK_CERT_GREY
    Run Test Process          -RunDriver 1 6

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_GREY]

Block Cert Hacktool
    [Documentation]     Блокировака из альтернативных потоков
    [Tags]              driver      sc

    Configurate AppControl    Drivers/Mask REG_QWORD 0x1000      Name REG_SZ BLOCK_CERT_HACKTOOL
    Run Test Process          -RunDriver 1 13

    Check Value In Log        load driver blocked by app control: profile: ProfileGUID [BLOCK_CERT_HACKTOOL]

*** Keywords ***
Prepare environment
    Run Keyword And Ignore Error             Turn off self-protection

    Run AppControl      -Create              ProfileGUID     RuleGUID
    Run AppControl      -Activate            ProfileGUID     RuleGUID
    Run AppControl      -AddProfileValue     ProfileGUID     Drivers/Enabled REG_DWORD 0x1

*** Settings ***
Default Tags      owner-a.darkwolf
Suite Setup       Prepare environment
Suite Teardown      Restart Dwservice
Resource          appcontrol.robot