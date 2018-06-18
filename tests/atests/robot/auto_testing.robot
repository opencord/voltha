*** Settings ***
Library           Process
Library           ../common/auto_test.py
Library           ../common/voltha.py
Library           ../common/preprovisioning.py

*** Variables ***
${LOG_DIR}        /tmp/voltha_test_results
${ROOT_DIR}       ${EMPTY}
${VOLTHA_DIR}     ${EMPTY}

*** Test Cases ***
Provisioning
    [Documentation]  Test VOLTHA Pre-provisioning
    ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}    auto_test.init    ${LOG_DIR}
    voltha.startVoltha    ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    preprovisioning.runTest    172.17.0.1    50060    ${LOG_DIR}

*** Keywords ***
