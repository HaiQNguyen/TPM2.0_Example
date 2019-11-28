

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../include/tss2_esys.h"
#include "../include/test-options.h"
#include "../include/context-util.h"
#include "../include/tss2_common.h"
#include "../include/tss2_mu.h"
#include "../include/tss2_rc.h"
#include "../include/tss2_sys.h"
#include "../include/tss2_tcti.h"
#include "../include/tss2_tcti_device.h"
#include "../include/tss2_tcti_mssim.h"
#include "../include/tss2_tcti_tbs.h"
#include "../include/tss2_tctildr.h"
#include "../include/tss2_tpm2_types.h"

#include "../ttci_helper/ttci_helper.h"

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108

int
main(int argc, char *argv[])
{
    TSS2_RC rc;
    size_t tcti_size;
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_TCTI_CONTEXT *tcti_inner;
    ESYS_CONTEXT *esys_context;
    TSS2_ABI_VERSION abiVersion =
        { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL,
        TSS_SAPI_FIRST_VERSION };


    test_opts_t opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = "localhost",
        .socket_port = PORT_DEFAULT,
    };

    get_test_opts_from_env(&opts);
    if (sanity_check_test_opts(&opts) != 0) {
        printf("TPM Startup FAILED! Error in sanity check");
        exit(1);
    }
    tcti_inner = tcti_init_from_opts(&opts);
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    rc = tcti_proxy_initialize(NULL, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x", rc);
        return rc;
    }
    tcti_context = calloc(1, tcti_size);
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    rc = tcti_proxy_initialize(tcti_context, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    rc = Esys_Initialize(&esys_context, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        return 1;
    }
    rc = Esys_Startup(esys_context, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    rc = Esys_SetTimeout(esys_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x", rc);
        return 1;
    }

    TPM2B_DIGEST *randomBytes;
    rc = Esys_GetRandom(esys_context, 
                        ESYS_TR_NONE, 
                        ESYS_TR_NONE, 
                        ESYS_TR_NONE,
                        4, 
                        &randomBytes);

    if (rc != TPM2_RC_SUCCESS) {
        printf("GetRandom FAILED! Response Code : 0x%x", rc);
    }
    printf("Random bytes: %d %d %d %d \r\n", randomBytes->buffer[0], randomBytes->buffer[1], 
            randomBytes->buffer[2], randomBytes->buffer[3] );

    TPM2B_MAX_BUFFER data = { .size = 20,
                              .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                       1, 2, 3, 4, 5, 6, 7, 8, 9}};
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA1;
    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_OWNER;
    TPM2B_DIGEST *outHash;
    TPMT_TK_HASHCHECK *validation;

    rc = Esys_Hash(
        esys_context,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &data,
        hashAlg,
        hierarchy,
        &outHash,
        &validation);
    
    printf("digest: ");
    for(uint8_t i = 0; i  < 20; i++){
        printf("%d ", outHash->buffer[i]);
    }

    printf("\r\n");


    printf("auth is set\r\n");

    Esys_Finalize(&esys_context);
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context);
    return 0;

error:
    Esys_Finalize(&esys_context);
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context);
    return 0;
}
