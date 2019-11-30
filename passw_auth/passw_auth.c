

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../include/tss2_esys.h"
#include "../include/tss2_common.h"
#include "../include/tss2_tpm2_types.h"

#include "../tcti_helper/tcti_helper.h"

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108

//#define WRONG_PASSW_1
//#define WRONG_PASSW_2

void HexDump(uint8_t * array, uint32_t size);

int
main(int argc, char *argv[])
{
    /*General declaration*****************************************************/
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
        printf("TPM Startup FAILED! Error in sanity check\r\n");
        exit(1);
    }
    tcti_inner = tcti_init_from_opts(&opts);
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    rc = tcti_proxy_initialize(NULL, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x\r\n", rc);
        return rc;
    }
    tcti_context = calloc(1, tcti_size);
    if (tcti_inner == NULL) {
        printf("TPM Startup FAILED! Error tcti init\r\n");
        exit(1);
    }
    rc = tcti_proxy_initialize(tcti_context, &tcti_size, tcti_inner);
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x\r\n", rc);
        return 1;
    }

    rc = Esys_Initialize(&esys_context, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }
    rc = Esys_Startup(esys_context, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    rc = Esys_SetTimeout(esys_context, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;

    /*use this password for authenticate primary object*/
    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0 },
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    //Init an object which is a RSA kaypair 
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_NULL
                  },
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };
    printf("\nRSA key will be created.");

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    //set auth value, for this hierarchy it is NULL
    rc = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;


    //Create primary object with the defined auth value: authValuePrimary
    rc = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_CreatePrimary FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }
#ifdef WRONG_PASSW_1
    TPM2B_AUTH wrong_passw = {
        .size = 0,
        .buffer = {}
    };
    //Set authenticate value for primary object by using wrong password
    rc = Esys_TR_SetAuth(esys_context, primaryHandle, &wrong_passw);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }
#else
    //Set authenticate value for primary object to use it to create a child object
    rc = Esys_TR_SetAuth(esys_context, primaryHandle, &authValuePrimary);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }
#endif
    //Setup second passw for child object
    TPM2B_AUTH authKey2 = {
        .size = 6,
        .buffer = {6, 7, 8, 9, 10, 11}
    };

    TPM2B_SENSITIVE_CREATE inSensitive2 = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
             },
            .data = {
                 .size = 0,
                 .buffer = {}
             }
        }
    };

    inSensitive2.sensitive.userAuth = authKey2;

    TPM2B_PUBLIC inPublic2 = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),

            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB
                 },
                 .scheme = {
                      .scheme =
                      TPM2_ALG_NULL,
                  },
                 .keyBits = 2048,
                 .exponent = 0
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {}
                 ,
             }
        }
    };

    TPM2B_DATA outsideInfo2 = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR2 = {
        .count = 0,
    };

    TPM2B_PUBLIC *outPublic2;
    TPM2B_PRIVATE *outPrivate2;
    TPM2B_CREATION_DATA *creationData2;
    TPM2B_DIGEST *creationHash2;
    TPMT_TK_CREATION *creationTicket2;

    rc = Esys_Create(esys_context,
                    primaryHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive2,
                    &inPublic2,
                    &outsideInfo2,
                    &creationPCR2,
                    &outPrivate2,
                    &outPublic2,
                    &creationData2, &creationHash2, &creationTicket2);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Create FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }
    printf("\nSecond key created.");

    rc = Esys_Load(esys_context,
                  primaryHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate2, outPublic2, &loadedKeyHandle);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Load FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    printf("\nSecond Key loaded.\r\n");
#ifdef WRONG_PASSW_2
    //Set authenticate value for primary object by using wrong password
    rc = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &wrong_passw);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }
#else
    rc = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }
#endif
    //using child object to create a second child objetc, this time password is NULL
    TPM2B_SENSITIVE_CREATE inSensitive3 = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {}
             },
            .data = {
                 .size = 0,
                 .buffer = {}
             }
        }
    };

    rc = Esys_Create(esys_context,
                    loadedKeyHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive3,
                    &inPublic2,
                    &outsideInfo2,
                    &creationPCR2,
                    &outPrivate2,
                    &outPublic2,
                    &creationData2, &creationHash2, &creationTicket2);

    rc = Esys_TR_SetAuth(esys_context, loadedKeyHandle, &authKey2);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_TR_SetAuth FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    //Finish, flush the key
    rc = Esys_FlushContext(esys_context, primaryHandle);
    primaryHandle = ESYS_TR_NONE;
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

    rc = Esys_FlushContext(esys_context, loadedKeyHandle);
    loadedKeyHandle = ESYS_TR_NONE;
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext FAILED! Response Code : 0x%x\r\n", rc);
        goto error;
    }

printf("application done!\r\n");
printf("clean up and quit\r\n");
Esys_Finalize(&esys_context);
Tss2_Tcti_Finalize  (tcti_inner);
Tss2_Tcti_Finalize  (tcti_context);
return 0;

error:
    //error, clean up and quit
    printf("error! clean up and quit\r\n");
    Esys_Finalize(&esys_context);
    Tss2_Tcti_Finalize  (tcti_inner);
    Tss2_Tcti_Finalize  (tcti_context);
    return 0;
}


void HexDump(uint8_t * array, uint32_t size)
{
    for(uint32_t i = 0; i < size; i++){
        if((i % 8) == 0){
            printf("\r\n");
            printf("%06d:      ", i);
        }
        printf("0x%02x ", array[i] );
    }
    printf("\r\n");
}
