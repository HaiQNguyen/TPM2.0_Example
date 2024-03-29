
#ifndef MODULE_H_
#define MODULE_H_

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../include/tss2_esys.h"
#include "../include/test-options.h"
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


enum state {
    forwarding,
    intercepting
};

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
              TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
    TSS2_TCTI_CONTEXT *tctiInner;
    enum state state;
} TSS2_TCTI_CONTEXT_PROXY;

/*Fuction Prototype***********************************************************/
TSS2_TCTI_CONTEXT_PROXY*
tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx);

TSS2_RC
tcti_proxy_transmit(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer
    );

TSS2_RC
tcti_proxy_receive(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout
    );


void
tcti_proxy_finalize(
    TSS2_TCTI_CONTEXT *tctiContext);

TSS2_RC
tcti_proxy_initialize(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    TSS2_TCTI_CONTEXT *tctiInner);

TSS2_TCTI_CONTEXT *
tcti_init_from_opts(test_opts_t * options);

TSS2_TCTI_CONTEXT *
tcti_socket_init(char const *host, uint16_t port);
#endif /*File_H_*/

/*** End of File **************************************************************/
