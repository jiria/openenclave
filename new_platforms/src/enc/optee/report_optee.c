/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/enclave.h>
#include <mbedtls/x509_crt.h>

#include "cyres_optee.h"
#include "enclavelibc.h"

oe_result_t oe_parse_report_internal(
    mbedtls_x509_crt* chain,
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    oe_report_t* parsed_report);

oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    if (report_buffer == NULL || report_buffer_size == NULL)
        return OE_INVALID_PARAMETER;

    return get_cyres_cert_chain(report_buffer, report_buffer_size);
}

// TODO add support for remote attestation
oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_OK;

    mbedtls_x509_crt chain = {0};
    mbedtls_x509_crt other_chain = {0};

    mbedtls_x509_crt_init(&chain);
    int res = mbedtls_x509_crt_parse(&chain, report, report_size);
    if (res != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // validate the cert chain contains CyReS measurements

    result = oe_parse_report_internal(&chain, report, report_size, parsed_report);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

    // validate the chain is properly rooted
    mbedtls_x509_crt* root = &chain;
    while (root->next)
        root = root->next;

    uint32_t validation_flags = 0;
    res = mbedtls_x509_crt_verify(
        &chain, root, NULL, NULL, &validation_flags, NULL, NULL);
    if (res != 0 || validation_flags != 0)
    {
        result = OE_FAILURE;
        goto Cleanup;
    }

    // validate the parent cert is matching
    char** trusted_roots;
    size_t trusted_roots_count;
    result = get_remote_attestation_trusted_root(
        &trusted_roots, &trusted_roots_count);
    if (result != OE_OK)
    {
        goto Cleanup;
    }

    if (trusted_roots_count == 0)
    {
        // perform local attestation

        uint8_t* local_report;
        size_t local_report_size;
        result = oe_get_report_v2(
            0, NULL, 0, NULL, 0, &local_report, &local_report_size);
        if (result != OE_OK)
        {
            goto Cleanup;
        }

        mbedtls_x509_crt_init(&other_chain);
        res = mbedtls_x509_crt_parse(
            &other_chain, local_report, local_report_size); // TODO make this change 
        if (res != 0)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        if (other_chain.next == NULL)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }

        if (memcmp(chain.next->raw.p, other_chain.next->raw.p, other_chain.next->raw.len))
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
    }
    else
    {
        bool found = FALSE;
        for (int i = 0; i < trusted_roots_count; i++)
        {
            mbedtls_x509_crt_init(&other_chain);
            res = mbedtls_x509_crt_parse(
                &other_chain, trusted_roots[i], strlen(trusted_roots[i]) + 1); // make sure we have \0
            if (res != 0)
            {
                result = OE_FAILURE;
                goto Cleanup;
            }

            if (memcmp(
                    root->raw.p,
                    other_chain.raw.p,
                    other_chain.raw.len) == 0)
            {
                found = TRUE;
                break;
            }

            mbedtls_x509_crt_free(&other_chain);
            memset(&other_chain, 0, sizeof(other_chain));
        }
        if (!found)
        {
            result = OE_FAILURE;
            goto Cleanup;
        }
        if (parsed_report)
        {
            parsed_report->identity.attributes |= OE_REPORT_ATTRIBUTES_REMOTE;
        }
    }

Cleanup:
    mbedtls_x509_crt_free(&chain);
    mbedtls_x509_crt_free(&other_chain);

    return result;
}
