// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <WS2tcpip.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <winsock2.h>

#define DPS_MOCK_URI "tammock.azurewebsites.net"
#define DPS_MOCK_RESOURCE "/api/DpsWebhook?code=bzCpm4R1Nx4lae6hCSsOB7864rLHedUCJNJ1GermQLvFQ/yx7VnHxw=="
#define IOTHUB_NAME "foobar"

#define HTTP_POST_REQUEST_HEADER                                          \
    "POST "                                                               \
    DPS_MOCK_RESOURCE " HTTP/1.0\n"                                       \
    "Host: " DPS_MOCK_URI "\n"                                            \
    "Content-Type: application/json\n"                                    \
    "Content-Length: %u\n"                                                \
    "\n"

#define TAM_REQUEST_PREFIX     \
    "{\"linkedHubs\": [\"" IOTHUB_NAME "\"],"    \
    "\"deviceRuntimeContext\":"         \
    "{\"data\":"                        \
    "{\"certificate\":\""
#define TAM_REQUEST_SUFFIX "\"}}}"

#define CERTIFICATE_PREFIX "\"returnData\":{\"certificate\":\""

oe_result_t HttpPostRequestCreate(
    const uint8_t* const Payload,
    const size_t PayloadSize,
    uint8_t* const Request,
    const size_t RequestSize,
    size_t* const RequiredSize)
{
    if (RequiredSize == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    const size_t headerSize = snprintf(
        (char* const)Request,
        RequestSize,
        HTTP_POST_REQUEST_HEADER,
        PayloadSize);
    oe_result_t status = OE_OK;

    *RequiredSize = headerSize + PayloadSize;

    if (*RequiredSize > RequestSize)
    {
        status = OE_BUFFER_TOO_SMALL;
        goto Exit;
    }

    if (Request == NULL || Payload == NULL)
    {
        status = OE_INVALID_PARAMETER;
        goto Exit;
    }

    memcpy(Request + headerSize, Payload, PayloadSize);

Exit:
    return status;
}

oe_result_t TamRequestCreate(
    const uint8_t* const Payload,
    const size_t PayloadSize,
    uint8_t* const Request,
    const size_t RequestSize,
    size_t* const RequiredSize)
{
    if (RequiredSize == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    oe_result_t status = OE_OK;

    *RequiredSize = sizeof(TAM_REQUEST_PREFIX) - 1 + PayloadSize - 1 + sizeof(TAM_REQUEST_SUFFIX);

    if (*RequiredSize > RequestSize)
    {
        status = OE_BUFFER_TOO_SMALL;
        goto Exit;
    }

    if (Request == NULL || Payload == NULL)
    {
        status = OE_INVALID_PARAMETER;
        goto Exit;
    }

    uint8_t* p = Request;
    memcpy(p, TAM_REQUEST_PREFIX, sizeof(TAM_REQUEST_PREFIX) - 1);
    p += sizeof(TAM_REQUEST_PREFIX) - 1;

    memcpy(p, Payload, PayloadSize);
    p += PayloadSize - 1;

    memcpy(p, TAM_REQUEST_SUFFIX, sizeof(TAM_REQUEST_SUFFIX));

Exit:
    return status;
}

oe_result_t HttpHeaderFindNumber(
    const char* const Data,
    const char* const Prefix,
    const int Base,
    size_t* const Output)
{
    if (Data == NULL || Prefix == NULL || Output == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    oe_result_t status = OE_OK;
    *Output = 0;

    if (strncmp(Data, Prefix, strlen(Prefix)) != 0)
    {
        status = OE_UNEXPECTED;
        goto Exit;
    }

    const char* const start = Data + strlen(Prefix);
    *Output = strtol(start, NULL, Base);

Exit:
    return status;
}

oe_result_t socket_send_receive(
    const uint8_t* request_buffer,
    const size_t request_buffer_size,
    uint8_t** response_buffer,
    size_t* response_buffer_size)
{
    WSADATA wsaData;
    SOCKET tamSocket = INVALID_SOCKET;
    struct addrinfo* addrInfo = NULL;
    uint8_t* responseBuffer = NULL;

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != NO_ERROR)
    {
        return OE_FAILURE;
    }

    {
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        result = getaddrinfo(DPS_MOCK_URI, "80", &hints, &addrInfo);
        if (result != 0)
        {
            goto Exit;
        }
    }

    
    tamSocket = socket(
        addrInfo->ai_family, addrInfo->ai_socktype, addrInfo->ai_protocol);
    if (tamSocket == INVALID_SOCKET)
    {
        result = 1;
        goto Exit;
    }

    result = connect(tamSocket, addrInfo->ai_addr, addrInfo->ai_addrlen);
    if (result == SOCKET_ERROR)
    {
        goto Exit;
    }

    result = send(tamSocket, request_buffer, request_buffer_size, 0);
    if (result == SOCKET_ERROR)
    {
        goto Exit;
    }

    size_t responseBufferSize = 4096;
    responseBuffer = malloc(responseBufferSize);
    if (responseBuffer == NULL)
    {
        result = 1;
        goto Exit;
    }
    memset(responseBuffer, 0, responseBufferSize);

    result = recv(tamSocket, responseBuffer, responseBufferSize - 1, 0);
    if (result == SOCKET_ERROR)
    {
        goto Exit;
    }
    size_t bytesReceived = result;
    result = 0;

    char* line = strtok(responseBuffer, "\n");
    if (strcmp("HTTP/1.1 200 OK\r", line))
    {
        result = 1;
        goto Exit;
    }

    size_t payloadBytes = 0;
    while ((line = strtok(NULL, "\n")) != NULL)
    {
        const oe_result_t res = HttpHeaderFindNumber(line, "Content-Length: ", 10, &payloadBytes);
        if (res == OE_UNEXPECTED)
        {
            continue;
        }
        else if (res == OE_OK)
        {
            break;
        }
        else
        {
            result = 1;
            goto Exit;
        }
    }

    if (line == NULL)
    {
        result = 1;
        goto Exit;
    }

    while ((line = strtok(NULL, "\n")) != NULL)
    {
        if (strcmp("\r", line) == 0)
        {
            break;
        }
    }

    if (line == NULL)
    {
        result = 1;
        goto Exit;
    }

    line = strtok(NULL, "\n");

    // line now contains JSON payload

    // TODO: find JSON parser library
    // TODO: find HTTP request/response library

    int len = strlen(line);
    if (line == NULL)
    {
        result = 1;
        goto Exit;
    }

    while (strlen(line) < payloadBytes)
    {
        if (bytesReceived < responseBufferSize)
        {
            result = recv(
                tamSocket,
                responseBuffer + bytesReceived,
                responseBufferSize - bytesReceived - 1,
                0);
            if (result == SOCKET_ERROR)
            {
                goto Exit;
            }
            bytesReceived += result;
            result = 0;
        }
        else
        {
            responseBufferSize *= 2;
            uint8_t* temp = realloc(responseBuffer, responseBufferSize);
            if (temp == NULL)
            {
                result = 1;
                goto Exit;
            }
            line = temp + (line - responseBuffer);
            responseBuffer = temp;
            memset(
                responseBuffer + (responseBufferSize / 2),
                0,
                responseBufferSize / 2);
        }
    }

    if (strlen(line) != payloadBytes)
    {
        result = 1;
        goto Exit;
    }

    *response_buffer = malloc(payloadBytes + 1);
    if (*response_buffer == NULL)
    {
        result = 1;
        goto Exit;
    }

    memcpy(*response_buffer, line, payloadBytes);
    (*response_buffer)[payloadBytes] = '\0';
    *response_buffer_size = payloadBytes;

Exit:
    if (responseBuffer)
        free(responseBuffer);

    if (addrInfo)
        freeaddrinfo(addrInfo);

    if (tamSocket != INVALID_SOCKET)
        closesocket(tamSocket);

    WSACleanup();

    return result ? OE_FAILURE : OE_OK;
}

oe_result_t remote_attest(
    const uint8_t* report,
    const size_t report_size,
    uint8_t* attestation_report,
    size_t* attestation_report_size)
{
    size_t bytes_needed;
    uint8_t* request_buffer = NULL;
    size_t request_buffer_size;
    uint8_t* payload_buffer = NULL;
    size_t payload_buffer_size;
    uint8_t* response_buffer = NULL;
    size_t response_buffer_size;

    oe_result_t result =
        TamRequestCreate(report, report_size, NULL, 0, &bytes_needed);
    if (result != OE_BUFFER_TOO_SMALL)
    {
        result = OE_FAILURE;
        goto Exit;
    }

    payload_buffer = malloc(bytes_needed);
    if (payload_buffer == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto Exit;
    }
    payload_buffer_size = bytes_needed;

    result = TamRequestCreate(report, report_size, payload_buffer, payload_buffer_size, &bytes_needed);
    if (result != OE_OK)
    {
        goto Exit;
    }

    result =
        HttpPostRequestCreate(payload_buffer, payload_buffer_size, NULL, 0, &bytes_needed);
    if (result != OE_BUFFER_TOO_SMALL)
    {
        result = OE_FAILURE;
        goto Exit;
    }

    request_buffer = malloc(bytes_needed);
    if (request_buffer == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto Exit;
    }
    request_buffer_size = bytes_needed;

    result = HttpPostRequestCreate(
        payload_buffer,
        payload_buffer_size,
        request_buffer,
        request_buffer_size,
        &bytes_needed);
    if (result != OE_OK)
    {
        goto Exit;
    }

    result = socket_send_receive(request_buffer, request_buffer_size, &response_buffer, &response_buffer_size);
    if (result != OE_OK)
    {
        goto Exit;
    }

    char* token = strtok(response_buffer, ",");
    if (strcmp(token, "{\"iotHubHostName\":\"" IOTHUB_NAME "\""))
    {
        result = OE_FAILURE;
        goto Exit;
    }
    token = strtok(NULL, ",");
    if (strncmp(token, CERTIFICATE_PREFIX, sizeof(CERTIFICATE_PREFIX) - 1))
    {
        result = OE_FAILURE;
        goto Exit;
    }

    token += sizeof(CERTIFICATE_PREFIX) - 1;
    token[strlen(token) - 3] = '\0';

    char* next = strstr(token, "\\n");
    size_t offset = 0;
    while (*attestation_report_size > offset + (next - token))
    {
        memcpy(attestation_report + offset, token, next - token);
        offset += next - token;
        token = next + 2;
        next = strstr(token, "\\n");
        attestation_report[offset++] = '\n';
        if (next == NULL)
        {
            break;
        }
    }

    size_t tokenLen = strlen(token);
    if (tokenLen > *attestation_report_size - offset - 1)
    {
        result = OE_BUFFER_TOO_SMALL;
        goto Exit;
    }

    memcpy(attestation_report + offset, token, tokenLen + 1);

    *attestation_report_size = offset + tokenLen + 1;

Exit:
    if (response_buffer)
        free(response_buffer);

    if (payload_buffer)
        free(payload_buffer);

    if (request_buffer)
        free(request_buffer);

    return result;
}
