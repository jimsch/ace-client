/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2017 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include "mbed.h"
#include "EthernetInterface.h"

#ifdef EASY_CONNECT
#include "easy-connect.h"
#endif // EASY_CONNECT
//#include "sn_nsdl.h"
#include "sn_coap_protocol.h"
#include "sn_coap_header.h"
#include "oscore.h"
//#include "dns.h"
#include "ace.h"

UDPSocket socket;           // Socket to talk CoAP over
Thread recvfromThread;      // Thread to receive messages over CoAP

DigitalOut red(LED1);
DigitalOut blue(LED2);
DigitalOut green(LED3);

extern void OscoreGet();
EventQueue MyQueue;

struct coap_s* coapHandle;
coap_version_e coapVersion = COAP_VERSION_1;

// CoAP HAL
void* coap_malloc(uint16_t size) {
    return malloc(size);
}

void coap_free(void* addr) {
    free(addr);
}

// tx_cb and rx_cb are not used in this program
uint8_t coap_tx_cb(uint8_t *a, uint16_t b, sn_nsdl_addr_s *c, void *d) {
    printf("coap tx cb\n");
    return 0;
}

int8_t coap_rx_cb(sn_coap_hdr_s *a, sn_nsdl_addr_s *b, void *c) {
    printf("coap rx cb\n");
    return 0;
}

CoapMessageItem PendingMessages[10];

void printCoapMsg(sn_coap_hdr_s * msg)
{
    // We know the payload is going to be a string
    // std::string payload((const char*)msg->payload_ptr, msg->payload_len);

    printf("\tparse status:     %d\n", msg->coap_status);
    printf("\tmsg_id:           %d\n", msg->msg_id);
    printf("\tmsg_code:         %d.%d\n", msg->msg_code >> 5, msg->msg_code & 0x1f);
    printf("\tcontent_format:   %d\n", msg->content_format);
    printf("\tpayload_len:      %d\n", msg->payload_len);
    printf("\tcontent type:     %d\n", msg->content_format);
    // printf("\tpayload:          %s\n", payload.c_str());
    printf("\toptions_list_ptr: %p\n", msg->options_list_ptr);
    fflush(stdout);
}

//  Event queue

//EventQueue * queue = &Queue;

// Main function for the recvfrom thread
void recvfromMain()
{
    int i;
    SocketAddress addr;
    uint8_t* recv_buffer = (uint8_t*)malloc(1280); // Suggested is to keep packet size under 1280 bytes

    nsapi_size_or_error_t ret;

    while ((ret = socket.recvfrom(&addr, recv_buffer, 1280)) >= 0) {
        // to see where the message came from, inspect addr.get_addr() and addr.get_port()


        printf("Received a message of length '%d'\n", ret);

        sn_coap_hdr_s* parsed = sn_coap_parser(coapHandle, ret, recv_buffer, &coapVersion);

        for (i=0; i<10; i++) {
            if (PendingMessages[i].active && PendingMessages[i].messageId == parsed->msg_id) {
                PendingMessages[i].active = false;
                PendingMessages[i].sn_coap_response = parsed;

                MyQueue.call(PendingMessages[i].callbackFn, i);
                break;
            }
        }

        if (i == 10) {
            free(parsed);
        }
    }

    free(recv_buffer);

    printf("UDPSocket::recvfrom failed, error code %d. Shutting down receive thread.\n", ret);
    fflush(stdout);

}

bool SendMessage(sn_coap_hdr_s * coap_msg_ptr, void * data,  coap_msg_delivery callback)
{
    // Calculate the CoAP message size, allocate the memory and build the message
    uint16_t message_len = sn_coap_builder_calc_needed_packet_data_size(coap_msg_ptr);
    if (message_len <= 0) {
        // M00BUG cleanup
        return false;
    }
    
    printf("Calculated message length: %d bytes\n", message_len);

    uint8_t* message_ptr = (uint8_t*)malloc(message_len);
    if (sn_coap_builder(message_ptr, coap_msg_ptr) < 0) {
        // M00BUG clean up
        return false;
    }
        

    // Uncomment to see the raw buffer that will be sent...
    // printf("Message is: ");
    // for (size_t ix = 0; ix < message_len; ix++) {
    //     printf("%02x ", message_ptr[ix]);
    // }
    // printf("\n");

    int i;
    for (i=0; i<10; i++) {
        if (PendingMessages[i].active == 0) break;
    }

    if (i == 10) return false;

    PendingMessages[i].active = true;
    PendingMessages[i].sn_coap_request = coap_msg_ptr;
    PendingMessages[i].messageId = coap_msg_ptr->msg_id;
    PendingMessages[i].callbackFn = callback;
    PendingMessages[i].callbackData = data;

    int scount = socket.sendto("192.168.0.12", 5683, message_ptr, message_len);
    printf("Sent %d bytes to coap://192.168.0.12:5683\n", scount);

    free(message_ptr);
    if (scount == 0) {
        PendingMessages[i].active = false;
        return false;
    }
    return scount == message_len;
    
}

int MessageId = 5;

void DoGetResponse(int index)
{
    printf("Got a message back\n");
    
    printCoapMsg(PendingMessages[index].sn_coap_response);

    if (PendingMessages[index].sn_coap_response->msg_code == COAP_MSG_CODE_RESPONSE_FORBIDDEN) {
        MakeAceRequest(&PendingMessages[index]);
    }
}

void DoGetMessage()
{
    // Path to the resource we want to retrieve
    const char* coap_uri_path = "/oscore/hello/1"; //  "/ace/helloWorld";

    // See ns_coap_header.h
    sn_coap_hdr_s *coap_res_ptr = (sn_coap_hdr_s*)calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(coap_res_ptr);

    coap_res_ptr->uri_path_ptr = (uint8_t*)coap_uri_path;       // Path
    coap_res_ptr->uri_path_len = strlen(coap_uri_path);
    coap_res_ptr->msg_code = COAP_MSG_CODE_REQUEST_GET;         // CoAP method

    // Message ID is used to track request->response patterns, because we're using UDP (so everything is unconfirmed).
    // See the receive code to verify that we get the same message ID back
    coap_res_ptr->msg_id = MessageId;
    MessageId += 1;

    if (!SendMessage(coap_res_ptr, NULL, DoGetResponse)) {
        free(coap_res_ptr);
    }
}

#ifndef EASY_CONNECT
EthernetInterface net;
#endif // EASY_CONNECT

int main()
{
    red = 1;
    blue = 1;
    green = 0;
#ifdef EASY_CONNECT
    NetworkInterface *network = easy_connect(true);
    if (!network) {
        printf("Cannot connect to the network, see serial output");
        return 1;
    }

    printf("Connected to the network. Opening a socket...\n");

    // Open a socket on the network interface
    socket.open(network);

#else
    if (0 != net.connect()) {
        printf("Error connecting\n");
        return -1;
    }

    const char * ip = net.get_ip_address();
    printf("IP Address is %s\n", ip ? ip : "No IP");

    socket.open(&net);

    // dns_init();
    
#endif    
    // Initialize the CoAP protocol handle, pointing to local implementations on malloc/free/tx/rx functions
    coapHandle = sn_coap_protocol_init(&coap_malloc, &coap_free, &coap_tx_cb, &coap_rx_cb);

    // UDPSocket::recvfrom is blocking, so run it in a separate RTOS thread
    recvfromThread.start(&recvfromMain);

    // queue = mbed_event_queue();

    

    //  Get message

    DoGetMessage();


    MyQueue.dispatch_forever();
#if 0    
    //  Try and do the OSCORE version of the get

    while (MsgReceived == 0) {
        red = 0;
        wait(0.2);
        red = 1;
        wait(0.2);
    }

    red = 1;

    MsgReceived = 0;
    OscoreGet();
#endif
    

    Thread::wait(osWaitForever);
    //  sn_coap_protool_destroy(coapHandle); // Clean up
}


void OscoreGet()
{
   // Path to the resource we want to retrieve
    const char* coap_uri_path = "/oscore/hello/1"; // "/ace/helloWorld";

    // See ns_coap_header.h
    sn_coap_hdr_s *coap_res_ptr = (sn_coap_hdr_s*)calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(coap_res_ptr);
    
    coap_res_ptr->uri_path_ptr = (uint8_t*)coap_uri_path;       // Path
    coap_res_ptr->uri_path_len = strlen(coap_uri_path);
    coap_res_ptr->msg_code = COAP_MSG_CODE_REQUEST_GET;         // CoAP method
    
    // Message ID is used to track request->response patterns, because we're using UDP (so everything is unconfirmed).
    // See the receive code to verify that we get the same message ID back
    
    coap_res_ptr->msg_id = 8;
    
    OscoreMsgMatch * match = OscoreRequest(coap_res_ptr, &DefaultKey);

    // Calculate the CoAP message size, allocate the memory and build the message
    uint16_t message_len = sn_coap_builder_calc_needed_packet_data_size(coap_res_ptr);
    printf("Calculated message length: %d bytes\n", message_len);

    uint8_t* message_ptr = (uint8_t*)malloc(message_len);
    sn_coap_builder(message_ptr, coap_res_ptr);

    // Uncomment to see the raw buffer that will be sent...
    // printf("Message is: ");
    // for (size_t ix = 0; ix < message_len; ix++) {
    //     printf("%02x ", message_ptr[ix]);
    // }
    // printf("\n");

    int scount = socket.sendto("192.168.0.12", 5683, message_ptr, message_len);
    printf("Sent %d bytes to coap://192.168.0.12:5683\n", scount);

    free(coap_res_ptr);
    free(message_ptr);
#if 0    
    while (MsgReceived == 0) {
        blue = 1;
        wait(0.2);
        blue = 0;
        wait(0.2);
    }

    blue = 1;
    
    coap_res_ptr = OscoreResponse(NextMsg, match);
    std::string payload((const char*)coap_res_ptr->payload_ptr, coap_res_ptr->payload_len);

    printf("\tparse status:     %d\n", coap_res_ptr->coap_status);
    printf("\tmsg_id:           %d\n", coap_res_ptr->msg_id);
    printf("\tmsg_code:         %d.%d\n", coap_res_ptr->msg_code >> 5, coap_res_ptr->msg_code & 0x1f);
    printf("\tcontent_format:   %d\n", coap_res_ptr->content_format);
    printf("\tpayload_len:      %d\n", coap_res_ptr->payload_len);
    printf("\tcontent type:     %d\n", coap_res_ptr->content_format);
    printf("\tpayload:          %s\n", payload.c_str());
    printf("\toptions_list_ptr: %p\n", coap_res_ptr->options_list_ptr);
#endif
}
