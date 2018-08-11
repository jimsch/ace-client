#include "mbed.h"
// #include "dns.h"
#include "sn_coap_protocol.h"
#include "sn_coap_header.h"
#include "cn-cbor.h"
#include "oscore.h"
#include "ace.h"

#include "link-mem.h"


extern bool SendMessage(sn_coap_hdr_s * coap_msg_ptr, void * data,  coap_msg_delivery callback);

extern EventQueue MyQUeue;
extern coap_s * coapHandle;
extern coap_version_e coapVersion;

typedef struct {
    char * schema;
    char * address;
    char * port;
    char * path;
} URL;

////    UrlParse - parse a URL to pieces
//
//  M00BUG - does not deal with IPv6 addresses.
//

URL * UrlParse(char * urlString)
{
    URL * url_ptr = (URL *) calloc(sizeof(URL), 1);
    int state = 0;
    char ch;
    
    url_ptr->schema = urlString;
    while (*urlString != 0) {
        ch = *urlString;
        if (state == 0) {
            if (ch == ':') {
                *urlString = 0;
                state = 1;
                urlString ++;
            }
            else {
                urlString++;
            }
        }
        else if (state == 1) {
            if (ch == '/' and urlString[1] == '/') {
                urlString += 2;
                url_ptr->address = urlString;
                state = 2;
            }
            else {
                free(url_ptr);
                return NULL;
            }
        }
        else if (state == 2) {
            if (ch == ':') {
                *urlString = 0;
                urlString ++;
                url_ptr->port = urlString;
                state = 3;
            }
            else if (ch == '/') {
                *urlString = 0;
                urlString ++;
                url_ptr->path = urlString;
                return url_ptr;
            }
            else {
                urlString ++;
            }
        }
        else if (state == 3) {
            if (ch == '/') {
                *urlString = 0;
                urlString++;
                url_ptr->path = urlString;
                return url_ptr;
            }
            urlString++;
        }
    }
    free(url_ptr);
    return NULL;
}

extern void AceResponse(int index);

//// MakeAceRequest
//
//  Given a 4.01 Forbidden response message, try and run ACE to get
//      a better answer
//

void MakeAceRequest(CoapMessageItem * messageData)
{
    sn_coap_hdr_s * response = messageData->sn_coap_response;
    
    // Validate the response to make sure we can use it

    if (response->msg_code != COAP_MSG_CODE_RESPONSE_FORBIDDEN ||
        (response->content_format != COAP_CT_NONE && response->content_format != COAP_CT_CBOR)) {
        return;
    }

    cn_cbor * ace_data = cn_cbor_decode(response->payload_ptr, response->payload_len, NULL, NULL);
    if (ace_data == NULL) {
        cn_cbor_free(ace_data, NULL);
        return;
    }

    cn_cbor * ace_request = cn_cbor_map_create(NULL, NULL);

    //  Copy over NONCE if it exists
    cn_cbor * tmp = cn_cbor_mapget_int(ace_data, 5);
    if (tmp != NULL) {
        cn_cbor_mapput_int(ace_request, 5, tmp, NULL, NULL);
    }

    cn_cbor_mapput_int(ace_request, 18, cn_cbor_int_create(2, NULL, NULL), NULL, NULL);  // grant_type
    cn_cbor_mapput_int(ace_request, 3, cn_cbor_string_create("aud2", NULL, NULL), NULL, NULL); // audience
    cn_cbor_mapput_int(ace_request, 12, cn_cbor_string_create("read", NULL, NULL), NULL, NULL); // scope

    // Parse out the URL

    tmp = cn_cbor_mapget_int(ace_data, 0);
    if (tmp == NULL || tmp->type != CN_CBOR_TEXT) {
        // M00BUG cleanup
        return;
    }

    URL * urlData = UrlParse((char *) tmp->v.str);
    

    sn_coap_hdr_s * ace_coap_request = (sn_coap_hdr_s*) calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(ace_coap_request);

    ace_coap_request->msg_code = COAP_MSG_CODE_REQUEST_POST;
    if (urlData->path != NULL) {
        ace_coap_request->uri_path_ptr = (uint8_t*) urlData->path;
        ace_coap_request->uri_path_len = strlen(urlData->path);
    }

    // Calculate the CoAP message size, allocate the memory and build the message
    int cb = cn_cbor_encoder_write(NULL, 0, 0, ace_request);
    uint8_t* message_ptr = (uint8_t*)malloc(cb);
    cn_cbor_encoder_write(message_ptr, 0, cb, ace_request);

    ace_coap_request->payload_ptr = message_ptr;
    ace_coap_request->payload_len = cb;

    SendMessage(ace_coap_request, NULL, AceResponse);

    return;
}

void AceResponse(int i)
{
    printf("ACE Response received");
}
