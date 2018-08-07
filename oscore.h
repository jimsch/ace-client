typedef uint8_t byte;

typedef struct {
    byte * key_ptr;
    int    key_len;
    int    algorithm;
    byte * baseIV_ptr;
    int    baseIV_len;
    byte * senderID_ptr;
    int    senderID_len;
    byte * recipID_ptr;
    int    recipID_len;
    byte * recipKey_ptr;
    int    recipKey_len;
    int    partialIV;
} OscoreKey;

typedef struct {
    byte   partialIV[4];        // Network order!!!
    int    partialIV_len;
    OscoreKey * key_ptr;
} OscoreMsgMatch;

extern OscoreKey DefaultKey;

OscoreMsgMatch * OscoreRequest(sn_coap_hdr_s *, OscoreKey *);
sn_coap_hdr_s * OscoreResponse(sn_coap_hdr_s *, OscoreMsgMatch *);

sn_coap_hdr_s * sn_coap_init_message(sn_coap_hdr_s * coap_msg_ptr);
sn_coap_options_list_s * sn_coap_init_options_list(sn_coap_options_list_s * coap_options_ptr);


//
//  Declarations to process messages
//

typedef void (*coap_msg_delivery)(int i);

typedef struct {
    int                 active;
    sn_coap_hdr_s *     sn_coap_request;
    sn_coap_hdr_s *     sn_coap_response;
    int                 messageId;
    coap_msg_delivery   callbackFn;
    void *              callbackData;
    //  Add retransmit information here
} CoapMessageItem;
