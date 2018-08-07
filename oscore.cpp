#include <string>
#include <stddef.h>
#include <mbed.h>
#include <FreescaleIAP.h>
#include <sn_coap_protocol.h>
#include <sn_coap_header.h>

#include "cn-cbor.h"
#include "oscore.h"
#include "cose.h"

 //   COSE_Algorithm_AES_CCM_16_64_128 = 10,
 
#define COAP_MSG_CODE_REQUEST_FETCH (sn_coap_msg_code_e) 5

byte SenderKey[] = {
    0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff 
};

byte RecipientKey[] = {
    0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
};

byte BaseIV[] = {
    0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c
};

byte RecipId[] = { 0x1 };

OscoreKey DefaultKey = {
    SenderKey, 16, 10, BaseIV, 13, 0, 0, RecipId, 1, RecipientKey, 16, 0
};

extern coap_s * coapHandle;
extern coap_version_e coapVersion;


sn_coap_hdr_s * sn_coap_init_message(sn_coap_hdr_s * coap_msg_ptr)
{
    /* * * * Check given pointer * * * */
    if (coap_msg_ptr == NULL) {
        printf("sn_coap_parser_init_message - message null!");
        return NULL;
    }

    /* XXX not technically legal to memset pointers to 0 */
    memset(coap_msg_ptr, 0x00, sizeof(sn_coap_hdr_s));

    coap_msg_ptr->content_format = COAP_CT_NONE;

    return coap_msg_ptr;
    
}

sn_coap_options_list_s * sn_coap_init_options_list(sn_coap_options_list_s * coap_options_ptr)
{
    /* * * * Check given pointer * * * */
    if (coap_options_ptr == NULL) {
        printf("sn_coap_parser_init_message - message null!");
        return NULL;
    }
    
    /* XXX not technically legal to memset pointers to 0 */
    memset(coap_options_ptr, 0x00, sizeof(sn_coap_options_list_s));

    coap_options_ptr->observe = COAP_OBSERVE_NONE;
    coap_options_ptr->max_age = 60;
    coap_options_ptr->accept = COAP_CT_NONE;
    coap_options_ptr->uri_port = -1; /* COAP_OPTION_URI_PORT_NONE; */
    coap_options_ptr->block2 = -1; /* COAP_OPTION_BlOCK_NONE; */
    coap_options_ptr->block1 = -1; /* COAP_OPTION_BLOCK_NONE; */

    return coap_options_ptr;
}

int BuildAAD(OscoreKey * oscore_key, OscoreMsgMatch * msg_match_ptr, byte ** ppbAad)
{
    cn_cbor * cn_aad = cn_cbor_array_create(NULL);
    cn_cbor * cn_tmp = cn_cbor_int_create(1, NULL);
    cn_cbor_array_append(cn_aad, cn_tmp, NULL);
    cn_tmp = cn_cbor_int_create(oscore_key->algorithm, NULL);
    cn_cbor * cn_tmp2 = cn_cbor_array_create(NULL);
    cn_cbor_array_append(cn_tmp2, cn_tmp, NULL);
    cn_cbor_array_append(cn_aad, cn_tmp2, NULL);
    cn_tmp = cn_cbor_data_create(oscore_key->senderID_ptr, oscore_key->senderID_len, NULL);
    cn_cbor_array_append(cn_aad, cn_tmp, NULL);
    cn_tmp = cn_cbor_data_create(msg_match_ptr->partialIV, msg_match_ptr->partialIV_len, NULL);
    cn_cbor_array_append(cn_aad, cn_tmp, NULL);
    cn_tmp = cn_cbor_data_create(NULL, 0, NULL);
    cn_cbor_array_append(cn_aad, cn_tmp, NULL);

    int cb = cn_cbor_encoder_write(NULL, 0, 0, cn_aad);
    byte * pb = (byte *) malloc(cb);
    int cb2 = cn_cbor_encoder_write(pb, 0, cb, cn_aad);

    *ppbAad = pb;
    return cb2;
}

OscoreMsgMatch * OscoreRequest(sn_coap_hdr_s * coap_outer_ptr, OscoreKey * oscore_key)
{
    int i;
    
    //  Allocate     
    sn_coap_hdr_s *coap_inner_ptr = (sn_coap_hdr_s*)calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(coap_inner_ptr);

    //  Copy options from the old message to the new message
    coap_inner_ptr->uri_path_ptr = coap_outer_ptr->uri_path_ptr; // Path
    coap_outer_ptr->uri_path_ptr = NULL;
    coap_inner_ptr->uri_path_len = coap_outer_ptr->uri_path_len; 
    coap_outer_ptr->uri_path_len = 0;

    //  Change the method to FETCH 
    coap_inner_ptr->msg_code = coap_outer_ptr->msg_code;        // CoAP method
    coap_outer_ptr->msg_code = COAP_MSG_CODE_REQUEST_FETCH;  

    // Calculate the CoAP message size, allocate the memory and build the message
    uint16_t message_len = sn_coap_builder_calc_needed_packet_data_size(coap_inner_ptr);

    uint8_t* message_ptr = (uint8_t*)malloc(message_len);
    sn_coap_builder(message_ptr, coap_inner_ptr);
    message_ptr[3] = message_ptr[1];

    // Bulid the associator structure

    OscoreMsgMatch * msgMatch = (OscoreMsgMatch *) malloc(sizeof(OscoreMsgMatch));
    msgMatch->key_ptr = oscore_key;

    int used = 0;
    if (oscore_key->partialIV & 0xff000000) used = 4;
    else if (oscore_key->partialIV & 0xffff0000) used = 3;
    else if (oscore_key->partialIV & 0xffffff00) used = 2;
    else used = 1;

    byte * pbIV = (byte *) &oscore_key->partialIV;
    for (i=used-1; i>=0; i--, pbIV++) {
        msgMatch->partialIV[i] = *pbIV;
    }
    msgMatch->partialIV_len = used;
    
    //  Figure out the IV to use
    byte useIV[13];
    memcpy(useIV, oscore_key->baseIV_ptr, oscore_key->baseIV_len);
    useIV[0] ^= (byte) oscore_key->senderID_len;
    byte * pb = useIV + (13 - 5 - oscore_key->baseIV_len);
    for (i=0; i<oscore_key->senderID_len; i++, pb++) {
        *pb ^= oscore_key->senderID_ptr[i];
    }
    pb = useIV + (13 - (used + 1));
    for (i=0; i<used; i++, pb++) {
        *pb ^= msgMatch->partialIV[i];
    }

    //  Build AAD

    byte * pbAAD = NULL;
    int cbAAD = BuildAAD(oscore_key, msgMatch, &pbAAD);

    //  Encrypt the message
    
    HCOSE_ENCRYPT hEncObj = COSE_Encrypt_Init(COSE_INIT_FLAGS_NONE, NULL);
    COSE_Encrypt_SetContent(hEncObj, message_ptr+3, message_len-3, NULL);
    COSE_Encrypt_SetExternal(hEncObj, pbAAD, cbAAD, NULL);
    
    COSE_Encrypt_map_put_int(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(oscore_key->algorithm, NULL), COSE_DONT_SEND, NULL);
    
    cn_cbor* cbor = cn_cbor_data_create(useIV, 13, NULL);
    COSE_Encrypt_map_put_int(hEncObj, COSE_Header_IV, cbor, COSE_DONT_SEND, NULL);

    
    COSE_Encrypt_encrypt(hEncObj, oscore_key->key_ptr, oscore_key->key_len, NULL);
    cn_cbor * cbor2 = COSE_get_cbor((HCOSE) hEncObj);

    cn_cbor * cbor_cipherText = cn_cbor_index(cbor2, 2);
    byte * rgb = (byte *) malloc(cbor_cipherText->length);
    memcpy(rgb, cbor_cipherText->v.bytes, cbor_cipherText->length);
    coap_outer_ptr->payload_ptr = rgb;
    coap_outer_ptr->payload_len = cbor_cipherText->length;


    COSE_Encrypt_Free(hEncObj);
    
    byte * optionValue = (byte *) malloc(2 + oscore_key->senderID_len);
    optionValue[0] = 0x8 + used;
    optionValue[1] = (byte) oscore_key->partialIV;
    memcpy(&optionValue[2], oscore_key->senderID_ptr, oscore_key->senderID_len);

    if (coap_outer_ptr->options_list_ptr == NULL) {
        coap_outer_ptr->options_list_ptr = (sn_coap_options_list_s *) malloc(sizeof(sn_coap_options_list_s));
        sn_coap_init_options_list(coap_outer_ptr->options_list_ptr);
    }
    coap_outer_ptr->options_list_ptr->oscore_ptr = optionValue;
    coap_outer_ptr->options_list_ptr->oscore_len = 2 + oscore_key->senderID_len;
    
    free(coap_inner_ptr);

    return msgMatch;
}


sn_coap_hdr_s * OscoreResponse(sn_coap_hdr_s * coap_outer_ptr, OscoreMsgMatch * match_ptr)
{
    int i;
    OscoreKey * oscore_ptr = match_ptr->key_ptr;
    
    cn_cbor * cn_enc_msg = cn_cbor_array_create(NULL);
    cn_cbor * cn_tmp = cn_cbor_data_create(NULL, 0, NULL);
    cn_cbor_array_append(cn_enc_msg, cn_tmp, NULL);
    cn_tmp = cn_cbor_map_create(NULL);
    cn_cbor_array_append(cn_enc_msg, cn_tmp, NULL);
    cn_tmp = cn_cbor_data_create(coap_outer_ptr->payload_ptr, coap_outer_ptr->payload_len, NULL);
    cn_cbor_array_append(cn_enc_msg, cn_tmp, NULL);

    //  Figure out the IV to use
    byte useIV[13];
    memcpy(useIV, oscore_ptr->baseIV_ptr, oscore_ptr->baseIV_len);
    useIV[0] ^= (byte) oscore_ptr->senderID_len;
    byte * pb = useIV + (13 - 5 - oscore_ptr->baseIV_len);
    for (i=0; i<oscore_ptr->senderID_len; i++, pb++) {
        *pb ^= oscore_ptr->senderID_ptr[i];
    }
    pb = useIV + (13 - (match_ptr->partialIV_len + 1));
    for (i=0; i<match_ptr->partialIV_len; i++, pb++) {
        *pb ^= match_ptr->partialIV[i];
    }
    //  Build AAD

    byte * pbAAD = NULL;
    int cbAAD = BuildAAD(oscore_ptr, match_ptr, &pbAAD);
    
    HCOSE_ENCRYPT hEncObj = COSE_Encrypt_Init_From_Object(cn_enc_msg, NULL);
    COSE_Encrypt_SetExternal(hEncObj, pbAAD, cbAAD, NULL);
    COSE_Encrypt_map_put_int(hEncObj, COSE_Header_Algorithm, cn_cbor_int_create(oscore_ptr->algorithm, NULL), COSE_DONT_SEND, NULL);

    cn_cbor* cbor = cn_cbor_data_create(useIV, 13, NULL);
    COSE_Encrypt_map_put_int(hEncObj, COSE_Header_IV, cbor, COSE_DONT_SEND, NULL);

    COSE_Encrypt_decrypt(hEncObj, oscore_ptr->recipKey_ptr, oscore_ptr->recipKey_len, NULL);

    size_t cb;
    const byte * pbContent;
    pbContent = COSE_Encrypt_GetContent(hEncObj, &cb, NULL);

    //  Rebuild a CoAP message
    
    byte * pbMsg = (byte *) malloc(cb+4);
    pbMsg[0] = 0x40;
    pbMsg[1] = pb[0];
    pbMsg[2] = 0xff;
    pbMsg[3] = 0xff;
    memcpy(pbMsg+4, pbContent+1, cb-1);

    sn_coap_hdr_s * coap_inner_ptr = sn_coap_parser(coapHandle, cb+4, pbMsg, &coapVersion);
    
    printf("\tparse status:     %d\n", coap_inner_ptr->coap_status);
    printf("\tmsg_id:           %d\n", coap_inner_ptr->msg_id);
    printf("\tmsg_code:         %d.%d\n", coap_inner_ptr->msg_code >> 5, coap_inner_ptr->msg_code & 0x1f);
    printf("\tcontent_format:   %d\n", coap_inner_ptr->content_format);
    printf("\tpayload_len:      %d\n", coap_inner_ptr->payload_len);
    printf("\tcontent type:     %d\n", coap_inner_ptr->content_format);
    printf("\toptions_list_ptr: %p\n", coap_inner_ptr->options_list_ptr);


    //  Copy things from the inner to the outer message

    if (coap_inner_ptr->options_list_ptr != NULL) {
        //  free(coap_outer_ptr->options_list_ptr->oscore_ptr); Need to dealloate things - free and allocate?
        memcpy(coap_outer_ptr->options_list_ptr, coap_inner_ptr->options_list_ptr, sizeof(sn_coap_options_list_s));
    }
    coap_outer_ptr->msg_code = coap_inner_ptr->msg_code;
    coap_outer_ptr->payload_len = coap_inner_ptr->payload_len;
    coap_outer_ptr->payload_ptr = coap_inner_ptr->payload_ptr;
    coap_inner_ptr->payload_ptr = NULL;

    free(coap_inner_ptr);
    
    return coap_outer_ptr;
}


void WriteToFlash()
{
    int address = flash_size() - SECTOR_SIZE;

    printf("Starting\n");
    erase_sector(address);

    program_flash(address, rgb, cb);
    
}


/*  STRUCTURE

destination - IP Addr + port OR Name + port
Algorithm - fixed to 10
KDF - fixed to HKDF
Secret -  BSTR
Salt - BSTR | NIL

Sender ID
Next PIV Saved

Recipient ID
Next Replay window Start

*/

info = [
          id : bstr,
          id_context : bstr / nil,
          alg_aead : int / tstr,
          type : tstr,
          L : uint
      ]

    
