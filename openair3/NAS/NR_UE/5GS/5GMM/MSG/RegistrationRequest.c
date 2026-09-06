/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*!
 * \brief registration request procedures for gNB
 */

#include "RegistrationRequest.h"
#include <stdint.h>
#include "T.h"
#include "nas_log.h"

#define IEI_NULL 0x00

int decode_registration_request(registration_request_msg *registration_request, const uint8_t *buffer, uint32_t len)
{
  uint32_t decoded = 0;
  int decoded_result = 0;

  LOG_FUNC_IN;
  LOG_TRACE(INFO, "5GMM: Registration Request len = %d", len);

  /* Decoding mandatory fields */
  if ((decoded_result =
           decode_5gs_registration_type(&registration_request->fgsregistrationtype, 0, *(buffer + decoded) & 0x0f))
      < 0) {
    LOG_FUNC_RETURN(decoded_result);
  }

  if ((decoded_result = decode_nas_key_set_identifier(&registration_request->naskeysetidentifier, IEI_NULL, *(buffer + decoded) >> 4))
      < 0) {
    //         return decoded_result;
    LOG_FUNC_RETURN(decoded_result);
  }

  decoded++;

  if ((decoded_result = decode_5gs_mobile_identity(&registration_request->fgsmobileidentity, 0, buffer + decoded, len - decoded))
      < 0) {
    LOG_FUNC_RETURN(decoded_result);
  } else
    decoded += decoded_result;

  // TODO, Decoding optional fields

  return decoded;
}

int encode_registration_request(const registration_request_msg *registration_request, uint8_t *buffer, uint32_t len)
{
  int encoded = 0;
  int encode_result = 0;
  bool is_for = true; // Follow-on request pending

  *(buffer + encoded) = ((encode_nas_key_set_identifier(&registration_request->naskeysetidentifier, IEI_NULL) & 0x0f) << 4)
                        | (encode_5gs_registration_type(&registration_request->fgsregistrationtype, is_for) & 0x0f);
  encoded++;

  if ((encode_result = encode_5gs_mobile_identity(&registration_request->fgsmobileidentity, 0, buffer + encoded, len - encoded))
      < 0)
    // Return in case of error
    return encode_result;
  else
    encoded += encode_result;

  if ((registration_request->presencemask & REGISTRATION_REQUEST_5GMM_CAPABILITY_PRESENT)
      == REGISTRATION_REQUEST_5GMM_CAPABILITY_PRESENT) {
    if ((encode_result = encode_5gmm_capability(buffer + encoded, &registration_request->fgmmcapability, len - encoded)) < 0)
      return encode_result;
    else
      encoded += encode_result;
  }

  if ((registration_request->presencemask & REGISTRATION_REQUEST_UE_SECURITY_CAPABILITY_PRESENT)
      == REGISTRATION_REQUEST_UE_SECURITY_CAPABILITY_PRESENT) {
    if ((encode_result = encode_nrue_security_capability(&registration_request->nruesecuritycapability,
                                                         REGISTRATION_REQUEST_UE_SECURITY_CAPABILITY_IEI,
                                                         buffer + encoded))
        < 0)
      // Return in case of error
      return encode_result;
    else
      encoded += encode_result;
  }

  // PDU session status (Optional) - 9.11.3.44 of 3GPP TS 24.501  
   if ((registration_request->presencemask & REGISTRATION_REQUEST_PDU_SESSION_STATUS_PRESENT)  
	   == REGISTRATION_REQUEST_PDU_SESSION_STATUS_PRESENT) {  
	 byte_array_t ba = { .buf = buffer + encoded, .len = len - encoded };  
	 if ((encode_result = encode_pdu_session_ie(&ba, REGISTRATION_REQUEST_PDU_SESSION_STATUS_IEI,  
												 registration_request->pdu_session_status)) < 0)  
	   return encode_result;  
	 encoded += encode_result;	
   }  
   
   if ((registration_request->presencemask & REGISTRATION_REQUEST_NAS_MESSAGE_CONTAINER_PRESENT)  
	   == REGISTRATION_REQUEST_NAS_MESSAGE_CONTAINER_PRESENT) {  
	 if ((encode_result = encode_fgc_nas_message_container(&registration_request->fgsnasmessagecontainer,  
															 REGISTRATION_REQUEST_NAS_MESSAGE_CONTAINER_IEI,  
															 buffer + encoded,	
															 len - encoded))  
		 < 0)  
	   return encode_result;  
	 else  
	   encoded += encode_result;  
   }  

  // TODO, Encoding optional fields
  return encoded;
}
