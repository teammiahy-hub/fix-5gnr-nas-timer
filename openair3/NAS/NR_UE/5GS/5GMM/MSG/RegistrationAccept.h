/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*!
 * \brief 5GS registration accept procedures
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "FGSMobileIdentity.h"
#include "ds/byte_array.h"
#include "fgmm_lib.h"

#ifndef REGISTRATION_ACCEPT_H_
#define REGISTRATION_ACCEPT_H_

#define NAS_MAX_TAI 16

#define IEI_TAI_LIST 0x54  
#define IEI_NETWORK_FEATURE_SUPPORT 0x21  
#define IEI_T3512_VALUE 0x5e  

typedef enum {
  FGS_REGISTRATION_RESULT_3GPP = 1,
  FGS_REGISTRATION_RESULT_NON_3GPP = 2,
  FGS_REGISTRATION_RESULT_3GPP_AND_NON_3GPP = 3
} fgs_registration_result_t;

#define NAS_MAX_NUMBER_SLICES 8

// 9.11.3.37 of 3GPP TS 24.501
typedef struct {
  int sst;
  int *hplmn_sst;
  int *sd;
  int *hplmn_sd;
} nr_nas_msg_snssai_t;

/* 10.5.7.3 3GPP TS 24.008 */
typedef struct {
  uint8_t value;
  uint8_t unit;
} tgpp_timer_t;

typedef struct {  
  uint8_t ims_vops : 1;  
  uint8_t ims_vops_n3gpp : 1;  
  uint8_t emc : 2;  
  uint8_t emf : 2;  
  uint8_t iwk_n26 : 1;  
  uint8_t mpsi : 1;  
  uint8_t cp_ciot_5gs : 1;  
  uint8_t n3_data : 1;  
  uint8_t iphc_cp_ciot_5gs : 1;  
  uint8_t up_ciot_5gs : 1;  
  uint8_t restrict_ec : 2;  
  uint8_t mcsi : 1;  
  uint8_t emcn3 : 1;  
} nr_nas_msg_5gs_feat_support_t;

typedef struct {  
  uint8_t mccdigit1, mccdigit2, mccdigit3;  
  uint8_t mncdigit1, mncdigit2, mncdigit3;  
  uint16_t tac; // actually 3 octets (24 bits) per spec  
} nr_nas_msg_tai_t;  
  
/*
 * Message name: Registration accept
 * Description: The REGISTRATION ACCEPT message is sent by the AMF to the UE. See table 8.2.7.1.1.
 * Significance: dual
 * Direction: network to UE
 */

typedef struct registration_accept_msg_tag {
  // 5GS registration result (Mandatory)
  fgs_registration_result_t result;
  bool sms_allowed;
  // 5G-GUTI (Optional)
  FGSMobileIdentity *guti;
  // Allowed NSSAI (Optional)
  nr_nas_msg_snssai_t nas_allowed_nssai[NAS_MAX_NUMBER_SLICES];
  uint8_t num_allowed_slices;
  // Configured NSSAI (Optional)
  nr_nas_msg_snssai_t config_nssai[NAS_MAX_NUMBER_SLICES];
  uint8_t num_configured_slices;

  nr_nas_msg_tai_t tai_list[NAS_MAX_TAI];  
  uint8_t num_tai;	
  nr_nas_msg_5gs_feat_support_t feature_support;  
  gprs_timer_t *t3512;

  bool has_pdu_session_status;
  uint8_t pdu_session_status[MAX_NUM_PSI];
} registration_accept_msg;

size_t decode_registration_accept(registration_accept_msg *registrationaccept, const byte_array_t buffer);

int encode_registration_accept(const registration_accept_msg *registrationaccept, uint8_t *buffer, uint32_t len);

bool eq_fgmm_registration_accept(const registration_accept_msg *a, const registration_accept_msg *b);
void free_fgmm_registration_accept(registration_accept_msg *msg);

#endif /* ! defined(REGISTRATION_ACCEPT_H_) */
