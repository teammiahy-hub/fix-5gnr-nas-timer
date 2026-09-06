/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __NR_NAS_MSG_SIM_H__
#define __NR_NAS_MSG_SIM_H__

#include <common/utils/assertions.h>
#include "common/5g_platform_types.h"
#include <openair3/UICC/usim_interface.h>
#include <stdbool.h>
#include <stdint.h>
#include "as_message.h"
#include "NR_NAS_defs.h"
#include "secu_defs.h"
#include "NR_NAS_defs.h"
#include "nas_timer.h"

//TO DOUBLE CHECK EXACT VALUE
#define T3502_DEFAULT_VALUE 720 /* 12 minutes   */
#define T3510_DEFAULT_VALUE 15 /* 15 seconds   */
#define T3511_DEFAULT_VALUE 10 /* 10 seconds   */
#define T3512_DEFAULT_VALUE 3240 /* 54 minutes   */
#define T3516_DEFAULT_VALUE 30 /* 30 seconds   */
#define T3517_DEFAULT_VALUE 15 /* 15 seconds   */
#define T3519_DEFAULT_VALUE 60 /* 60 seconds   */

/*
 * Internal data used for registration procedure
 */

#define FGS_REGISTRATION_COUNTER_MAX 5

typedef struct {
  unsigned int	fgsregistrationtype; /* Registration type */
  unsigned int attempt_count; /* Counter used to limit the number of
                 * subsequently rejected registration attempts */
} fgmm_registration_data_t;


typedef struct {
    struct nas_timer_t T3502;   /* registration failure timer         */	
    struct nas_timer_t T3510;   /* registration timer             */	
    struct nas_timer_t T3511;   /* registration restart timer             */	
    struct nas_timer_t T3512;   /* periodic registration timer             */
    struct nas_timer_t T3516;   /* 5GS authentication challenge timer   */
    struct nas_timer_t T3517;   /* Service request timer        */
    struct nas_timer_t T3519;   /* Fresh suci timer        */
} fgmm_timers_t;

typedef int (*nr_ll_success_cb_t)(void *args);  
typedef int (*nr_ll_failure_cb_t)(bool is_initial, void *args);  
typedef int (*nr_ll_release_cb_t)(void *args);  
  
typedef struct {  
  nr_ll_success_cb_t success;  
  nr_ll_failure_cb_t failure;  
  nr_ll_release_cb_t release;  
  void *args;  
} nr_registration_lowerlayer_data_t;

#define INITIAL_REGISTRATION 0b001

#define SECURITY_PROTECTED_5GS_NAS_MESSAGE_HEADER_LENGTH 7
#define NAS_INTEGRITY_SIZE 4

/* 3GPP TS 24.501: 9.11.3.50 Service type */
#define SERVICE_TYPE_DATA 0x1

typedef enum fgs_mm_state_e {
  /* 5GMM-NULL */
  FGS_NULL,

  /* 5GMM-DEREGISTERED states */
  FGS_DEREGISTERED,
  FGS_DEREGISTERED_INITIATED,
  FGS_DEREGISTERED_NORMAL_SERVICE,
  FGS_DEREGISTERED_LIMITED_SERVICE,
  FGS_DEREGISTERED_ATTEMPTING_REGISTRATION,
  FGS_DEREGISTERED_PLMN_SEARCH,
  FGS_DEREGISTERED_NO_SUPI,
  FGS_DEREGISTERED_NO_CELL_AVAILABLE,
  FGS_DEREGISTERED_REGISTRATION_NEEDED,

  /* 5GMM-REGISTERED states */
  FGS_REGISTERED_INITIATED,
  FGS_REGISTERED,
  FGS_REGISTERED_NORMAL_SERVICE,
  FGS_REGISTERED_LIMITED_SERVICE,
  FGS_REGISTERED_PLMN_SEARCH,
  FGS_REGISTERED_UPDATE_NEEDED,
  FGS_REGISTERED_ATTEMPTING_REGISTRATION_UPDATE,

  /* 5GMM procedures */
  FGS_SERVICE_REQUEST_INITIATED,
  FGS_DEREGISTRATION_INITIATED,
  FGS_PERIODIC_REGISTRATION_UPDATE_INITIATED,
  FGS_MOBILITY_REGISTRATION_UPDATE_INITIATED,

  FGS_MM_STATE_MAX

} fgs_mm_state_t;

/*
 * 5GS mobility management (5GMM) modes
 * 5.1.3.2.1.1 of TS 24.501
 */
typedef enum fgs_mm_mode_e {
  FGS_NOT_CONNECTED,
  FGS_IDLE,
  FGS_CONNECTED,
} fgs_mm_mode_t;


typedef enum {
  FGS_U1_UPDATED,
  FGS_U2_NOT_UPDATED,
  FGS_U3_ROAMING_NOT_ALLOWED
} fgmm_5gs_update_t;

/* Security Key for SA UE */
typedef struct {
  uint8_t kausf[32];
  uint8_t kseaf[32];
  uint8_t kamf[32];
  uint8_t knas_int[16];
  uint8_t knas_enc[16];
  uint8_t res[16];
  uint8_t rand[16];
  uint8_t kgnb[32];
  uint32_t nas_count_ul;
  uint32_t nas_count_dl;
} ue_sa_security_key_t;


typedef struct {
  /* 5GS Mobility Management States (5.1.3.2.1 of 3GPP TS 24.501) */
  fgs_mm_state_t fiveGMM_state;
  /* 5GS Mobility Management mode */
  fgs_mm_mode_t fiveGMM_mode;  
  fgmm_5gs_update_t    fgs_status;	  /* The current 5G update status			*/
  uicc_t *uicc;
  ue_sa_security_key_t security;
  stream_security_container_t *security_container;
  Guti5GSMobileIdentity_t *guti;
  bool termination_procedure;
  instance_t UE_id;
  /* RRC Inactive Indication */
  bool is_rrc_inactive;
  fgmm_timers_t fgmm_timer;
  
  // Timer t3448 in seconds (-1 = disabled)
  int t3448;
  // Timer t3446 in seconds (-1 = disabled)
  int t3446;
  /* NAS Key Set Identifier associated to the security context */
  uint8_t *ksi;
  plmn_id_t *sn_id;
  
  fgmm_registration_data_t fgmm_reg_data;
  nr_registration_lowerlayer_data_t *lowerlayer_data;
} nr_ue_nas_t;

nr_ue_nas_t *get_ue_nas_info(module_id_t module_id);
void generateRegistrationRequest(as_nas_info_t *initialNasMsg, nr_ue_nas_t *nas, bool is_security_mode);
void generateServiceRequest(as_nas_info_t *initialNasMsg, nr_ue_nas_t *nas);
void *nas_nrue_task(void *args_p);
void *nas_nrue(void *args_p);
void nas_init_nrue(int num_ues);
int nas_itti_kgnb_refresh_req(instance_t instance, const uint8_t kgnb[32]);
void nr_ue_create_ip_if(const char *ifnameprefix, const char *ipv4, const char *ipv6, int ue_id, int pdu_session_id);
void request_pdusession(nr_ue_nas_t *nas, const pdu_session_config_t *pdu);
nr_ue_nas_t *get_nr_ue_nas_info(uint8_t ue_inst);
int nr_registration_lowerlayer_initialize(nr_registration_lowerlayer_data_t *lowerlayer_data, 
	                               nr_ll_success_cb_t success,
                                   nr_ll_failure_cb_t failure,
                                   nr_ll_release_cb_t release,
                                   void *args);
int nr_proc_registration_request(void *args);
int nr_proc_registration_failure(bool is_initial, void *args);
int nr_proc_registration_release(void *args);
int nr_registration_lowerlayer_failure(nr_registration_lowerlayer_data_t *lowerlayer_data, bool is_initial);

void *fgmm_expiry_t3502_handler(void *args);
void *fgmm_expiry_t3510_handler(void *args);
void *fgmm_expiry_t3511_handler(void *args);
void *fgmm_expiry_t3516_handler(void *args);
void *fgmm_expiry_t3517_handler(void *args);
void *fgmm_expiry_t3519_handler(void *args);

#endif /* __NR_NAS_MSG_SIM_H__*/
