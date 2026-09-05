# SPDX-License-Identifier: LicenseRef-CSSL-1.0

add_library(nas_utils OBJECT
    TLVDecoder.c
    OctetString.c
    nas_timer.c
)
target_link_libraries(nas_utils PUBLIC log_headers asn1_lte_rrc_hdrs asn1_nr_rrc_hdrs)

target_include_directories(nas_utils PRIVATE .)
