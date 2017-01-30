/*--------------------------------------------------------------------------*/
/* Copyright (C) 2015 - 2016 by Tibit Communications, Inc.                  */
/* All rights reserved.                                                     */
/*                                                                          */
/*    _______ ____  _ ______                                                */
/*   /_  __(_) __ )(_)_  __/                                                */
/*    / / / / __  / / / /                                                   */
/*   / / / / /_/ / / / /                                                    */
/*  /_/ /_/_____/_/ /_/                                                     */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/* PROPRIETARY NOTICE                                                       */
/* This Software consists of confidential information.                      */
/* Trade secret law and copyright law protect this Software.                */
/* The above notice of copyright on this Software does not indicate         */
/* any actual or intended publication of such Software.                     */
/*--------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <common.h>
#include <cli.h>
#include <command.h>
#include <assert.h>

#include "tb_dbug.h"
#include "tb_port.h"
#include "tb_util.h"
#include "tb_global.h"
#include "tb_types.h"

#include "cli_version.h"
#include "mgmt_json.h"
#include "brdg.h"
#include "os_interface.h"
#include "jsmn.h"

#include "olt_fsm.h"
#include "onu_fsm.h"
#include "eth_fsm.h"
#include "hal_llid.h"
#include "hal_frame.h"
#include "switching.h"

#include "ieee_802.3.h"


/*--- global variables -----------------------------------------------------*/
static tb_pkt_deprec_t fake_frame;      /* for commands from the CLI */
extern const char *brdg_stat_name_lower[];
extern const char *brdg_stat_total_lower[];
static bool command_line_json = false;

/*--- definitions ----------------------------------------------------------*/
#define FRAME_CRC_SIZE           4
#define VLAN_HEADER_BYTES        4

#define START_OF_JSON_VLAN       (27 + (VLAN_HEADER_BYTES))
#define START_OF_JSON_UNTAGGED   (27)
#define COPY_TYPE                0x636f7079 // 'copy'
#define DNLD_TYPE                0x646e6c64 // 'dnld'
#define JSON_TYPE                0x6a736f6e     /* ASCII HEX 'json' */
#define JSON_MAX_INTERFACES      5
typedef enum json_string_print { APPEND, APPEND_AND_FLUSH, APPEND_AND_FLUSH_CR,
    RESET
} json_string_print_t;

/*--- function prototypes --------------------------------------------------*/
void hw_reset(void);
int set_sernum_and_mac_address(unsigned int);
static int dump(const char *js, jsmntok_t * t, size_t count, int indent);
static int remove_backslashes(char *working, uint8_t * p_buffer, unsigned int length);

/*--- more globals ---------------------------------------------------------*/
static char global_json_string[SIZE_OF_JSON_STRING] = { '\0' };

static char operation[SIZE_OF_OPERATION] = { '\0' };
static char location[SIZE_OF_ADDRESS] = { '\0' };
static char value[SIZE_OF_VALUE] = { '\0' };
static char llid[SIZE_OF_LLID] = { '\0' };
static char macblock[SIZE_OF_MACBLOCK] = { '\0' };
static char itype[SIZE_OF_ITYPE] = { '\0' };
static char iinst[SIZE_OF_IINST] = { '\0' };
static char mac[MAC_STR_LEN] = { '\0' };
static char swr[SIZE_OF_SWR] = { '\0' };
static char cmd[SIZE_OF_CMD] = { '\0' };

#define SVID_STR_LEN 5
#define CVID_STR_LEN 5
static char svid[SVID_STR_LEN] = { '\0' };
static char cvid[CVID_STR_LEN] = { '\0' };

static mac_address mac_addr;
#define CIR_STR_LEN 12
#define EIR_STR_LEN 12
static char cir[CIR_STR_LEN] = { '\0' };
static char eir[EIR_STR_LEN] = { '\0' };

#define CODE_STR_LEN 5
static char code[CODE_STR_LEN] = { '\0' };

#define TPID_STR_LEN 5
static char tpid[TPID_STR_LEN] = { '\0' };

#define VID_STR_LEN 5
static char vid[VID_STR_LEN] = { '\0' };

#define MODE_STR_LEN 9
static char mode[MODE_STR_LEN] = { '\0' };

#define TAG_MODE_STR_LEN 5
static char tag_mode[TAG_MODE_STR_LEN] = { '\0' };

/*--- more function prototypes ---------------------------------------------*/
static int process_copy(const uint8_t *, uint32);
static int process_dnld(const uint8_t *, uint32);
static int process_json(tb_pkt_deprec_t *);
static int json_error(tb_pkt_deprec_t *, brdg_return_t);
static int json_version(tb_pkt_deprec_t *);
static int json_interfaces(tb_pkt_deprec_t *);
static int json_links(tb_pkt_deprec_t *, char *, tb_ifc_inst_t);
static int json_register_read(tb_pkt_deprec_t *, unsigned int address);
static int json_register_write(tb_pkt_deprec_t *, unsigned int address, unsigned int value);
static int json_stats(tb_pkt_deprec_t *, unsigned int llid, unsigned int macblock);
static tb_rc json_tag_mode_get(tb_pkt_deprec_t * rx_frame);
static tb_rc json_tag_mode_set(tb_pkt_deprec_t * rx_frame, char * tag_mode);
static tb_rc json_fec_set(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key, bool);
static tb_rc json_fec_get(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key);
static tb_rc json_sla_set(tb_pkt_deprec_t * rx_frame, lsm_link_key_t * link_key,
                          lsm_link_sla_spec_t * sla_spec);
static tb_rc json_sla_get(tb_pkt_deprec_t * rx_frame, lsm_link_key_t * link_key,
                          lsm_link_sla_spec_t * sla_spec);
static tb_rc json_flows_add(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key,
                            sw_rec_key_t * sw_rec_key, port_vlan_op_cfg_t port_vlan_op_cfg);
static tb_rc json_flows_delete(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key,
                              sw_rec_key_t * sw_rec_key);
static tb_rc json_flows_get(tb_pkt_deprec_t * rx_frame);
static tb_rc json_mode_set(tb_pkt_deprec_t * rx_frame, mandata_pon_type_t mandata_pon);
static int json_cli_cmd(tb_pkt_deprec_t *);

static int json_str_append_and_out(char *, char *, json_string_print_t, tb_pkt_deprec_t *);

// mac_address mgmt_mac_addr = { .u8 = { 0x08, 0x00, 0x27, 0x63, 0xe8, 0x6e } };
mac_address mgmt_mac_addr = { .u8 = { 0x84, 0x38, 0x35, 0x4e, 0x9b, 0xb2 } };

void mgmt_mac_addr_set(const mac_address *new_mgmt_mac_addr) {
    tb_mac_address_str_t  old;

    assert(new_mgmt_mac_addr);

    tb_mac_address_to_str(mgmt_mac_addr.u8, old);

    if (0 != memcmp(mgmt_mac_addr.u8, new_mgmt_mac_addr->u8, sizeof(mgmt_mac_addr))) {
        tb_mac_address_str_t  new;

        tb_mac_address_to_str(new_mgmt_mac_addr->u8, new);

        TB_TRACE("updating mgmt_mac_addr   %s -> %s", old, new);

        memcpy(mgmt_mac_addr.u8, new_mgmt_mac_addr->u8, sizeof(mgmt_mac_addr));
    } else {
        // TB_TRACE("mgmt_mac_addr %s (unchanged)", old);
    }
}

void mgmt_mac_addr_get(void *mgmt_mac_addr_dest) {
    assert(mgmt_mac_addr_dest);
    memcpy(mgmt_mac_addr_dest, mgmt_mac_addr.u8, sizeof(mgmt_mac_addr));
}

/**
 *  @brief Forward an OAM Request to the designated MAC Address
 *
 * @param rx_frame   Pointer to OAM message to be forwarded
 * @param dst_mac    Pointer to Destination MAC Address
 * @param src_mac    Pointer to Source MAC Address
 * @param oam_start  Pointer to Protocol Subtype (0x03 for OAM) in frame
 * @param onu_vid    ONU VID Value
 *
 * @return tb_rc
 */
static
tb_rc cli_forward_oam(tb_pkt_deprec_t * rx_frame, mac_address *dst_mac,
                      mac_address *src_mac, const uint8_t *oam_start, uint16_t onu_vid)
{
    tb_rc rc = TB_RC_OK;

    unsigned int payload_length = ((unsigned int)rx_frame->num_bytes) - (oam_start - &rx_frame->preamble_start[0]);
    unsigned int frame_length = 0;

    /* Set destination MAC to EOAM multicast mac */
    memcpy(&rx_frame->preamble_start[8], &multicast_da_oam, sizeof(mac_address));

    /* Set source MAC to OLT MAC address */
    memcpy(&rx_frame->preamble_start[14], &tbg.mac_1_address, sizeof(mac_address));

    /* Set the type and copy in the payload */
    tb_pack_u16(&rx_frame->preamble_start[20], 0x8809);

    /* Zero out CRC on frame just to make sure that it is not be reused */
    memset(&rx_frame->preamble_start[rx_frame->num_bytes - 4], 0, 4);

    /* Copy in the frame */
    memcpy(&rx_frame->preamble_start[22], oam_start, payload_length);

    /* NEW Frame Length */
    frame_length = 6    /* dest  */
        + 6             /* source */
        + 2             /* type */
        + payload_length;

    TB_TRACE("tx length %d (w/o preamble)", frame_length);
    rx_frame->num_bytes = frame_length;

    rc = oam_olt_send_oam_to_onu(rx_frame->preamble_start + 8, frame_length,
                                 src_mac, dst_mac, OLT_OAM_ORIGIN_HOST, onu_vid);
    return rc;
}


tb_rc cli_handle_rx_frame(tb_pkt_deprec_t * rx_frame)
{
    tb_rc rc = TB_RC_OK;
    unsigned int jsonType = 0;
    const uint8_t  *payload_start = &rx_frame->preamble_start[8]; // real payload starts after 8-byte preamble
    const uint8_t  *ethtype_start = payload_start + 2*sizeof(mac_address);
    const uint8_t  *json_start;
    uint16_t vid = 0;
    unsigned short  ethType       = (ethtype_start[0] << 8) | ethtype_start[1];

    mac_address  dest_addr;
    memcpy(dest_addr.u8, payload_start, sizeof(mac_address));

    mac_address  remote_addr;
    memcpy(remote_addr.u8, payload_start+sizeof(mac_address), sizeof(mac_address));
    mgmt_mac_addr_set((const mac_address *)(payload_start+sizeof(mac_address)));

    tb_mac_address_str_t  remote_addr_str;
    tb_mac_address_to_str(remote_addr.u8, remote_addr_str);

    tb_dbug_hexdump_one_line(TB_DBUG_LVL_DEBUG, __FUNCTION__, __LINE__, rx_frame->preamble_start, 0, rx_frame->num_bytes+8, COLOR_RED "Frame:   " COLOR_OFF , "<---");

    TB_DEBUG("payload_start %p  remote %s   ethtype_start %p   ethtype %04x  num_bytes %u   rx_que %u   tx_que %u   data %08lx", payload_start, remote_addr_str, ethtype_start, ethType, rx_frame->num_bytes, rx_frame->rx_que, rx_frame->tx_que, (uint32_t) rx_frame->data);

    while ((0x88a8 == ethType) || (0x8100 == ethType)) {
        vid = ((ethtype_start[2] << 8) | ethtype_start[3]) & 0xfff;
        TB_TRACE("skipping %c-tag, value %04d (0x%03x), ethtype_start %p -> %p",
                 (0x88a8 == ethType) ? 'S' : 'C',
                 vid, vid,
                 ethtype_start,
                 ethtype_start+4);

        ethtype_start += 4;
        ethType = (ethtype_start[0] << 8) | ethtype_start[1];
    }
    json_start = ethtype_start + 2;
    if (ethType != 0x9001) {
        TB_WARNING("FRAME ETHERTYPE NOT 0x9001");
        TB_ERROR("ethtype  0x%04x (actual) vs. 0x9001 (expected)", ethType);
        tb_dbug_hexdump_one_line(TB_DBUG_LVL_ERROR, __FUNCTION__, __LINE__,
                                     rx_frame->preamble_start,
                                     0,
                                     rx_frame->num_bytes+8,
                                     COLOR_RED "Frame:   ", "<---" COLOR_OFF );
        return 0;
    }

    jsonType = ((json_start[0] << 24) |
                (json_start[1] << 16) |
                (json_start[2] <<  8) |
                (json_start[3] <<  0));

    switch (jsonType) {
        case COPY_TYPE: {
            uint32 length = ((unsigned int)rx_frame->num_bytes) - (json_start - &rx_frame->preamble_start[0]);
            process_copy(json_start+4, length);
            break;
        } // case COPY_TYPE

        case DNLD_TYPE: {
            uint32 length = ((unsigned int)rx_frame->num_bytes) - (json_start - &rx_frame->preamble_start[0]);
            process_dnld(json_start+4, length);
            break;
        } // case DNLD_TYPE

        case JSON_TYPE:
            process_json(rx_frame);
            break;

            // case 0x030050fe:        /* 03:OAM 0050:FLAGS fe:OAMPDU */
        default: {
            uint8_t  subtype = json_start[0];

            switch (subtype) {

                case slow_protocol_subtype_oam: {
                    uint16_t flags_expected = oam_flag_loc_stab | oam_flag_rem_stab; // 0x50;
                    uint16_t flags_actual   = tb_unpack_u16(json_start+1);

                    if (flags_expected != flags_actual) {
                        TB_WARNING("unexpected flags  0x%04x actual vs. 0x%04x expected",
                            flags_actual, flags_expected);
                        rc = TB_RC_REMOTE_PEER_RESP;
                    } else {
                        uint8_t        opcode               = json_start[3];

                        switch (opcode) {
                            case oam_pdu_code_organization_specific: {

                                /* If the destination address for the OAM PDU was the OLT's
                                 * ethernet port, then invoke the local OAM handling code. */
                                if ((!memcmp(dest_addr.u8, tbg.mac_0_address.u8, sizeof(mac_address))) &&
                                    (vid == 0))
                                {
                                    uint32 length = ((unsigned int)rx_frame->num_bytes) - (json_start - &rx_frame->preamble_start[0]);

                                    if (0 == memcmp(json_start+4, dpoe_oui, 3)) {
                                        TB_TRACE("dispatching to DPoE organization-specific handler");
                                        rc = oam_hdl_org_spec_dpoe(&remote_addr, json_start+7, length-7);
                                    } else if (0 == memcmp(json_start+4, tibit_oam_oui, 3)) {
                                        TB_TRACE("dispatching to Tibit organization-specific handler");
                                        rc = oam_hdl_org_spec_tibit(&remote_addr, json_start+7, length-7);
                                    } else {
                                        uint32         oui                  = tb_unpack_u24(json_start+4);
                                        TB_ERROR("unknown organization-specific OUI %06x", oui);
                                        rc = TB_RC_REMOTE_PEER_RESP;
                                    }

                                } else if (olt_device_p()) {
                                    /* Forward the OAM request */
                                    if (vid != 0) {
                                        /* Constructing the ONU MAC address from the VLAN value. For the board MAC
                                         * address, all Tibit MAC addresses use the EPON identifier */
                                        dest_addr.u8[3] = (unsigned char)(MANDATA_PON_TYPE_10G_EPON_ONU << 4)
                                            | TB_IFC_TYPE_ONU;
                                        dest_addr.u8[4] = (vid - VOLTHA_ONU_BASE_VLAN);
                                    }
                                    dest_addr.u8[0] = 0x00;
                                    dest_addr.u8[1] = 0x25;
                                    dest_addr.u8[2] = 0xdc;
                                    dest_addr.u8[3] = 0xd9;

                                    dest_addr.u8[5] = 0x10;

                                    rc = cli_forward_oam(rx_frame, &dest_addr, &remote_addr, json_start, vid);
                                } else {
                                    TB_ERROR("Can only forward OAM PDUs from an OLT");
                                    rc = TB_RC_REMOTE_PEER_RESP;
                                }

                                break;
                            } // case 0xfe

                            default:
                                TB_ERROR("unknown opcode 0x%x", opcode);
                                rc = TB_RC_REMOTE_PEER_RESP;
                                break;
                        } // switch (opcode)
                    } // else

                    break;
                } // case slow_protocol_subtype_oam

                default:
                    TB_ERROR("unknown subtype 0x%02x", subtype);
                    rc = TB_RC_REMOTE_PEER_RESP;
                    break;
            } // switch (subtype)

            // uint32 length = ((unsigned int)rx_frame->num_bytes) - (json_start - &rx_frame->preamble_start[0]);
            TB_TRACE("rx_frame->num_bytes %u  json_offset %u", rx_frame->num_bytes, (json_start - &rx_frame->preamble_start[0]));

            tb_dbug_hexdump_one_line(TB_DBUG_LVL_TRACE, __FUNCTION__, __LINE__,
                                     rx_frame->preamble_start,
                                     0,
                                     rx_frame->num_bytes+8,
                                     "Frame:   ", "<---");

            const uint8_t *dpoe_org_spec_start = json_start;
            uint32        dpoe_org_spec_length = ((unsigned int)rx_frame->num_bytes) - (json_start - &rx_frame->preamble_start[0]);

            tb_dbug_hexdump_one_line(TB_DBUG_LVL_TRACE, __FUNCTION__, __LINE__, dpoe_org_spec_start, 0, dpoe_org_spec_length, "orgspec: ", "<---");
            break;
        } // default
    } // switch (jsonType)

    return rc;
}

static int dump(const char *js, jsmntok_t * t, size_t count, int indent)
{
    int i, j, k;
    static int found_operation = 0;
    static int found_location = 0;
    static int found_value = 0;
    static int found_llid = 0;
    static int found_macblock = 0;
    static int found_itype = 0;
    static int found_iinst = 0;
    static int found_mac = 0;
    static int found_cir = 0;
    static int found_eir = 0;
    static int found_swr = 0;
    static int found_cvid = 0;
    static int found_svid = 0;
    static int found_cmd = 0;
    static int found_code = 0;
    static int found_tpid = 0;
    static int found_vid = 0;
    static int found_mode = 0;
    static int found_tag_mode = 0;

    if (count == 0) {
        return 0;
    }
    if (t->type == JSMN_PRIMITIVE) {
        TB_TRACE("PRIMITIVE: ");
        TB_TRACE("%.*s", t->end - t->start, js + t->start);
        return 1;
    } else if (t->type == JSMN_STRING) {
        TB_INFO("STRING: ");
        TB_INFO("'%.*s'", t->end - t->start, js + t->start);
        /*--- "operation" command ------------------------------------------*/
        if (found_operation == 1) {
            TB_INFO(" ACTION: storing 'operation' string");
            if (strncmp("code", js + t->start, t->end - t->start) == 0) {
                TB_TRACE("skipping code!");
            } else {
                memset(operation, 0, SIZE_OF_OPERATION);
                strncpy(operation, js + t->start, t->end - t->start);
            }
            found_operation = 0;
        }
        if (strncmp("operation", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'operation'");
            found_operation = 1;
        }
        /*--- "location" command -------------------------------------------*/
        if (found_location == 1) {
            TB_INFO(" ACTION: storing 'location'");
            memset(location, 0, SIZE_OF_ADDRESS);
            strncpy(location, js + t->start, t->end - t->start);
            found_location = 0;
        }
        if (strncmp("address", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'location'");
            found_location = 1;
        }
        /*--- "value" ------------------------------------------------------*/
        if (found_value == 1) {
            TB_INFO(" ACTION: storing 'value'");
            memset(value, 0, SIZE_OF_VALUE);
            strncpy(value, js + t->start, t->end - t->start);
            found_value = 0;
        }
        if (strncmp("value", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'value'");
            found_value = 1;
        }
        /*--- "llid" -------------------------------------------------------*/
        if (found_llid == 1) {
            TB_INFO(" ACTION: storing 'llid'");
            memset(llid, 0, SIZE_OF_LLID);
            strncpy(llid, js + t->start, t->end - t->start);
            found_llid = 0;
        }
        if (strncmp("llid", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'llid'");
            found_llid = 1;
        }
        /*--- "macblock" ---------------------------------------------------*/
        if (found_macblock == 1) {
            TB_INFO(" ACTION: storing 'macblock'");
            memset(macblock, 0, SIZE_OF_MACBLOCK);
            strncpy(macblock, js + t->start, t->end - t->start);
            found_macblock = 0;
        }
        if (strncmp("macblock", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'macblock'");
            found_macblock = 1;
        }
        /*--- "itype" ---------------------------------------------------*/
        if (found_itype == 1) {
            TB_INFO(" ACTION: storing 'itype'");
            strncpy(itype, js + t->start, t->end - t->start);
            found_itype = 0;
        }
        if (strncmp("itype", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'itype'");
            found_itype = 1;
        }
        /*--- "iinst" ---------------------------------------------------*/
        if (found_iinst == 1) {
            TB_INFO(" ACTION: storing 'iinst'");
            strncpy(iinst, js + t->start, t->end - t->start);
            found_iinst = 0;
        }
        if (strncmp("iinst", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'iinst'");
            found_iinst = 1;
        }
        /*--- "swr" ---------------------------------------------------*/
        if (found_swr == 1) {
            TB_INFO(" ACTION: storing 'swr'");
            strncpy(swr, js + t->start, t->end - t->start);
            found_swr = 0;
        }
        if (strncmp("swr", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'swr'");
            found_swr = 1;
        }
        /*--- "mac" --------------------------------------------------------*/
        if (found_mac == 1) {
            TB_INFO(" ACTION: storing 'mac'");
            strncpy(mac, js + t->start, t->end - t->start);

            if (sizeof(mac_addr) != tb_str_to_buf(mac_addr.u8, mac, sizeof(mac_addr))) {
                TB_ERROR("failed to parse macid `%s'", mac);
            }

            found_mac = 0;
        }
        if (strncmp("mac", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'mac'");
            found_mac = 1;
        }
        /*--- "macid" ------------------------------------------------------*/
        if (found_mac == 1) {
            TB_INFO(" ACTION: storing 'macid'");
            strncpy(mac, js + t->start, t->end - t->start);

            if (sizeof(mac_addr) != tb_str_to_buf(mac_addr.u8, mac, sizeof(mac_addr))) {
                TB_ERROR("failed to parse macid `%s'", mac);
            }

            found_mac = 0;
        }
        if (strncmp("macid", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'macid'");
            found_mac = 1;
        }
        /*--- "cir" ---------------------------------------------------*/
        if (found_cir == 1) {
            TB_INFO(" ACTION: storing 'cir'");
            strncpy(cir, js + t->start, t->end - t->start);
            found_cir = 0;
        }
        if (strncmp("cir", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'cir'");
            found_cir = 1;
        }
        /*--- "eir" ---------------------------------------------------*/
        if (found_eir == 1) {
            TB_INFO(" ACTION: storing 'eir'");
            strncpy(eir, js + t->start, t->end - t->start);
            found_eir = 0;
        }
        if (strncmp("eir", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'eir'");
            found_eir = 1;
        }
        /*--- "svid" ---------------------------------------------------*/
        if (found_svid == 1) {
            TB_INFO(" ACTION: storing 'svid'");
            strncpy(svid, js + t->start, t->end - t->start);
            found_svid = 0;
        }
        if (strncmp("svid", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'svid'");
            found_svid = 1;
        }
        /*--- "cvid" ---------------------------------------------------*/
        if (found_cvid == 1) {
            TB_INFO(" ACTION: storing 'cvid'");
            strncpy(cvid, js + t->start, t->end - t->start);
            found_cvid = 0;
        }
        if (strncmp("cvid", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'cvid'");
            found_cvid = 1;
        }
        /*--- "cmd" --------------------------------------------------------*/
        if (found_cmd == 1) {
            TB_INFO(" ACTION: storing 'cmd'");
            strncpy(cmd, js + t->start, t->end - t->start);
            found_cmd = 0;
        }
        if (strncmp("cmd", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'cmd'");
            found_cmd = 1;
        }
        /*--- "code" -------------------------------------------------------*/
        if (found_code == 1) {
            TB_INFO(" ACTION: storing 'code'");
            memset(code, 0, sizeof(CODE_STR_LEN));
            strncpy(code, js + t->start, t->end - t->start);
            found_code = 0;
        }
        if (strncmp("code", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'code'");
            found_code = 1;
        }
        /*--- "tpid" -------------------------------------------------------*/
        if (found_tpid == 1) {
            TB_INFO(" ACTION: storing 'tpid'");
            memset(tpid, 0, sizeof(TPID_STR_LEN));
            strncpy(tpid, js + t->start, t->end - t->start);
            found_tpid = 0;
        }
        if (strncmp("tpid", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'tpid'");
            found_tpid = 1;
        }
        /*--- "vid" --------------------------------------------------------*/
        if (found_vid == 1) {
            TB_INFO(" ACTION: storing 'vid'");
            memset(vid, 0, sizeof(VID_STR_LEN));
            strncpy(vid, js + t->start, t->end - t->start);
            found_vid = 0;
        }
        if (strncmp("vid", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'vid'");
            found_vid = 1;
        }
        /*--- "mode" --------------------------------------------------------*/
        if (found_mode == 1) {
            TB_INFO(" ACTION: storing 'mode'");
            memset(mode, 0, sizeof(MODE_STR_LEN));
            strncpy(mode, js + t->start, t->end - t->start);
            found_mode = 0;
        }
        if (strncmp("mode", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'mode'");
            found_mode = 1;
        }
        /*--- "mode" --------------------------------------------------------*/
        if (found_tag_mode == 1) {
            TB_INFO(" ACTION: storing 'tag_mode'");
            memset(tag_mode, 0, sizeof(TAG_MODE_STR_LEN));
            strncpy(tag_mode, js + t->start, t->end - t->start);
            found_tag_mode = 0;
        }
        if (strncmp("tag_mode", js + t->start, t->end - t->start) == 0) {
            TB_INFO(" ACTION: found 'tag_mode'");
            found_tag_mode = 1;
        }
        return 1;
    } else if (t->type == JSMN_OBJECT) {
        TB_INFO("OBJECT: ");
        TB_INFO("\n");
        j = 0;
        for (i = 0; i < t->size; i++) {
            for (k = 0; k < indent; k++)
                TB_INFO("  ");
            /* tb_printf("---  dump one --- [j=%d] [count=%d, count - j = %d]\n", j, count, count-j); */
            j += dump(js, t + 1 + j, count - j, indent + 1);
            TB_INFO(": ");
            if ((count - j - 1) > 0) {
                /* tb_printf("---  dump two --- [j=%d] [count=%d, count - j = %d]\n", j, count, count-j); */
                j += dump(js, t + 1 + j, count - j, indent + 1);
            }
            TB_INFO("\n");
        }
        return j + 1;
    } else if (t->type == JSMN_ARRAY) {
        TB_INFO("ARRAY: ");
        j = 0;
        TB_INFO("\n");
        for (i = 0; i < t->size; i++) {
            for (k = 0; k < indent - 1; k++)
                TB_INFO("  ");
            TB_INFO("   - ");
            j += dump(js, t + 1 + j, count - j, indent + 1);
            TB_INFO("\n");
        }
        return j + 1;
    }
    return 0;
}

static int json_version(tb_pkt_deprec_t * rx_frame)
{
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    brdg_mem_t brdg_memory;
    tb_mac_address_str_t mac_str;
    brdg_return_t rc;

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    sprintf(tmp_string, "{\"operation\": \"version\", \"success\": true, \"results\": {");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    /* get bridge memory values */
    brdg_mem_t_init(&brdg_memory);
    brdg_memory.addr = 0x10000000;
    brdg_memory.num = 3;
    rc = brdg_mem_read(&brdg_memory);

    if (rc != BRDG_RET_OK) {
        json_error(rx_frame, rc);
    }

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"manufacturer\": \"%08x\",", brdg_memory.data[0]);
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    switch (tbg.PON) {
        case MANDATA_PON_TYPE_10G_EPON_ONU:
            sprintf(tmp_string, "\"device\": \"10G EPON ONU\",");
            break;
        case MANDATA_PON_TYPE_10G_EPON_OLT:
            sprintf(tmp_string, "\"device\": \"10G EPON OLT\",");
            break;
        case MANDATA_PON_TYPE_10G_GPON_ONU:
            sprintf(tmp_string, "\"device\": \"10G GPON ONT\",");
            break;
        case MANDATA_PON_TYPE_10G_GPON_OLT:
            sprintf(tmp_string, "\"device\": \"10G GPON OLT\",");
            break;
        case MANDATA_PON_TYPE_1G_P2P:
        case MANDATA_PON_TYPE_10G_P2P:
            sprintf(tmp_string, "\"device\": \"10G/1G LAN\",");
            break;
        case MANDATA_PON_TYPE_1G_EPON_ONU:
        case MANDATA_PON_TYPE_1G_GPON_ONU:
        case MANDATA_PON_TYPE_1G_GPON_OLT:
        case MANDATA_PON_TYPE_1G_EPON_OLT:
            sprintf(tmp_string, "\"device\": \"1G PON DEVICE\",");
            break;
        default:
        case MANDATA_PON_TYPE_UNK:
            sprintf(tmp_string, "\"device\": \"UNK\",");
            break;
    }
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"datecode\": \"%08x\",", brdg_memory.data[2]);
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"firmware\": \"%02d:%02d:%02d\",", __VERSION_MAJOR__, __VERSION_MINOR__,
            __VERSION_REVISION__);
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"modelversion\": \"%s\",", "1.0");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"macid\": \"%s\"", tb_mac_address_to_str(tbg.mac_0_address.u8, mac_str));
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}, ");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"error\": null");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);
    return 0;
}

static int json_interfaces(tb_pkt_deprec_t * rx_frame)
{
    int i;
    uint8_t max_count = 5;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    tb_ifc_key_t olt_ifc_keys[JSON_MAX_INTERFACES];
    tb_ifc_key_t onu_ifc_keys[JSON_MAX_INTERFACES];
    tb_ifc_key_t eth_ifc_keys[JSON_MAX_INTERFACES];

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"interfaces\", \"success\": true, \"results\":[");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    if (onu_device_p()) {
        onu_fsm_report_all_ifc_keys(&max_count, onu_ifc_keys);
        if (max_count < JSON_MAX_INTERFACES) {
            for (i = 0; i < max_count; i++) {
                memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                sprintf(tmp_string, "{\"iinst\": \"%d\", \"itype\": \"onu\"}, ",
                        onu_ifc_keys[i].inst);
                json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
            }
        } else {
            TB_TRACE("E:Num ifcs > size of table (%s:%d)", __FUNCTION__, __LINE__);
        }
    }

    if (olt_device_p()) {
        olt_fsm_report_all_ifc_keys(&max_count, olt_ifc_keys);
        if (max_count < JSON_MAX_INTERFACES) {
            for (i = 0; i < max_count; i++) {
                memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                sprintf(tmp_string, "{\"iinst\": \"%d\", \"itype\": \"olt\"}, ",
                        olt_ifc_keys[i].inst);
                json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
            }
        } else {
            TB_TRACE("E:Num ifcs > size of table (%s:%d)", __FUNCTION__, __LINE__);
        }
    }

    eth_fsm_report_all_ifc_keys(&max_count, eth_ifc_keys);
    if (max_count < JSON_MAX_INTERFACES) {
        for (i = 0; i < max_count; i++) {
            memset(tmp_string, 0, SIZE_OF_TMP_STRING);
            sprintf(tmp_string, "{\"iinst\": \"%d\", \"itype\": \"eth\"}", eth_ifc_keys[i].inst);
            json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
        }
    } else {
        TB_TRACE("E:Num ifcs > size of table (%s:%d)", __FUNCTION__, __LINE__);
    }

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "],\"error\":null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return 0;
}                               /* json_interfaces */

#define MAX_REGISTERED_LINKS 16 /* for now... */
static int json_links(tb_pkt_deprec_t * rx_frame, UNUSED_ARG char *itype, UNUSED_ARG tb_ifc_inst_t iinst)
{
    int i;
    tb_mac_address_str_t mac_str = "";
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    mac_address all_zeros_mac = {.u8 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
    int num_links = 0;

    mac_address registered_mac_addresses[MAX_REGISTERED_LINKS];

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    num_links = lsm_report_all_links_mgmt(registered_mac_addresses);

    if (num_links >= MAX_REGISTERED_LINKS) {
        TB_ERROR("Out of bounds error, more links than memory allocated");
    } else if (num_links < 0) {
        /* error condition */
        TB_TRACE("I: (%s:%d)", __FUNCTION__, __LINE__);
    }

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"links\", ");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    if (num_links) {
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        sprintf(tmp_string, "\"success\": true, \"results\":[");
        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

        for (i = 0; i < num_links; i++) {
            memset(tmp_string, 0, SIZE_OF_TMP_STRING);
            tb_mac_address_to_str(registered_mac_addresses[i].u8, mac_str);
            if (i + 1 == num_links) {
                sprintf(tmp_string, "{\"macid\": \"%s\"}", mac_str);
            } else {
                sprintf(tmp_string, "{\"macid\": \"%s\"},", mac_str);
            }
            json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
        }
    } else {
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        sprintf(tmp_string, "\"success\": true, \"results\":[");
        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        tb_mac_address_to_str(all_zeros_mac.u8, mac_str);
        /* sprintf(tmp_string, "{\"macid\": \"%s\"}", mac_str); */
        /* json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame); */
    }

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return 0;
}                               /* json_links */

static int json_register_read(tb_pkt_deprec_t * rx_frame, unsigned int address)
{
    brdg_mem_t brdg_memory;
    brdg_return_t rc = BRDG_RET_OK;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"register_read\", \"success\": true, \"results\": {");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);

    brdg_mem_t_init(&brdg_memory);
    brdg_memory.addr = address;
    brdg_memory.num = 1;
    rc = brdg_mem_read(&brdg_memory);

    sprintf(tmp_string, "\"value\": \"%08x\"", brdg_memory.data[0]);
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}, ");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"error\": null");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

static int json_register_write(tb_pkt_deprec_t * rx_frame, unsigned int address, unsigned int value)
{
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    brdg_mem_t brdg_memory;
    brdg_return_t rc = BRDG_RET_OK;

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    brdg_mem_t_init(&brdg_memory);
    brdg_memory.addr = address;
    brdg_memory.num = 1;
    brdg_memory.data[0] = value;
    rc = brdg_mem_write(&brdg_memory);

    if (rc == BRDG_RET_OK) {
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        sprintf(tmp_string,
                "{\"operation\": \"register_write\", \"success\": true, \"error\": null}");
        json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);
    } else {
        json_error(rx_frame, rc);
    }

    return rc;

}                               /* json_register_write */

static int json_stats(tb_pkt_deprec_t * rx_frame, unsigned int lidx, brdg_mac_block_t mac_block)
{
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    unsigned long long int wide_total = 0;
    brdg_return_t rc = BRDG_RET_OK;
    brdg_dpram_t output;
    brdg_dpram_t *p_out;
    unsigned int s;

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    p_out = &output;
    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"stats\", \"success\": true, \"results\":{");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    for (s = 0; s < 31; s++) {
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        p_out->num = 1;
        if (lidx == 256) {
            rc = (mac_block == MB0) ? brdg_dpram_read(SLCT_MSTAT_RDCLR_0, (s << 5) | 31,
                                                      p_out) : brdg_dpram_read(SLCT_MSTAT_RDCLR_1,
                                                                               (s << 5) | 31,
                                                                               p_out);
        } else {
            rc = (mac_block == MB0) ? brdg_dpram_read(SLCT_MSTAT_RDCLR_0, (lidx << 5) | s,
                                                      p_out) : brdg_dpram_read(SLCT_MSTAT_RDCLR_1,
                                                                               (lidx << 5) | s,
                                                                               p_out);
        }
        if (rc == BRDG_RET_OK) {
            sprintf(tmp_string, "\"%s\":\"%u\", ", brdg_stat_name_lower[s], p_out->data[0]);
        }
        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
    }

    for (s = 0; s < 7; s++) {
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        p_out->num = 2;
        if (lidx == 256) {
            rc = (mac_block == MB0) ? brdg_dpram_read(SLCT_MWIDE_RDCLR_0, (s << 3) | 7,
                                                      p_out) : brdg_dpram_read(SLCT_MWIDE_RDCLR_1,
                                                                               (s << 3) | 7, p_out);
        } else {
            rc = (mac_block == MB0) ? brdg_dpram_read(SLCT_MWIDE_RDCLR_0, (lidx << 3) | s,
                                                      p_out) : brdg_dpram_read(SLCT_MWIDE_RDCLR_1,
                                                                               (lidx << 3) | s,
                                                                               p_out);
        }
        if (rc == BRDG_RET_OK) {
            wide_total = p_out->data[1];
            wide_total <<= 32ULL;
            wide_total += p_out->data[0];
            if (s != 6) {       /* ! last one */
                sprintf(tmp_string, "\"%s\":\"%llu\", ", brdg_stat_total_lower[s], wide_total);
            } else {
                sprintf(tmp_string, "\"%s\":\"%llu\"", brdg_stat_total_lower[s], wide_total);
            }
        }
        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
    }

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}, ");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"error\": null");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

static int json_error(tb_pkt_deprec_t * rx_frame, brdg_return_t brdg_return_code)
{
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"%s\", \"success\": false, \"results\": {}, ", operation);
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    switch (brdg_return_code) {
    case BRDG_RET_INPUT_INVALID:
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        sprintf(tmp_string, "\"error\": {\"code\": 2, \"message\": \"Missing parameters\"");
        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
        break;
    default:
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        sprintf(tmp_string, "\"error\": {\"code\": 5, \"message\": \"Unknown error\"");
        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

        break;
    }

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return 0;
}

static int json_str_append_and_out(char *global_json_string, char *tmp_string,
                                   json_string_print_t output, tb_pkt_deprec_t * rx_frame)
{
    uint i;
    static int offset = 0;
    mac_address tmp_mac;

    if (output != RESET) {
        TB_TRACE("jstr: @pos[%d] + %d chars", offset, (int)strlen(tmp_string));
        strncpy(global_json_string + offset, tmp_string, strlen(tmp_string));
        offset += strlen(tmp_string);
    }

    switch (output) {
    case RESET:
        offset = 0;
        break;

    case APPEND_AND_FLUSH:
        offset = 0;
        TB_TRACE("%s", global_json_string);
        break;

    case APPEND_AND_FLUSH_CR:
        if (command_line_json) {
            tb_printf("%s\n", global_json_string);
            command_line_json = false;
        } else {
            TB_TRACE("%s", global_json_string);
        }
        /* store src address in tmp */
        memcpy(tmp_mac.u8, &rx_frame->preamble_start[14], sizeof(mac_address));
        /* make src my mac */
        memcpy(&rx_frame->preamble_start[14], tbg.mac_0_address.u8, sizeof(mac_address));
        /* make tmp src new dst */
        memcpy(&rx_frame->preamble_start[8], tmp_mac.u8, sizeof(mac_address));
        if (tbg.mgmt_vlan != MGMT_VLAN_DISABLED) {
            /* VLAN HEADER: */
            rx_frame->preamble_start[20] = tbg.outer_tpid >> 8;
            rx_frame->preamble_start[21] = tbg.outer_tpid & 0xff;
            rx_frame->preamble_start[22] = (MGMT_VLAN_PRIORITY << 5) | (tbg.mgmt_vlan >> 8);
            rx_frame->preamble_start[23] = tbg.mgmt_vlan & 0xff;
            rx_frame->preamble_start[24] = 0x90;
            rx_frame->preamble_start[25] = 0x01;
            rx_frame->preamble_start[26] = 0x6a;   /* j */
            rx_frame->preamble_start[27] = 0x73;   /* s */
            rx_frame->preamble_start[28] = 0x6f;   /* o */
            rx_frame->preamble_start[29] = 0x6e;   /* n */
            rx_frame->preamble_start[30] = 0x20;   /* 'space' */
            /* FIX: Magic numbers +4 for VLAN, START_OF_JSON_VLAN header, offset = payload, 4 for CRC */
            rx_frame->num_bytes = 4 + START_OF_JSON_VLAN + offset;
            TB_TRACE("num_bytes %d", rx_frame->num_bytes);
            memcpy(&rx_frame->preamble_start[START_OF_JSON_VLAN], global_json_string, rx_frame->num_bytes);
        } else {
            /* FIX: Magic numbers START_OF_JSON_UNTAGGED header, offset = payload, 4 for CRC */
            rx_frame->num_bytes = START_OF_JSON_UNTAGGED + offset + 4;
            memcpy(&rx_frame->preamble_start[START_OF_JSON_UNTAGGED], global_json_string, rx_frame->num_bytes);
        }
        for (i = 0; i < rx_frame->num_bytes; ++i) {
            uint16_t dword_idx = i / 4;
            uint8_t byte_shift = (3 - (i % 4)) << 3;    // 0->24, 1->16, 2->8, 3->0

            //   i   3-(i%4)   byte_shift
            // --------------------------
            //   0      3          24
            //   1      2          16
            //   2      1           8
            //   3      0           0
            //   4      3          24
            //   5      2          16
            //   6      1           8
            //   ⋮      ⋮           ⋮
            if (0 == (i % 4)) {
                rx_frame->data[dword_idx] = 0;
            }
            rx_frame->data[dword_idx] |= (rx_frame->preamble_start[i] << byte_shift);
        }

        rx_frame->tx_modifier = BRDG_MODIFIER_FLAG_APPLY_CRC;

        brdg_que_write(7, BRDG_MODIFIER_FLAG_APPLY_CRC, rx_frame);

        offset = 0;
        break;
    case APPEND:
    default:
        /* do nothing */
        break;
    }

    return 0;
}

static tb_rc json_fec_set(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key, bool fec_enabled)
{
    tb_rc rc = TB_RC_OK;

    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string,
            "{\"operation\": \"fec_set\", \"success\": true, \"results\": [], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    olt_fsm_fec_enable_set(ifc_key, fec_enabled, fec_enabled);

    return rc;
}

static tb_rc json_fec_get(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key)
{
    tb_rc rc = TB_RC_OK;
    bool fec_tx_enable = false;
    bool fec_rx_enable = false;

    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"fec_get\", \"success\": true, \"results\": ");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    rc = olt_fsm_fec_enable_get(ifc_key, &fec_tx_enable, &fec_rx_enable);

    if (fec_tx_enable == true) {
        sprintf(tmp_string, "{\"mode\": \"enabled\"}");
    } else {
        sprintf(tmp_string, "{\"mode\": \"disabled\"}");
    }
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, ", \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

static tb_rc json_tag_mode_set(tb_pkt_deprec_t * rx_frame, char * tag_mode)
{
    tb_rc rc = TB_RC_OK;

    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string,
            "{\"operation\": \"tag_mode_set\", \"success\": true, \"results\": [], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    if (strncmp(tag_mode, "SC", 3) == 0) {
        rc = hwsys_manufacturing_CTAG_CTAG_write(false);
    } else {
        rc = hwsys_manufacturing_CTAG_CTAG_write(true);
    }

    return rc;
}

static tb_rc json_tag_mode_get(tb_pkt_deprec_t * rx_frame)
{
    tb_rc rc = TB_RC_OK;

    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"tag_mode_get\", \"success\": true, \"results\": ");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);

    if (tbg.outer_tpid == 0x8100) {
        sprintf(tmp_string, "{\"tag_mode\": \"CC\"}");
    } else {
        sprintf(tmp_string, "{\"tag_mode\": \"SC\"}");
    }
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, ", \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

static tb_rc json_sla_set(tb_pkt_deprec_t * rx_frame, lsm_link_key_t * link_key,
                          lsm_link_sla_spec_t * sla_spec)
{
    tb_rc rc = lsm_link_sla_set(link_key, sla_spec);

    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string,
            "{\"operation\": \"sla_set\", \"success\": true, \"results\": [], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

static tb_rc json_sla_get(tb_pkt_deprec_t * rx_frame, lsm_link_key_t * link_key,
                          lsm_link_sla_spec_t * sla_spec)
{
    tb_rc rc = lsm_link_sla_get(link_key, sla_spec);

    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"sla_get\", \"success\": true, \"results\": [");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"cir\": \"%u\", \"eir\": \"%u\"}", (unsigned int)sla_spec->cir_Kbps,
            (unsigned int)sla_spec->eir_Kbps);
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

static tb_rc json_flows_add(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key,
                            sw_rec_key_t * sw_rec_key, port_vlan_op_cfg_t port_vlan_op_cfg)
{
    tb_rc rc = TB_RC_OK;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    rc = sw_associate_port(sw_rec_key, ifc_key, port_vlan_op_cfg);
    if (rc != TB_RC_OK) {
        TB_INFO("%s:%d Failed sw_associate.", __FUNCTION__, __LINE__);
    }

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    if ((rc == TB_RC_OK) || (rc == TB_RC_ALREADY)) {
        sprintf(tmp_string, "{\"operation\": \"flows_add\", \"success\": true, \"results\": [");
    } else {
        sprintf(tmp_string, "{\"operation\": \"flows_add\", \"success\": false, \"results\": [");
    }
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

static tb_rc json_flows_delete(tb_pkt_deprec_t * rx_frame, tb_ifc_key_t * ifc_key,
                              sw_rec_key_t * sw_rec_key)
{
    tb_rc rc = TB_RC_OK;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    rc = sw_dissociate_port(sw_rec_key, ifc_key);
    if (rc != TB_RC_OK) {
        tb_printf("%s:%d Failed sw_deassociate. (rc=%d)\n", __FUNCTION__, __LINE__, rc);
    }

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    if ((rc == TB_RC_OK) || (rc == TB_RC_ALREADY)) {
        sprintf(tmp_string, "{\"operation\": \"flows_delete\", \"success\": true, \"results\": [");
    } else {
        sprintf(tmp_string, "{\"operation\": \"flows_delete\", \"success\": false, \"results\": [");
    }
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

#define MAX_SWITCHING_RECORDS 20        /* for now... */
static tb_rc json_flows_get(tb_pkt_deprec_t * rx_frame)
{
    tb_rc rc = TB_RC_OK;
    int i, j = 0;
    int num_switching_records = 0;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    sw_rec_key_t switching_record[MAX_SWITCHING_RECORDS];
    tb_port_key_t ports_per_record[MAX_SWITCHING_RECORDS][MAX_REPORTABLE_PORTS_PER_SW_RECORD];
    tb_mac_address_str_t mac_str = "";

    memset(switching_record, 0, sizeof(sw_rec_key_t) * MAX_SWITCHING_RECORDS);
    memset(ports_per_record, 0,
           sizeof(tb_port_key_t) * MAX_SWITCHING_RECORDS * MAX_REPORTABLE_PORTS_PER_SW_RECORD);

    num_switching_records =
        sw_report_all_sw_rec_mgmt(MAX_SWITCHING_RECORDS, switching_record,
                                  MAX_REPORTABLE_PORTS_PER_SW_RECORD, ports_per_record);

    if (num_switching_records >= MAX_SWITCHING_RECORDS) {
        TB_ERROR("Out of bounds error, more swr than memory allocated");
    } else if (num_switching_records < 0) {
        TB_TRACE("I: (%s:%d)", __FUNCTION__, __LINE__);
        return (rc = TB_RC_INTERNAL_ERROR);
    }
    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    if (num_switching_records) {
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        if ((rc == TB_RC_OK) || (rc == TB_RC_ALREADY)) {
            sprintf(tmp_string, "{\"operation\": \"flows\", \"success\": true, \"results\": [");
        } else {
            sprintf(tmp_string, "{\"operation\": \"flows\", \"success\": false, \"results\": [");
        }
        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

        for (i = 0; i < num_switching_records; i++) {
            if (i >= 1) {
                memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                sprintf(tmp_string, ",");
                json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
            }
            for (j = 0; j < MAX_REPORTABLE_PORTS_PER_SW_RECORD; j++) {
                tb_port_type_t  type = ports_per_record[i][j].port_type;
                /* printf("MGMT_JSON[%d][%d]: port type %u\n", i, j, type); */
                if (type && (j >= 1)) {
                    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                    sprintf(tmp_string, ",");
                    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
                }

                switch (type) {
                    case tb_port_type_eth_dn: {
                        tb_ifc_key_t          *ifc_key = &ports_per_record[i][j].key.ifc;
                        lsm_link_key_t        link_key;
                        port_vlan_op_cfg_t    port_vlan_op_cfg;
                        port_vlan_op_cfg_t    *p_vlan_op_cfg;

                        /* ingress switch record */
                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        sprintf(tmp_string, "{\"ingress_switch_record\": {\"svid\": \"%05d\", \"cvid\": \"%05d\"},",
                                switching_record[i].outer_vid, switching_record[i].inner_vid);
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        /* ingress port */
                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        sprintf(tmp_string, "\"ingress_port\": {\"iinst\": \"%d\", \"itype\": \"eth\"},",
                                ifc_key->inst);
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        /* egress port */
                        rc = hal_find_link_key_by_llid(switching_record[i].default_dest, &link_key);
                        if (rc != TB_RC_OK) {
                            TB_ERROR("find link key failed");
                        }

                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        tb_mac_address_to_str(link_key.mac.u8, mac_str);
                        sprintf(tmp_string, "\"egress_port\": {\"iinst\": \"%d\", \"itype\": \"olt\", \"macid\": \"%s\"},",
                                link_key.ifc_inst, mac_str);
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        /* vlan operation */
                        memset(&port_vlan_op_cfg, 0, sizeof(port_vlan_op_cfg));

                        p_vlan_op_cfg = sw_find_port_vlan_op_cfg(&switching_record[i],
                                                                 &ports_per_record[i][0], /* single ports right now */
                                                                 &port_vlan_op_cfg);

                        if (p_vlan_op_cfg == NULL) {
                            TB_ERROR("p_vlan_op_cfg is NULL");
                        }

                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        if ((port_vlan_op_cfg[0].op_type != port_vlan_op_type_unspecified) &&
                            (port_vlan_op_cfg[0].op_type != port_vlan_op_type_none)) {
                            /* STAG */
                            sprintf(tmp_string, "\"operation\": ");
                            switch (port_vlan_op_cfg[0].op_type) {
                                case port_vlan_op_type_push:
                                    sprintf(tmp_string + 13, "{\"code\": \"push\", \"tpid\": \"88a8\", \"vid\": \"%d\"}",
                                            port_vlan_op_cfg[0].op_arg);
                                    break;
                                case port_vlan_op_type_pop:
                                    sprintf(tmp_string + 13, "{\"code\": \"pop\", \"tpid\": \"88a8\"}");
                                    break;
                                case port_vlan_op_type_none:
                                    sprintf(tmp_string + 13, "{\"code\": \"none\", \"tpid\": \"88a8\"}");
                                    break;
                                default:
                                case port_vlan_op_type_translate:
                                case port_vlan_op_type_count:
                                case port_vlan_op_type_unspecified:
                                    TB_TRACE("stag unspecified");
                                    break;
                            }
                        } else if ((port_vlan_op_cfg[1].op_type != port_vlan_op_type_unspecified) &&
                                   (port_vlan_op_cfg[0].op_type != port_vlan_op_type_none)) {
                            /* CTAG */
                            sprintf(tmp_string, "\"operation\": ");
                            switch (port_vlan_op_cfg[1].op_type) {
                                case port_vlan_op_type_push:
                                    sprintf(tmp_string + 13, "{\"code\": \"push\", \"tpid\": \"8100\", \"vid\": \"%d\"}",
                                            port_vlan_op_cfg[1].op_arg);
                                    break;
                                case port_vlan_op_type_pop:
                                    sprintf(tmp_string + 13, "{\"code\": \"pop\", \"tpid\": \"8100\"}");
                                    break;
                                case port_vlan_op_type_none:
                                    sprintf(tmp_string + 13, "{\"code\": \"none\", \"tpid\": \"8100\"}");
                                    break;
                                default:
                                case port_vlan_op_type_translate:
                                case port_vlan_op_type_count:
                                case port_vlan_op_type_unspecified:
                                    TB_TRACE("ctag unspecified");
                                    break;
                            }
                        }
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        sprintf(tmp_string, "}");
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        break;
                    }
                    case tb_port_type_llid_up: {
                        lsm_link_key_str_t  link_key_str;
                        lsm_link_key_t      *link_key = &ports_per_record[i][j].key.link;
                        tb_ifc_subinst_t      llid    = lsm_find_llid_by_link_key(link_key);
                        port_vlan_op_cfg_t    port_vlan_op_cfg;
                        port_vlan_op_cfg_t    *p_vlan_op_cfg;
                        lsm_link_key_llid_to_str(link_key, llid, link_key_str);

                        /* ingress switch record */
                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        sprintf(tmp_string, "{\"ingress_switch_record\": {\"svid\": \"%05d\", \"cvid\": \"%05d\"},",
                                switching_record[i].outer_vid, switching_record[i].inner_vid);
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);


                        /* ingress port */
                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        tb_mac_address_to_str(link_key->mac.u8, mac_str);
                        sprintf(tmp_string, "\"ingress_port\": {\"iinst\": \"%d\", \"itype\": \"olt\", \"macid\": \"%s\"},",
                                link_key->ifc_inst, mac_str);
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        /* egress port */
                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        sprintf(tmp_string, "\"egress_port\": {\"iinst\": \"0\", \"itype\": \"eth\"},");
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        /* vlan operation */
                        memset(&port_vlan_op_cfg, 0, sizeof(port_vlan_op_cfg));
                        p_vlan_op_cfg = sw_find_port_vlan_op_cfg(&switching_record[i],
                                                                 &ports_per_record[i][0], /* single ports right now */
                                                                 &port_vlan_op_cfg);

                        if (p_vlan_op_cfg == NULL) {
                            TB_ERROR("p_vlan_op_cfg is NULL");
                        }

                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        if (port_vlan_op_cfg[0].op_type != port_vlan_op_type_unspecified) {
                            /* STAG */
                            sprintf(tmp_string, "\"operation\": ");
                            switch (port_vlan_op_cfg[0].op_type) {
                                case port_vlan_op_type_push:
                                    sprintf(tmp_string + 13, "{\"code\": \"push\", \"tpid\": \"88a8\", \"vid\": \"%d\"}",
                                            port_vlan_op_cfg[0].op_arg);
                                    break;
                                case port_vlan_op_type_pop:
                                    sprintf(tmp_string + 13, "{\"code\": \"pop\", \"tpid\": \"88a8\"}");
                                    break;
                                case port_vlan_op_type_none:
                                    sprintf(tmp_string + 13, "{\"code\": \"none\", \"tpid\": \"88a8\"}");
                                    break;
                                default:
                                case port_vlan_op_type_translate:
                                case port_vlan_op_type_count:
                                case port_vlan_op_type_unspecified:
                                    break;
                            }
                        } else if (port_vlan_op_cfg[1].op_type != port_vlan_op_type_unspecified) {
                            /* CTAG */
                            sprintf(tmp_string, "\"operation\": ");
                            switch (port_vlan_op_cfg[1].op_type) {
                                case port_vlan_op_type_push:
                                    sprintf(tmp_string + 13, "{\"code\": \"push\", \"tpid\": \"8100\", \"vid\": \"%d\"}",
                                            port_vlan_op_cfg[1].op_arg);
                                    break;
                                case port_vlan_op_type_pop:
                                    sprintf(tmp_string + 13, "{\"code\": \"pop\", \"tpid\": \"8100\"}");
                                    break;
                                case port_vlan_op_type_none:
                                    sprintf(tmp_string + 13, "{\"code\": \"none\", \"tpid\": \"8100\"}");
                                    break;
                                default:
                                case port_vlan_op_type_translate:
                                case port_vlan_op_type_count:
                                case port_vlan_op_type_unspecified:
                                    break;
                            }
                        }
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

                        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
                        sprintf(tmp_string, "}");
                        json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);
                        break;
                    }
                    default:
                        rc = TB_RC_INTERNAL_ERROR;
                        break;
                } // switch
            }
        }
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        sprintf(tmp_string, "], \"error\": null}");
        json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    } else {
        memset(tmp_string, 0, SIZE_OF_TMP_STRING);
        sprintf(tmp_string, "{\"operation\": \"flows\", \"success\": true, \"results\": [], \"error\": null}");
        json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);
    }

    return rc;
}

static tb_rc json_mode_set(tb_pkt_deprec_t * rx_frame, mandata_pon_type_t PON)
{
    tb_rc rc = TB_RC_OK;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };
    unsigned int serial_number = 0;

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"mode_set\", \"success\": true, \"results\": [");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    sleep_ms(20);

    /* Only change if we not currently at the requested mode */
    if (tbg.PON != PON) {
        rc = hwsys_manufacturing_pon_write(PON);
        if (rc == 0) {
            rc = hwsys_manufacturing_pon_read(&tbg.PON);
            if (rc != 0) {
                tb_printf("E: PON read error (%s:%d)\n", __FILE__, __LINE__);
            }

            /* if the PON type changes, re-write the mac addresses */
            hwsys_manufacturing_serial_read(&serial_number);
            set_sernum_and_mac_address(serial_number);

            hw_reset(); /* RESET the BITSTREAM */
        }
    }
    return rc;
}

static tb_rc json_cli_cmd(tb_pkt_deprec_t * rx_frame)
{
    tb_rc rc = TB_RC_OK;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "{\"operation\": \"cli\", \"success\": true, \"results\": [");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "], \"error\": null}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);

    return rc;
}

typedef struct {
    uint32   image_length;
    uint32   crc32_expected;
    uint32   crc32_actual;
} image_header_t;

// [tibit@tibit-ubuntu-vm-pow] /opt/tbos.git $ cat /tmp/hello.txt
// hello, world!
// [tibit@tibit-ubuntu-vm-pow] /opt/tbos.git $ od -t x1 /tmp/hello.txt
// 0000000 68 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a
// [tibit@tibit-ubuntu-vm-pow] /opt/tbos.git $ crc32 /tmp/hello.txt
// b631dfc0
// [tibit@tibit-ubuntu-vm-pow] /opt/tbos.git $ wc -c /tmp/hello.txt
// 14 /tmp/hello.txt

static int process_copy(const uint8_t *msg_buf, UNUSED_ARG uint32 msg_len)
{
    const uint8_t *image_start           = (const uint8_t *)0x81000000;
    const uint8_t *image_length_packed   = msg_buf;
    const uint8_t *crc32_expected_packed = msg_buf + 4;
    uint32         crc32_expected        = tb_unpack_u32(crc32_expected_packed);
    uint32         image_length          = tb_unpack_u32(image_length_packed);
    uint32         crc32_actual          = crc32(image_start, image_length);

    TB_WARNING("[copy] image_length %u  crc32_expected 0x%08x   crc32_actual 0x%08x", image_length, crc32_expected, crc32_actual);
    if (crc32_expected == crc32_actual) {
        image_header_t *header = (image_header_t *)(image_start - sizeof(image_header_t));

        TB_WARNING("-> writing image header");
        header->image_length   = image_length;
        header->crc32_expected = crc32_expected;
        header->crc32_actual   = 0; // calculated & compared w/ expected value by U-Boot script

        tb_dbug_hexdump_one_line(TB_DBUG_LVL_WARNING, __FUNCTION__, __LINE__, header, 0, 32, "header+image: ", " ...");
    } else {
        TB_ERROR("crc32_expected 0x%08x != crc32_actual 0x%08x", crc32_expected, crc32_actual);
    }

    return 0;
}

static int process_dnld(const uint8_t *msg_buf, uint32 msg_len)
{
    const uint8_t *start_offset_packed    = msg_buf;
    const uint8_t *fragment_length_packed = msg_buf + 4;
    const uint8_t *fragment_start         = msg_buf + 8;
    uint32         start_offset           = tb_unpack_u32(start_offset_packed);
    uint32         fragment_length        = tb_unpack_u32(fragment_length_packed);
    uint8_t       *dest_buf               = (uint8_t *)0x81000000;

    TB_WARNING("[dnld] memcpy(%p, %p, %u)", dest_buf+start_offset, fragment_start, fragment_length);
    tb_dbug_hexdump_one_line(TB_DBUG_LVL_WARNING, __FUNCTION__, __LINE__, msg_buf, 0, msg_len, "msg_buf: ", NULL);
    tb_dbug_hexdump_one_line(TB_DBUG_LVL_WARNING, __FUNCTION__, __LINE__, fragment_start, 0, fragment_length, "fragment: ", NULL);
    memcpy(dest_buf+start_offset, fragment_start, fragment_length);

    return 0;
}

int json_send_response(char *type, char *buffer, uint16_t bufflen)
{
    tb_pkt_deprec_t *rx_frame = &fake_frame;
    char tmp_string[SIZE_OF_TMP_STRING] = { '\0' };

    memset(rx_frame, 0, sizeof(*rx_frame));

    memset(global_json_string, 0, SIZE_OF_JSON_STRING);
    json_str_append_and_out(global_json_string, tmp_string, RESET, rx_frame);

    // Add the header
    sprintf(tmp_string, "{\"operation\": \"%s\", \"success\": true, \"results\": {", type);
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    if (bufflen > SIZE_OF_JSON_STRING) {
        json_error(rx_frame, BRDG_RET_NOT_OK);
        return 0;
    }

    // Add the attribute values
    json_str_append_and_out(global_json_string, buffer, APPEND, rx_frame);

    // Add the trailer
    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}, ");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "\"error\": null");
    json_str_append_and_out(global_json_string, tmp_string, APPEND, rx_frame);

    memset(tmp_string, 0, SIZE_OF_TMP_STRING);
    sprintf(tmp_string, "}");
    json_str_append_and_out(global_json_string, tmp_string, APPEND_AND_FLUSH_CR, rx_frame);
    return 0;
}



static int process_json(tb_pkt_deprec_t * rx_frame)
{
    int r;
    int eof_expected = 0;
    char *js = NULL;
    size_t jslen = 0;
    char buf[TB_PKT_DEPREC_PAYLOAD_BYTES];
    jsmn_parser p;
    jsmntok_t *tok;
    size_t tokcount = 2;
    unsigned int json_length = 0;

    jsmn_init(&p);

    /* Allocate some tokens as a start */
    tok = malloc(sizeof(*tok) * tokcount);
    if (tok == NULL) {
        printf("malloc(): errno=%d\n", errno);
        return 3;
    }

    memset(buf, 0, sizeof(buf));
#ifdef USE_VLAN_HEADER_INCOMING
    json_length = (rx_frame->num_bytes - START_OF_JSON_VLAN - FRAME_CRC_SIZE);
    strncpy(buf, (const char *)&rx_frame->preamble_start[START_OF_JSON_VLAN], json_length);
#else
    json_length = (rx_frame->num_bytes - START_OF_JSON_UNTAGGED - FRAME_CRC_SIZE);
    strncpy(buf, (const char *)&rx_frame->preamble_start[START_OF_JSON_UNTAGGED], json_length);
#endif
    r = strlen(buf);
    /* tb_printf("STRLEN:[%d] %s\n", r, buf); */

    if (r <= 0) {
        if (tok != NULL) { free(tok); }
        if (js  != NULL) { free(js);  }
    if (r < 0) {
        printf("fread(): %d, errno=%d\n", r, errno);
        return 1;
    }
    if (r == 0) {
        if (eof_expected != 0) {
            return 0;
        } else {
            printf("fread(): unexpected EOF\n");
            return 2;
        }
    }
    }

    js = realloc(js, jslen + r + 1);
    if (js == NULL) {
        printf("realloc(): errno=%d\n", errno);
        if (tok != NULL) { free(tok); }
        return 3;
    }
    strncpy(js + jslen, buf, r);
    jslen = jslen + r;

 again:
    r = jsmn_parse(&p, js, jslen, tok, tokcount);
    if (r < 0) {
        if (r == JSMN_ERROR_NOMEM) {
            tokcount = tokcount * 2;
            tok = realloc(tok, sizeof(*tok) * tokcount);
            if (tok == NULL) {
                printf("realloc(): errno=%d\n", errno);
                if (js != NULL) { free(js); }
                return 3;
            }
            goto again;
        }
    } else {
        /* This is the starting point for processing a JSON frame */
        /* tb_printf("START_JSON_PARSE\n"); */
        dump(js, tok, p.toknext, 0);
        eof_expected = 1;
    }

    if (tok != NULL) { free(tok); }
    if (js  != NULL) { free(js);  }

    if (strlen(operation) != 0) {
        if (strcmp(operation, "version") == 0) {
            json_version(rx_frame);
        } else if (strcmp(operation, "interfaces") == 0) {
            json_interfaces(rx_frame);
        } else if (strcmp(operation, "links") == 0) {
            json_links(rx_frame, itype, strtoul(iinst, NULL, 10));
        } else if (strcmp(operation, "register_read") == 0) {
            if (strlen(location) == 0) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                json_register_read(rx_frame, strtoul(location, NULL, 16));
            }
        } else if (strcmp(operation, "register_write") == 0) {
            if (strlen(location) == 0) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                json_register_write(rx_frame, strtoul(location, NULL, 16),
                                    strtoul(value, NULL, 16));
            }
        } else if (strcmp(operation, "stats") == 0) {
            if ((strlen(itype) == 0) || (strlen(iinst) == 0) || (strlen(mac) == 0)) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                uint16_t lidx = 0;
                /* tb_ifc_key_t    ifc_key = { .type = TB_IFC_TYPE_OLT, */
                /*                             .inst = strtoul(iinst,NULL,10) }; */
                lsm_link_key_t link_key = {.ifc_type = TB_IFC_TYPE_OLT,
                    .ifc_inst = strtoul(iinst, NULL, 10)
                };
                /* hal_ifc_hw_cfg *hw_cfg; */

                if (0 == strcmp("olt", itype)) {
                    /* ifc_key.type  = TB_IFC_TYPE_OLT; */
                    link_key.ifc_type = TB_IFC_TYPE_OLT;
                    if (gpon_device_p()) {
                        link_key.ifc_type = TB_IFC_TYPE_ALLOC_ID;
                    }
                } else if (0 == strcmp("onu", itype)) {
                    /* ifc_key.type  = TB_IFC_TYPE_ONU; */
                    link_key.ifc_type = TB_IFC_TYPE_ONU;
                }
                /* hw_cfg = hal_get_hw_cfg_by_key(ifc_key); */


                memcpy(link_key.mac.u8, mac_addr.u8, sizeof(link_key.mac));
                if (TB_RC_OK != hal_find_lidx_by_link_key(&link_key, &lidx)) {
                    TB_ERROR("link not found");
                    // Nathan: json_error(rx_frame, BRDG_RET_INPUT_INVALID); ??
                }
                TB_TRACE("LIDX: %d", lidx);

                /* Warning: Should derive the mac block from hw_cfg */
                json_stats(rx_frame, lidx, MB1);
            }
        } else if (strcmp(operation, "sla_set") == 0) {
            if ((strlen(itype) == 0) || (strlen(iinst) == 0) || (strlen(mac) == 0)
                || (strlen(cir) == 0) || (strlen(eir) == 0)) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                if (0 != strcmp("olt", itype)) {
                    json_error(rx_frame, BRDG_RET_INPUT_INVALID);
                } else {
                    lsm_link_sla_spec_t sla_spec = {.cir_Kbps = strtoul(cir, NULL, 10),
                        .eir_Kbps = strtoul(eir, NULL, 10)
                    };
                    lsm_link_key_t link_key = {.ifc_type = TB_IFC_TYPE_OLT,
                        .ifc_inst = strtoul(iinst, NULL, 10)
                    };

                    memcpy(link_key.mac.u8, mac_addr.u8, sizeof(link_key.mac));

                    tb_rc rc = json_sla_set(rx_frame, &link_key, &sla_spec);

                    TB_TRACE("json_sla_set returned %d (%s)", rc, tb_strerror(rc));
                }
            }
        } else if (strcmp(operation, "sla_get") == 0) {
            if ((strlen(itype) == 0) || (strlen(iinst) == 0) || (strlen(mac) == 0)) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                if (0 != strcmp("olt", itype)) {
                    json_error(rx_frame, BRDG_RET_INPUT_INVALID);
                } else {
                    tb_mac_address_str_t mac_str;
                    lsm_link_sla_spec_t sla_spec;
                    lsm_link_key_t link_key = {.ifc_type = TB_IFC_TYPE_OLT,
                        .ifc_inst = strtoul(iinst, NULL, 10)
                    };

                    memcpy(link_key.mac.u8, mac_addr.u8, sizeof(link_key.mac));

                    tb_mac_address_to_str(link_key.mac.u8, mac_str);

                    tb_rc rc = json_sla_get(rx_frame, &link_key, &sla_spec);

                    TB_TRACE("json_sla_get returned %d (%s)", rc, tb_strerror(rc));
                }
            }
        } else if (strcmp(operation, "fec_set") == 0) {
            if ((strlen(mode) == 0)) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                tb_rc rc = TB_RC_OK;
                tb_ifc_key_t ifc_key = {.type = TB_IFC_TYPE_OLT,
                                        .inst = 0,
                                        .subinst = TB_IFC_SUBINST_NONE
                };

                if (strncmp(mode, "enabled", 7) == 0) {
                    rc = json_fec_set(rx_frame, &ifc_key, true);
                } else {
                    rc = json_fec_set(rx_frame, &ifc_key, false);
                }

                TB_TRACE("json_fec_set returned %d (%s)", rc, tb_strerror(rc));
            }
        } else if (strcmp(operation, "fec_get") == 0) {
            tb_ifc_key_t ifc_key = {.type = TB_IFC_TYPE_OLT,
                                    .inst = 0,
                                    .subinst = TB_IFC_SUBINST_NONE
            };

            tb_rc rc = json_fec_get(rx_frame, &ifc_key);

            TB_TRACE("json_fec_get returned %d (%s)", rc, tb_strerror(rc));

        } else if (strcmp(operation, "tag_mode_set") == 0) {
            if ((strlen(tag_mode) == 0)) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                tb_rc rc = TB_RC_OK;

                rc = json_tag_mode_set(rx_frame, tag_mode);


                TB_TRACE("json_tag_mode_set returned %d (%s)", rc, tb_strerror(rc));
            }
        } else if (strcmp(operation, "tag_mode_get") == 0) {

            tb_rc rc = TB_RC_OK;

            rc = json_tag_mode_get(rx_frame);

            TB_TRACE("json_tag_mode_get returned %d (%s)", rc, tb_strerror(rc));

        } else if (strcmp(operation, "flows_add") == 0) {
            if ((strlen(itype) == 0) || (strlen(iinst) == 0) || (strlen(mac) == 0)
                || (strlen(svid) == 0) || (strlen(cvid) == 0)
                || (strlen(code) == 0)) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                sw_rec_key_t sw_rec_key = { .outer_vid = strtoul(svid, NULL, 10),
                                            .inner_vid = strtoul(cvid, NULL, 10)
                };
                tb_ifc_key_t ingress_ifc_key = {.type = TB_IFC_TYPE_UNKNOWN,
                                                .inst = strtoul(iinst, NULL, 10),
                                                .subinst = TB_IFC_SUBINST_NONE
                };
                lsm_link_key_t link_key = {.ifc_type = TB_IFC_TYPE_OLT,
                                           .ifc_inst = strtoul(iinst, NULL, 10)
                };
                port_vlan_op_cfg_t port_vlan_op_cfg = {
                    { port_vlan_op_type_unspecified, 0 },
                    { port_vlan_op_type_unspecified, 0 }
                };

                if (strncmp(tpid, "88a8", 5) == 0) {
                    if (strncmp(code, "pop", 4) == 0) {
                        port_vlan_op_cfg[0].op_type = port_vlan_op_type_pop;
                        TB_TRACE("setting stag pop");

                    } else if (strncmp(code, "push", 4) == 0) {
                        port_vlan_op_cfg[0].op_type = port_vlan_op_type_push;
                        port_vlan_op_cfg[0].op_arg = strtoul(vid, NULL, 10);
                        TB_TRACE("setting stag push");
                    }
                } else if (strncmp(tpid, "8100", 5) == 0) {
                    if (strncmp(code, "pop", 4) == 0) {
                        port_vlan_op_cfg[1].op_type = port_vlan_op_type_pop;
                        TB_TRACE("settting ctag pop");

                    } else if (strncmp(code, "push", 4) == 0) {
                        port_vlan_op_cfg[1].op_type = port_vlan_op_type_push;
                        port_vlan_op_cfg[1].op_arg = strtoul(vid, NULL, 10);
                        TB_TRACE("setting ctag push");
                    }
                }

                tb_str_to_buf(link_key.mac.u8, mac, sizeof(mac_addr));

                if (strncmp(itype,"olt", 4) == 0) {
                    ingress_ifc_key.type = TB_IFC_TYPE_OLT;
                    /* If ingress type is OLT, then set the subinst to LLID */
                    ingress_ifc_key.subinst = lsm_find_llid_by_link_key(&link_key);
                    if (gpon_device_p()) {
                        ingress_ifc_key.subinst += (0x1000 + BRDG_XGEM_ALLOC_ID_LIDX_THRESHOLD);
                    }

                } else if (strncmp(itype,"eth", 4) == 0) {
                    ingress_ifc_key.type = TB_IFC_TYPE_ETHERNET;
                    if (gpon_device_p()) {
                        link_key.ifc_type = TB_IFC_TYPE_ALLOC_ID;
                    }
                    /* If ingress type is Ethernet, set the default dest to the LLID */
                    sw_rec_key.default_dest = lsm_find_llid_by_link_key(&link_key);
                    if (sw_rec_key.default_dest == TB_IFC_SUBINST_NONE) {
                        if (gpon_device_p()) {
                            sw_rec_key.default_dest = 0x10000 | 0x10bc; // FIXME temporary hard-coded pseudo-broadcast xgem id
                        } else {
                            sw_rec_key.default_dest = 0x10000 | 0x7ffe; // FIXME not sure if we should assume EPON or fail in the EPON case
                        }
                    }
                } else {
                    tb_printf("UNKNOWN IFC TYPE\n");
                }

                tb_rc rc = json_flows_add(rx_frame, &ingress_ifc_key, &sw_rec_key,
                                          port_vlan_op_cfg);

                TB_TRACE("json_flows_add returned %d (%s)", rc, tb_strerror(rc));
            }
        } else if (strcmp(operation, "flows_delete") == 0) {
            if ((strlen(itype) == 0) || (strlen(iinst) == 0) || (strlen(mac) == 0)
                || (strlen(svid) == 0) || (strlen(cvid) == 0)) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                sw_rec_key_t sw_rec_key = {.outer_vid = strtoul(svid, NULL, 10),
                                           .inner_vid = strtoul(cvid, NULL, 10)
                };
                tb_ifc_key_t ingress_ifc_key = {.type = TB_IFC_TYPE_UNKNOWN,
                                                .inst = strtoul(iinst, NULL, 10),
                                                .subinst = TB_IFC_SUBINST_NONE
                };
                lsm_link_key_t link_key = {.ifc_type = TB_IFC_TYPE_OLT,
                                           .ifc_inst = strtoul(iinst, NULL, 10)
                };
                tb_str_to_buf(link_key.mac.u8, mac, sizeof(mac_addr));


                if (strncmp(itype,"olt", 4) == 0) {
                    ingress_ifc_key.type = TB_IFC_TYPE_OLT;
                    /* If ingress type is OLT, then set the subinst to LLID */
                    ingress_ifc_key.subinst = lsm_find_llid_by_link_key(&link_key);
                    /*  if (gpon_device_p()) { */
                    /*     ingress_ifc_key.subinst += (0x1000 + BRDG_XGEM_ALLOC_ID_LIDX_THRESHOLD); */
                    /* } */

                } else if (strncmp(itype,"eth", 4) == 0) {
                    ingress_ifc_key.type = TB_IFC_TYPE_ETHERNET;
                    if (gpon_device_p()) {
                        link_key.ifc_type = TB_IFC_TYPE_ALLOC_ID;
                    }
                    /* If ingress type is Ethernet, set the default dest to the LLID */
                    sw_rec_key.default_dest = lsm_find_llid_by_link_key(&link_key);

                } else {
                    tb_printf("UNKNOWN IFC TYPE\n");
                }

                tb_rc rc = json_flows_delete(rx_frame, &ingress_ifc_key, &sw_rec_key);

                TB_TRACE("json_flows_delete returned %d (%s)", rc, tb_strerror(rc));
            }
        } else if (strcmp(operation, "flows") == 0) {
            tb_rc rc = json_flows_get(rx_frame);
            TB_TRACE("json_flows_get returned %d (%s)", rc, tb_strerror(rc));
        } else if (strcmp(operation, "mode_set") == 0) {
            if (strlen(mode) == 0) {
                json_error(rx_frame, BRDG_RET_INPUT_INVALID);
            } else {
                tb_rc rc = TB_RC_OK;

                if (strncmp(mode, "GPON", 5) == 0) {
                    if (olt_device_p()) {
                        rc = json_mode_set(rx_frame, MANDATA_PON_TYPE_10G_GPON_OLT);
                    } else {
                        rc = json_mode_set(rx_frame, MANDATA_PON_TYPE_10G_GPON_ONU);
                    }
                } else if (strncmp(mode, "EPON", 5) == 0) {
                    if (olt_device_p()) {
                        rc = json_mode_set(rx_frame, MANDATA_PON_TYPE_10G_EPON_OLT);
                    } else {
                        rc = json_mode_set(rx_frame, MANDATA_PON_TYPE_10G_EPON_ONU);
                    }
                } else {
                    TB_WARNING("Unrecognized mode %s", mode);
                }
                TB_TRACE("json_mode_set returned %d (%s)", rc, tb_strerror(rc));
            }
        } else if (strcmp(operation, "cli") == 0) {
            run_command(cmd, 0);
            json_cli_cmd(rx_frame);
        } else if (strcmp(operation, "getRequest") == 0) {
            mac_address deviceMac;
            tb_str_to_buf(deviceMac.u8, mac, sizeof(mac_addr));
            oam_snd_get_request(&deviceMac);
        } else {
            TB_WARNING("unknown operation \"%s\" -- ignoring", operation);
        }

        memset(operation, 0, SIZE_OF_OPERATION);
        memset(itype, 0, SIZE_OF_ITYPE);
        memset(iinst, 0, SIZE_OF_IINST);
        memset(svid, 0, SVID_STR_LEN);
        memset(cvid, 0, CVID_STR_LEN);
        memset(cmd, 0, SIZE_OF_CMD);
    }

    return 0;

}                               /* process_json() */

/* JSON input mode
 *
 * Syntax:
 *  json
 */
static int do_json(UNUSED_ARG cmd_tbl_t * cmdtp, UNUSED_ARG int flag, UNUSED_ARG int argc, char *const argv[])
{
    tb_pkt_deprec_t *p_fake_frame;
    tb_dbug_lvl_t    original_dbug_lvl;
    p_fake_frame = &fake_frame;

    memset(p_fake_frame, 0, sizeof(tb_pkt_deprec_t));
    /* No spaces allowed during json input on the command line or else
     * the json is considered as more then one argument (argc > 2) */
    p_fake_frame->num_bytes = 8 /* preamble */
        + 6                     /* dest  */
        + 6                     /* source */
        + 2                     /* type */
        + 4                     /* 'json' */
        + 1                     /* space  */
        + strlen(argv[1])
        + 4;                    /* CRC */
    memcpy(&p_fake_frame->preamble_start[START_OF_JSON_UNTAGGED], argv[1], strlen(argv[1]));
    command_line_json = true;

    /* silence debug while we process a command */
    original_dbug_lvl = tb_dbug_lvl;
    if ((tb_dbug_lvl == TB_DBUG_LVL_ERROR) || (tb_dbug_lvl == TB_DBUG_LVL_WARNING)) {
        tb_dbug_lvl = TB_DBUG_LVL_SILENT;
    }

    process_json(p_fake_frame);
    tb_dbug_lvl = original_dbug_lvl;
    return 0;
}                               /* do_json */

/**************************************************/
U_BOOT_CMD(json, 2, 0, do_json, "enter json mode", "\r\n");
