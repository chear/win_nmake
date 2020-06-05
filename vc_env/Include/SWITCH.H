/*
** $Id: SWITCH.H 1.3 2004/10/20 13:01:56 mrchung Exp $
*/
/****************************************************************************/
/*
 * Copyright (C) 1994-1997 ZyXEL Communications, Inc.
 * All Rights Reserved.
 *
 * ZyXEL Confidential; Need to Know only.
 * Protected as an unpublished work.
 *
 * The computer program listings, specifications and documentation
 * herein are the property of ZyXEL Communications, Inc. and
 * shall not be reproduced, copied, disclosed, or used in whole or
 * in part for any reason without the prior express written permission of
 * ZyXEL Communications, Inc.
 */
/****************************************************************************/
/*
** $Log: SWITCH.H $
** Revision 1.3  2004/10/20 13:01:56  mrchung
** Revision 1.2  2004/10/01 12:28:29  mrchung
** 
** For new NAT , add the following definition.
** #define NAT_SESSION_TABLE_SIZE
** #define NAT_HASH_TABLE_SIZE
** #define NAT_HASH_TABLE_MASK
** Revision 1.1  2004/09/30 08:01:21  mrchung
** Initial revision
** Revision 1.129  2004/04/13 08:17:48  rweng
** add ZYXEL_P662HW_6x
** Revision 1.128  2004/04/08 01:07:40  bchung
** Update for P652HW.
** Revision 1.127  2004/03/31 06:13:19  bchung
** Add UPNP_RULE_PER_SET definition.
** Revision 1.126  2004/03/11 01:50:23  bchung
** Add FW_ACL_BUFFER_SIZE definition.
** Revision 1.125  2004/02/27 05:48:14  bchung
** Add content filter protection to avoid exceed ROM file usage.
** Revision 1.124  2004/02/26 01:59:12  cjalee
** Add P660H-61
** Revision 1.123  2004/02/25 01:07:14  yfchen
** Add ZYXEL_P660M_67
** Revision 1.122  2004/02/17 13:08:42  bchung
** Add some definition for new NAT.
** Revision 1.121  2004/02/10 07:03:09  bchung
** Add XAUTH complier flag.
** Revision 1.120  2004/02/06 02:06:30  cjalee
** Add to support P660HW_63
** Revision 1.119  2004/02/05 06:28:31  bchung
** Update SNMP object ID for ZYXEL_P650H_37,
**  ZYXEL_P650HW_31, and ZYXEL_P650HW_33
** Revision 1.118  2004/01/15 06:42:06  bchung
** Support WLAN filter and extend rom file to 48K for P660W6x.
** Revision 1.117  2004/01/14 03:47:42  cjalee
** remove VPN feature for P660HW-61
** Revision 1.116  2004/01/13 11:23:29  ccshen
** turn on WLAN_FILTER in p660hw
** Revision 1.115  2004/01/06 03:34:15  bchung
** 1. Add SNMP object ID for P660 series.
** 2. Add ZYXEL_P660R_61.
** Revision 1.114  2003/12/30 06:57:27  cjalee
** Romfile size = 48 for P660HW-61
** Revision 1.113  2003/12/24 07:43:25  cjalee
** change p660hw-61 OBM version for Large Romfile
** Revision 1.112  2003/12/18 10:09:31  dsu
** Add vc hunt support for AR7 platform.
** Revision 1.111  2003/12/17 10:32:40  cjalee
** Add LARGE_ROMFILE for P660hw-61 (telefonica version)
** Revision 1.110  2003/12/16 07:30:31  Administrator
** Update for ZYXEL_P660W_61.
** Revision 1.109  2003/12/11 09:47:07  ccshen
** Add WEP_256BIT flag in p660hw
** Revision 1.108  2003/12/05 10:43:13  khung
** modify for add ILMI auto config function
** Revision 1.107  2003/12/03 03:01:54  cjalee
** for p660HW-61 projedct:
** 1. modify MULTI_LANGUAGE for only support OBM version
** 2. add embedded help
** Revision 1.106  2003/12/01 07:47:42  ccshen
** Add 802.1x support for p660hw61 platform
** Revision 1.105  2003/11/28 12:04:17  cjalee
** Remove BW_MGNT for p660hw-61
** Revision 1.104  2003/11/18 08:12:44  bchung
** Add IEEE802_1X_SMT for WLAN common API.
** Revision 1.103  2003/11/18 03:10:48  cjalee
** Add p660hw_61 for telefonica
** Revision 1.102  2003/11/11 03:48:26  dkuo
** Remove half bridge for P650R31 and r33.
** Revision 1.101  2003/11/11 03:30:51  bchung
** Add for P660W_61
** Revision 1.100  2003/11/10 05:13:51  cjalee
** modify p660hw-61 traffic redirect
** Revision 1.99  2003/11/09 09:34:27  cjalee
** add wlan support
** Revision 1.98  2003/11/07 08:17:08  cyeh
** Invoke ELCP by defining V5_PORT_CTRL and V5_BCC. 
** Revision 1.97  2003/11/06 03:31:27  cjalee
** add ZX1600 in P660HW_61
** Revision 1.96  2003/11/05 02:03:04  rweng
** add FTP_BUFFER_SIZE in P652HW
** Revision 1.95  2003/11/04 14:11:42  kycheng
** for p654ra-a1 projedct:
** VOIP_INTERRUPT_MODE->VP_INTERRUPT_MODE
** VOIP_POLLING_MODE->VP_POLLING_MODE
** Revision 1.94  2003/10/29 08:48:53  dkuo
** Revision 1.93  2003/10/28 09:23:34  cjalee
** Revision 1.92  2003/10/13 06:08:12  dkuo
** Define FTP_BUFFER_SIZE for P650HW_31 and P650R
** Revision 1.91  2003/10/13 05:46:52  dkuo
** add "WEB_OLD_WAN_BACKUP" for P650HW and P650R
** Revision 1.90  2003/09/29 10:41:15  dkuo
** Support 1)Content filter               2)VC auto-hunt
**         3)SIP pass-through             4)Static DHCP by MAC
** for P650HW-31/33/37
** Revision 1.89  2003/09/18 17:43:58  mrchung
** 1. Modify ZYXEL_TC3160.
** 2. Add ZYXEL_P645R_Tx and ZYXEL_P623R_Tx
** Revision 1.88  2003/09/15 15:29:15  kycheng
** Add HAL_API support
** Revision 1.87  2003/08/05 11:31:04  dkuo
** Enable Mail Client for P650HW31
** Revision 1.86  2003/08/04 07:59:17  ohsieh
** Update for P652HW
** Revision 1.85  2003/07/18 08:11:24  dkuo
** Support VPN and Firewall for P650HW31
** Revision 1.84  2003/07/09 02:34:40  bchung
** Support ZD1201 wireless card for P650HW31
** Revision 1.83  2003/06/30 10:04:03  bchung
** Add AES encryption for P652R
** Revision 1.82  2003/06/25 12:46:01  dkuo
** Add multi-lingual to P650HW-31 & P650H-31
** Add BW_MGNT to P650H-31
** Revision 1.81  2003/06/16 03:04:23  ohsieh
** Revision 1.80  2003/06/06 07:05:33  ohsieh
** Revision 1.79  2003/06/03 09:16:00  ohsieh
** Update P652HW
** Revision 1.78  2003/05/30 08:46:13  bchung
** Add Bandwith Managemnet for P650HW
** Revision 1.77  2003/04/15 06:55:38  tnli
** add SYS_ETNA_ARM9
** Revision 1.76  2003/04/14 03:38:55  mrchung
** Add ZYXEL_TC3160
** Revision 1.75  2003/04/08 05:27:53  ohsieh
** Add P652HW
** Revision 1.74  2003/04/07 07:42:43  chchien
** add support for BEFDSR41W
** Revision 1.73  2003/04/04 02:39:22  bchung
** Support higher LBN task for P652
** Revision 1.72  2003/04/01 05:49:28  sandyliu
** Remove some constants used for UPnP 
** Revision 1.71  2003/03/21 02:19:19  bchung
** Support 802.1x and WEB login user name for P650HW-31
** Revision 1.70  2003/03/19 03:57:29  chchien
** Add constant  NAT_SERVER_RULE_PER_SET , UPNP_RULE_PER_SET
** Revision 1.69  2003/03/12 14:11:24  BChung
** Add NetBIOS passthrough for P652R-11
** Revision 1.68  2003/02/27 06:33:34  BChung
** Add P650H_37.
** Revision 1.67  2003/02/14 09:46:07  llo
** add LOGIN_DEFAULT_USER_NAME definition for default login user name
** Revision 1.66  2003/02/13 07:36:14  rweng
** modify in P650HW-11/13
** Revision 1.65  2003/02/11 14:39:04  wcliang
** modify p202h setting
** Revision 1.64  2003/02/11 06:09:36  BChung
** Support generic filter for wireless channel for P650HW31
** Revision 1.63  2003/01/21 06:18:57  wcliang
** add firewall
** Revision 1.62  2003/01/13 08:29:43  slchiang
** Add VLAN_TAGGING_BRIDGING for P650M.
** Revision 1.61  2003/01/13 05:59:50  BChung
** Modify for P652R feature.
** Revision 1.60  2003/01/06 06:07:23  wcliang
** modify p202 SYSOBJID
** Revision 1.59  2003/01/06 01:20:32  wcliang
** modify P202H config
** Revision 1.58  2002/12/31 11:47:32  slchiang
** Add ZD2001 flag for P650M.
** Revision 1.57  2002/12/31 11:01:52  slchiang
** Add "watchdog for DSP" in P650M.
** Revision 1.56  2002/12/30 07:47:26  BChung
** Modify Object Identifier for P650HW31/33.
** Revision 1.55  2002/12/24 03:10:06  dsu
** Differentiate ZD2001 from TX39.
** Revision 1.54  2002/12/04 07:16:46  bchung
** Add P650HW31.
** Revision 1.53  2002/11/18 03:12:49  slchiang
** add half bridge for P650R31 and r33.
** Revision 1.52  2002/11/05 11:43:57  slchiang
** Add P650R33 model.
** Revision 1.51  2002/11/04 13:09:58  slchiang
** Add WATCHDOG_FOR_DSP for DSP hang up problem.
** Revision 1.50  2002/11/01 08:28:55  cwchen
** Change the SNMP SYSOBJID for P650R and mark ADSL_MIB
** Revision 1.49  2002/10/29 08:23:04  slchiang
** Remove INTERNAL_CLK_UART for P650R31.
** Revision 1.48  2002/10/24 06:16:07  dsu
** Modify P650R_31 support
** Revision 1.47  2002/09/18 06:48:02  cwchen
** Update this file for P65x products
** Revision 1.42  2002/04/09 07:17:12  cwchen
** Add P650R series ( R11/R13/R17/R45), and modify XDSL_CHIP setting
** Revision 1.41  2002/03/18 04:50:04  dyjiang
** Revision 1.40  2002/01/11 10:47:31  cchang
** ADD Zebra OSPF Support
** Revision 1.38  2001/12/27 13:21:40  cchang
** Add MAC/IP Address Validation
** Revision 1.37  2001/11/08 05:50:42  Mrchung
** Add DHCP conditional compiler flag in ZYXEL_P654
** Revision 1.36  2001/11/07 04:02:37  rweng
** add ZYXEL_P650R_11
** Revision 1.35  2001/10/30 09:27:57  dyjiang
** Add p794rb case.
** Revision 1.34  2001/10/23 12:07:51  slchiang
** Add the P790 case.
** Revision 1.33  2001/10/18 06:28:40  chchien
** add support for P654
** Revision 1.32  2001/09/07 11:11:08  yetseng
** Revision 1.31  2001/09/07 05:32:57  slchiang
** modify for P782.
** Revision 1.30  2001/08/30 01:44:43  slchiang
** add CONN_MGNT_TASK_PRIORITY in P724.
** Revision 1.29  2001/07/25 08:03:27  hchou
** disable (comment out) ZYCFG_CLNT in NETGEAR_P647W model
** Revision 1.28  2001/07/25 07:11:35  rweng
** add model P647
** Revision 1.27  2001/07/25 06:23:40  cchiang
** change p650w to netgear p647w
** Revision 1.26  2001/07/05 06:37:21  slchiang
** Add the complier flags for p724.
** Revision 1.25  2001/06/18 06:45:12  slchiang
** remove RCV_IP_MULTICAST_ONLY on P724.
** Revision 1.24  2001/06/14 10:26:59  cchiang
** Add model p650w
** Revision 1.23  2001/05/23 03:35:10  slchiang
** delete PPPOE in P724v.
** Revision 1.22  2001/05/21 01:33:38  slchiang
** add P724 model.
** Revision 1.21  2001/05/14 01:10:14  cchiang
** Revision 1.20  2001/02/01 06:01:52  cchiang
** Merge from zynos.250
** Revision 1.34  2000/12/08 08:59:43  rweng
** change ZYXEL_P642OFR define flag
** Revision 1.33  2000/11/24 02:51:45  sku
** Add HTTPD flag
** Revision 1.32  2000/11/17 05:46:13  wcliang
** add VERSION_REAL
** Revision 1.31  2000/11/09 07:23:13  rweng
** add ZYXEL_P642SPR for sprint casino
** Revision 1.30  2000/09/27 03:16:13  rweng
** for p643 add QUICK_BRIDGE, CALL_SCH
** Revision 1.29  2000/09/08 07:47:40  ghuang
** support P782
** Revision 1.28  2000/09/07 01:02:30  ghuang
** P742 support QUICK_BRIDGE for bridge mode enhance
** Revision 1.27  2000/09/02 08:15:08  rweng
** add model p643
** Revision 1.26  2000/08/09 09:28:20  cchiang
** Add p788B4 entry
** Revision 1.25  2000/07/20 01:57:49  GHUANG
** support "DIRTY_BRIDGE" for P742
** Revision 1.24  2000/06/30 09:07:28  GHUANG
** change P742 network queue size
** Revision 1.23  2000/06/02 04:54:16  ycsu
** change network process count for P310 to all
** Revision 1.22  2000/05/17 01:46:14  CJYU
** Add in ZYXEL_POEM.
** Revision 1.19  2000/11/28 06:07:07  dlai
** dlai for p1600
** Revision 1.18  2000/11/28 00:54:05  dlai
** dlai for 1600
** Revision 1.17  2000/11/08 07:16:38  yjyeh
** Revision 1.16  2000/10/19 07:31:21  hchang
** re-check in for server crash
** Revision 1.16  2000/10/06 11:07:29  hchang
** add DHCP relay compile flag
** Revision 1.15  2000/09/05 09:22:42  hchang
** add SMTP_CLNT, P310_ST, P310_FR compile flag support
** Revision 1.13  2000/06/12 09:50:47  hchang
** add zyxp_p314
** Revision 1.12  2000/06/09 07:01:29  dyen
** Revision 1.11  2000/06/07 06:33:54  hchang
** remove adjusttime support for p314
** Revision 1.10  2000/06/07 04:16:14  hchang
** Merge performance tunnig from Bill
** Revision 1.9  2000/05/26 10:47:02  hchang
** modify p314 feature set
** Revision 1.8  2000/05/23 03:50:58  hchang
** add model_316 support
** Revision 1.7  2000/05/22 08:02:18  hchang
** remove cli compile option
** Revision 1.6  2000/05/22 05:13:30  hchang
** add p314 support
** Revision 1.5  2000/05/19 11:00:04  hchang
** merge from 2.50
** Revision 1.21  2000/05/08 07:33:55  ycsu
** add CALL_SCH in P202
** Revision 1.20  2000/05/08 02:28:10  rlu
** modify P642(OBM)
** Revision 1.19  2000/05/03 01:17:48  cchen
** merge error corrected
** Revision 1.18  2000/05/02 23:08:07  cchen
** for P742 tmp
** Revision 1.17  2000/04/07 09:15:16  YuMJ
** P201 support SNMPD and RADIUS=2
** Revision 1.16  2000/03/29 06:35:26  RLO
** for P641FM. add FTPSERV.
** Revision 1.15  2000/03/27 05:02:52  RLO
** for P642 OBM router
** Revision 1.14  2000/03/06 08:21:58  SLCHIANG
** define MPOA for a690v
** Revision 1.13  2000/02/15 07:28:19  dlai
** dlai for p641
** Revision 1.12  2000/02/09 02:28:01  hiwu
** add IPPR, IP_ALIAS, MEGA_BUNDLE support for p480
** Revision 1.11  2000/02/01 06:16:27  dlai
** dlai for P641
** Revision 1.10  2000/02/01 03:59:42  cmlo
** Merge P683
** Revision 1.9  2000/01/19 06:44:08  RLO
** rlo for p642
** Revision 1.8  2000/01/19 06:40:02  hchang
** add p310 feature and gre definition
** Revision 1.7  2000/01/10 09:05:36  dlai
** Dlai for P641
** Revision 1.6  2000/01/07 23:50:19  dlai
** Dlai for P641 series
** Revision 1.5  2000/01/06 03:51:39  dlai
** Dlai for P691M/A690V
** Revision 1.4  1999/12/31 02:50:14  GHUANG
** enable dirty bridge in P681
** Revision 1.3  1999/12/16 06:57:27  dlai
** Dlai for CHT P641fm P641gm
** Revision 1.2  1999/11/18 09:07:09  rlu
** Add P641FM for CHT tender case
** Revision 1.1  1999/11/18 03:44:34  rlu
** Initial revision
** Revision 1.39  1999/10/14 06:33:43  YuMJ
** Revision 1.38  1999/10/14 05:49:06  bsu
** add FTPSERV on ARM and MPC platform
** Revision 1.37  1999/09/30 11:26:40  GHUANG
** P681 & A681M definition for network task
** Revision 1.36  1999/09/28 10:53:05  GHUANG
** P681 check in
** Revision 1.35  1999/09/15 01:53:14  rlu
** Revision 1.32  1999/09/03 02:58:18  hchang
** code merge from 2.40
** Revision 1.31  1999/09/01 06:49:08  dchen
** Merge from ZyNOS 2.40
** Revision 1.30  1999/08/10 11:08:44  dchen
** Merge from ZyNOS 2.30/2.40
** Revision 1.29  1999/06/08 06:30:21  bsu
** add options for P1020A/P1100
** Revision 1.28  1999/06/08 05:04:57  bsu
** add P1020A, P1100 support
** Revision 1.27  1999/04/28 06:50:25  HCHANG
** modify zyxp_p220 -> zyxp_p310
** Revision 1.26  1999/04/21 07:51:04  altsai
** remove rt338
** Revision 1.25  1999/04/15 01:51:29  altsai
** Add P202
** Revision 1.24  1999/04/14 09:55:37  rlu
** remove ZYXP_P200
** Revision 1.23  1999/04/13 07:48:41  rlu
** Add ZYXP_RT338
** Revision 1.22  1999/04/13 00:41:22  HCHANG
** rename p220->p310
** Revision 1.21  1999/03/31 06:53:18  HCHANG
** add roadrunner support
** Revision 1.20  1999/03/25 10:56:27  bsu
** fix variable used before set for 860
** Revision 1.19  1999/03/19 07:26:33  HCHANG
** remove SNMP support
** Revision 1.18  1999/02/25 07:34:27  bsu
** add IGMP definition in P128 & P153
** Revision 1.17  1999/02/13 03:08:30  rlu
** Revision 1.16  1999/01/23 04:27:04  EWU
** Modify P200 feature set.
** Revision 1.15  1999/01/18 10:48:45  dlai
** Dlai for p240,p440
** Revision 1.14  1999/01/18 07:01:52  dlai
** dlai for p240, p242
** Revision 1.13  1999/01/15 09:45:08  dlai
** Dlai add p240 option
** Revision 1.12  1999/01/12 01:38:25  HCHANG
** add p220 support
** Revision 1.11  1999/01/04 11:34:41  ghuang
** change SYS_P200 to SYS_ARMC5K
** Revision 1.10  1999/01/04 03:15:24  rlu
** Revision 1.9  1998/12/17 10:01:36  altsai
** Add P200(P100ef) compile option
** Revision 1.8  1998/12/10 09:43:41  EWU
** Enable SMT for P200
** Revision 1.7  1998/11/24 02:40:11  EWU
** ARM
** Revision 1.6  1998/11/18 03:12:19  bsu
** merged 860 code from An-Ping
** Revision 1.5  1998/10/22 03:11:32  dchen
** Add "ZYXEL_P100MH" for P100MH
** Revision 1.4  1998/10/21 05:17:54  bsu
** code merged 220b20 from San Jose
** Revision 1.3  1998/10/13 11:24:34  dchen
** Remove RADIUS for P100 and P100MH/WH
** Revision 1.2  1998/09/02 11:28:09  dchen
** Separate P100 and P100MH flags.
** Revision 1.1  1998/08/31 03:41:11  bsu
** Initial revision
** Revision 1.4  1998/07/03 13:50:50  BRIAN
** Add L2TP and seperate P153 and P128 options
** Revision 1.3  1998/05/16 16:03:00  PHUANG
** Revision 1.2  1998/05/05 18:35:54  PHUANG
** Revision 1.1  1998/05/01 15:21:48  PHUANG
** Revision 1.10  1998/03/02 11:30:58  SHERWIN
** Add TFTP define.
** Revision 1.9  1998/02/24 11:20:36  PHUANG
** Revision 1.8  1998/02/12 12:03:14  SHERWIN
** Add HDAP define.
** Revision 1.7  1998/01/22 12:04:08  PHUANG
** Revision 1.6  1997/12/09 10:42:06  PHUANG
** Revision 1.5  1997/12/02 13:08:02  PHUANG
** Revision 1.4  1997/10/30 13:43:04  PHUANG
** Revision 1.3  1997/10/09 17:22:24  PHUANG
** Revision 1.2  1997/10/01 10:29:40  TROY
** Change copyright notice
*/

#ifdef HAL_API
#include "project.h"
#endif

#ifndef _SWITCH_H
#define _SWITCH_H

/*_____ System options _______________________________________________________*/
/* #define M68K                    1 */

/*_____ Software options _____________________________________________________*/
/* Development version */
#ifdef  DEV
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#endif

/* LITE version */
#ifdef  DEV
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#endif

/* Basic version */
#ifdef  BASIC
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define BCP                     1               /* Bridge Protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#define SNMPD                   1               /* SNMP agent deamon */
#endif

/* IP and IPX version */
#ifdef  IPIPX
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define BCP                     1               /* Bridge Protocol */
#define IPX                     1               /* IPX protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#define SNMPD                   1               /* SNMP agent deamon */
#endif

#ifdef  IPATALK
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define BCP                     1               /* Bridge Protocol */
#define ATALK                   1               /* AppleTalk protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#define SNMPD                   1               /* SNMP agent deamon */
#endif

#ifdef  ALL
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define BCP                     1               /* Bridge Protocol */
#define IPX                     1               /* IPX protocol */
#define ATALK                   1               /* AppleTalk protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#define SNMPD                   1               /* SNMP agent deamon */
#define X75_V120                1               /* X75 and V128 */
#define HDAP            1       /* Host Discovery & Addr Assignment Protocol */
#define TFTP            1       /* TFTP server */
#endif

#ifndef HAL_API
#define ALCATEL_ADSL	1
#define GLOBALSPAN_ADSL	2
#define GLOBALSPAN_SDSL	3
#define SAMSUNG_8950_ADSL 4
#endif

/*______________________________________________________________________________
**      product definition
**____________________________________________________________________________*/
#define ZYXP_P2864I 1   /* prestige 2864I                       */
#define ZYXP_P128       2       /* prestige 128                         */
#define ZYXP_P100       3       /* prestige 100                         */
#define ZYXP_PPPC       4       /* Prestige PPC                         */
#define ZYXP_P480       5       /* Prestige P480 Dual DSL       */
#define ZYXP_P641       6       /* Prestige ADSL*/
#define ZYXP_P310       7       /* Prestige P310 Fast Ethernet & HUB */
#define ZYXP_P202       8       /* Prestige P202                        */
#define ZYXP_P402       9       /* Prestige P402                        */
#define ZYXP_P312  10   /* Prestige P312                        */
#define ZYXP_P681  11   /* Prestige P681                        */
#define ZYXP_P201  12   /* Prestige P201                        */
#define ZYXP_P691M 13   /* Prestige P201            */
#define ZYXP_P683  14   /* Prestige P683                        */
#define ZYXP_P742  15   /* Prestige P742                        */
#define ZYXP_P782  16	/* Prestige P782			*/
#define ZYXP_P316  16   /* Prestige P316                        */
#define ZYXP_P314  17   /* Prestige P314                        */
#define ZYXP_P724V 20   /* Prestige P724V            */
#define ZYXP_P654  18   /* Prestige P654                        */
#define ZYXP_P791  19	/* Prestige P791						*/

/*_____ P100 model _____________________________________________________*/
/*----- all mldels share ZYXP_P100 -------------------------------------*/
#define ZYXM_P100I      1
#define ZYXM_P100MH 2

/*______________________________________________________________________________
**      product option
**____________________________________________________________________________*/
/*_____ ZyXel Prestige 2864I ____________________________________________*/
#ifdef  ZYXEL_P2864I
#define ZYXP            ZYXP_P2864I
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define BCP                     1               /* Bridge Protocol */
#define IPX                     1               /* IPX protocol */
#define ATALK                   1               /* AppleTalk protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#define SNMPD                   1               /* SNMP agent deamon */
#define X75_V120                1               /* X75 and V128 */
#define HDAP            1       /* Host Discovery & Addr Assignment Protocol */
#endif

/*_____ ZyXel Prestige 128 _____________________________________________*/
#ifdef  ZYXEL_P128
#define ZYXP            ZYXP_P128
/* Features same as P153 */
#define IP_OPTION               1               /* IP protocol */
#define BCP                     1               /* Bridge Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#define IPX                     1               /* IPX protocol */
#define RADIUS                  1               /* RADIUS authentication */
#define SECURE                  1               /* Security */
#define PPP                     1               /* Point-to-Point Protocol */
#define SNMPD                   1               /* SNMP agent deamon */
#define HDAP                    1               /* Host Discovery & Addr Assignment Protocol */
#define TFTP                    1               /* TFTP server */
/* Features only for P128 */
#define L2TP                    1               /* L2TP support */
#define IGMP                    1               /* IP multicast support */
#endif

/*_____ ZyXel Prestige 153 _____________________________________________*/
#ifdef  ZYXEL_P153                              /* Same as P128 except L2TP */
#define ZYXP            ZYXP_P128
#define IP_OPTION               1               /* IP protocol */
#define BCP                     1               /* Bridge Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#define IPX                     1               /* IPX protocol */
#define RADIUS                  1               /* RADIUS authentication */
#define SECURE                  1               /* Security */
#define PPP                     1               /* Point-to-Point Protocol */
#define SNMPD                   1               /* SNMP agent deamon */
#define HDAP                    1               /* Host Discovery & Addr Assignment Protocol */
#define TFTP                    1               /* TFTP server */
#define IGMP                    1               /* IP multicast support */
#define SMT_IPX                 1               /* SMT IPX Menu */
#define SMT_BCP                 1               /* SMT BCP Menu */
#endif

/*_____ ZyXel Prestige 100 _____________________________________________*/
#ifdef  ZYXEL_P100
#define ZYXP            ZYXP_P100
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#ifdef  P104
#define LIMIT_USERS 4   /* define number of user in LAN segment */
#endif  /* P104 */
#define HDAP            1       /* Host Discovery & Addr Assignment Protocol */
#define TFTP            1       /* TFTP server */

/*----- Model Definition -----------------------------------------------*/
#ifdef  MODEL_P100I
#define ZYXM            ZYXM_P100I
#endif
#endif /* ZYXEL_P100 */

/*_____ ZyXel Prestige 100MH _____________________________________________*/
#ifdef  ZYXEL_P100MH
#define ZYXP            ZYXP_P100
#define DIALER                  1               /* WAN Dialer code */
#define SECURE                  1               /* Security */
#define IP_OPTION               1               /* IP protocol */
#define PPP                     1               /* Point-to-Point Protocol */
#define SPT                     1               /* SPT */
#define SMT                     1               /* SMT */
#ifdef  P104
  #define       LIMIT_USERS 4           /* define number of user in LAN segment */
#endif  /* P104 */
#define HDAP                    1               /* Host Discovery & Addr Assignment Protocol */
#define TFTP                    1               /* TFTP server */

#endif  /* ZYXEL_P100MH */

/*____________________________________________________________________________*/

/*_____ ZyXel Prestige P1020A _____________________________________________*/
#ifdef ZYXEL_1020A
        #define ZYXP            ZYXP_P1020A
        #define IP_OPTION       1       /* IP protocol */
        #define SPT             1       /* SPT */
        #define PPP             1       /* Point-to-Point Protocol */
        #define HDAP            1       /* Host Discovery and Address Assignment */
        #define SMT             1       /* SMT */
        #define L2TP            1       /* L2TP Tunneling Protocol */
        #define SPT             1       /* SPT */
        #define TFTP            1       /* TFTP */
        #define FTPSERV         1       /* FTP server support */
        #define IPX             1       /* IPX protocol */
        #define BCP             1       /* Bridge Protocol */
        #define RADIUS          1       /* RADIUS authentication */
        #define SECURE          1       /* Security */
        #define SNMPD           1       /* SNMP agent deamon */
        #define IPPR            1       /* IP policy routing */
        #define IGMP            1       /* IP multicast */
        #define IP_ALIAS        1       /* IP aliasing support */
        #define PKT_PARSE       1       /* built-in packet parser */
#endif /* P1020A */

/*_____ ZyXel Prestige P1100 _____________________________________________*/
#ifdef ZYXEL_P1100
        #define ZYXP            ZYXP_P1100
        #define IP_OPTION       1       /* IP protocol */
        #define SPT             1       /* SPT */
        #define PPP             1       /* Point-to-Point Protocol */
        #define HDAP            1       /* Host Discovery and Address Assignment */
        #define SMT             1       /* SMT */
        #define L2TP            1       /* L2TP Tunneling Protocol */
        #define SPT             1       /* SPT */
        #define TFTP            1       /* TFTP */
        #define FTPSERV         1       /* FTP server support */
        #define IPX             1       /* IPX protocol */
        #define BCP             1       /* Bridge Protocol */
        #define RADIUS          1       /* RADIUS authentication */
        #define SECURE          1       /* Security */
        #define SNMPD           1       /* SNMP agent deamon */
        #define IPPR            1       /* IP policy routing */
        #define IGMP            1       /* IP multicast */
        #define IP_ALIAS        1       /* IP aliasing support */
        #define PKT_PARSE       1       /* built-in packet parser */
#endif /* P1100 */

/*_____ ZyXel Prestige P480 _____________________________________________*/
#ifdef  ZYXEL_P480
        #define ZYXP            ZYXP_P480
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define RADIUS          1               /* RADIUS authentication */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1       /* FTP server support */
        #define L2TP            1               /* L2TP support */
        #define SMT             1               /* SMT */
        #define SMT_IPX         1               /* SMT IPX Menu */
        #define SMT_RTC         1               /* Real Time Clock(P480 only) */
        #define SMT_BCP         1               /* SMT BCP Menu */
        #define SMTP480         1               /* P480 specific Menu */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define RTC             1               /* Real Time Clock support */
        #define NUM_SUA_ENTRY 256       /* SUA Entry */
#if 1   
        #define IP_ALIAS        1       /* IP aliasing support */
        #define MEGA_BUNDLE     1               /* ip mega bundle support*/
    #define IPPR        1       /* IP policy routing */         
#endif
  #if 0
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P202 ____________________________________________*/
#ifdef  ZYXEL_P202
        #define ZYXP            ZYXP_P202
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define SECURE          1               /* Security */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1       /* FTP server support */
        #define SMT             1               /* SMT */
        #define RADIUS          1               /* RADIUS authentication */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define CALL_SCH    1           /* call scheduler */
		#define SNMPD		1		/* SNMP agent deamon */
		#define NAT_OPT     1
		#define HTTPD           1               /* HTTP daemon and GUI */				
    	#define SMT_RTC         1
        #define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 2, 1}	/* System Object Identifier */
        #define SYSOBJID_LEN 11
		#define RANGE_PORT_FORWARDING	1	/* smt15 using range port forwarding */  
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 800 /* Timothy 0227, from 800 -> 2400 */
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
        #define CLI								/* Command Line Interface */
        #define IPSEC				1			/* IPSec-VPN */
        #define ISAKMP				1			/* ISAKMP/Oakley protocol */
    
        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */ /* bchung debug for 5 VPN session */
		#define NUM_OF_MAX_IPSC_RULE		5 	/* max ipsec rules */ /* bchung debug for 5 VPN session */
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	5	/* max active ipsec rules *//* bchung debug for 5 VPN session */
		#define SPD_NUM_ENTRY				10 	/* #entry of SPD *//* bchung debug for 5 VPN session */

		#define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define DHCP			1
		#define IP_ALIAS			1			/* IP aliasing support */        
	    #define FIREWALL			1			/* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE	 1		/* Firewall act when time scheduled */
//		#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
//		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS	1			/* Bypass accessing router from LAN */
//		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MISC_FIREWALL		1			/* Misc FIREWALL configuration */
	#endif        
       // #define ROMFILE_BACKUP		1			/* Restore default romfile */
        //#define CLI				 				/* Command Line Interface */
		//#define SPTGEN				1			/* SPTGen support */
		//#define REMOTE_MANAGE_SETUP 1			/* Remote Manage Setup support */
		#define ZyNOS				1		
        
  #if 0
        #define BCP             1               /* Bridge Protocol */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define L2TP            1               /* L2TP support */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P201 ____________________________________________*/
#ifdef  ZYXEL_P201
        #define ZYXP            ZYXP_P201
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define SECURE          1               /* Security */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1       /* FTP server support */
        #define SMT             1               /* SMT */
        #define RADIUS          2               /* RADIUS authentication *//* no menu 23.2 */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define SNMPD           1               /* SNMP agent deamon */
  #if 0
        #define BCP             1               /* Bridge Protocol */
        #define IPX             1               /* IPX protocol */
        #define L2TP            1               /* L2TP support */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P402 ____________________________________________*/
#ifdef  ZYXEL_P402
        #define ZYXP            ZYXP_P402
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define SECURE          1               /* Security */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1       /* FTP server support */
        #define RADIUS          1               /* RADIUS authentication */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define BCP             1               /* Bridge Protocol */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define SMT             1               /* SMT */
        #define SMT_IPX         1               /* SMT IPX Menu */
        #define SMT_BCP         1               /* SMT BCP Menu */
  #if 0
        #define L2TP            1               /* L2TP support */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif
/*_____ ZyXel Prestige P742 _____________________________________________*/
        #ifdef  ZYXEL_P742
        #define XDSL_CHIP				GLOBALSPAN_SDSL
        #define ZYXP                    ZYXP_P742
        #define IP_OPTION               1                               /* IP protocol */
        #define SPT                             1                               /* SPT */
        #define PPP                             1                               /* Point-to-Point Protocol */
        #define BCP                             1                               /* Bridge Protocol */
        #define SECURE                  1                               /* Security */
        #define SNMPD                   1                               /* SNMP agent deamon */
        #define IPX                             1                               /* IPX protocol */
        #define HDAP                    1                               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP                    1                               /* TFTP server */
        #define FTPSERV                 1                               /* FTP server support */
        #define SMT                             1                               /* SMT */
        #define PKT_PARSE               1                               /* Embedded ZPKTTOOL */
        #define BCP                             1
        #define MPOA                            1
        #define TCP_MSS_ADJUST                  1
        #define RCV_IP_MULTICAST_ONLY   1
        #define PPPOE                                   1
        #define SMT_IPX                                 1
	#if 0
	#define BRIDGE_ONLY_MANAGEMENT	1
	#else
	#define DIRTY_BRIDGE 1		/* fix bridge problem */
	#endif
	#define QUICK_BRIDGE			1
	
	#define ONE_LAN_BRIDGE			1
	#define IGMP					1		/* IP multicast */
	#define IP_ALIAS				1		/* IP aliasing support */
	#define IPPR					1		/* IPPR */

	#define NUM_SUA_ENTRY		256			/* SUA Entry */
	#define N_NETWORK_EQ_CELL	20
	#define N_NETWORK_DQ_CELL	100
	#define N_TCPOUT_DQ_CELL	10
	#define MAX_NETWORK_COUNT	100
	#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
	#if 0
		#define RADIUS			1				/* RADIUS authentication */
		#define L2TP			1				/* L2TP support */
	#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif

/*_____ ZyXel Prestige P782 _____________________________________________*/
#ifdef  ZYXEL_P782
	#define XDSL_CHIP		GLOBALSPAN_SDSL
	#define ZYXP			ZYXP_P782
	#define BI_DIRECTION	1
	#define IP_OPTION		1				/* IP protocol */
	#define SPT				1				/* SPT */
	#define PPP				1				/* Point-to-Point Protocol */
	#define BCP				1				/* Bridge Protocol */
	#define SECURE			1				/* Security */
	#define SNMPD			1				/* SNMP agent deamon */
	#define IPX				1				/* IPX protocol */
	#define HDAP			1				/* Host Discovery & Addr Assignment Protocol */
	#define TFTP			1				/* TFTP server */
	#define FTPSERV			1				/* FTP server support */
	#define SMT				1				/* SMT */
	#define PKT_PARSE		1				/* Embedded ZPKTTOOL */
	#define MPOA				1
	#define TCP_MSS_ADJUST			1
	#define RCV_IP_MULTICAST_ONLY	1
	#define PPPOE					1
	#define SMT_IPX					1
	#define BRIDGE_ONLY_MANAGEMENT	1
	#define QUICK_BRIDGE			1
	#define ONE_LAN_BRIDGE			1
	#define IGMP					1		/* IP multicast */
	#define IP_ALIAS				1		/* IP aliasing support */
	#define IPPR					1		/* IPPR */
	#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     

	#define NUM_SUA_ENTRY		256			/* SUA Entry */
	#define N_NETWORK_EQ_CELL	20
	#define N_NETWORK_DQ_CELL	800
	#define N_TCPOUT_DQ_CELL	10
	#define MAX_NETWORK_COUNT	800
	#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
	#define	CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 12)
    #define DNS_QUERY       1		/* DNS Query SUPPORT */
	#if 0
		#define RADIUS			1				/* RADIUS authentication */
		#define L2TP			1				/* L2TP support */
	#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif

/*_____ ZyXel Prestige P788B4 _____________________________________________*/
	#ifdef  ZYXEL_P788B4
	#define XDSL_CHIP		GLOBALSPAN_SDSL
	#define ZYXP			ZYXP_P788B4
	#define IP_OPTION		1				/* IP protocol */
	#define SPT				1				/* SPT */
	#define PPP				1				/* Point-to-Point Protocol */
	#define BCP				1				/* Bridge Protocol */
	#define SECURE			1				/* Security */
	#define SNMPD			1				/* SNMP agent deamon */
	#define IPX				1				/* IPX protocol */
	#define HDAP			1				/* Host Discovery & Addr Assignment Protocol */
	#define TFTP			1				/* TFTP server */
	#define FTPSERV			1				/* FTP server support */
	#define SMT				1				/* SMT */
	#define PKT_PARSE		1				/* Embedded ZPKTTOOL */
	#define BCP				1
	#define MPOA				1
	#define TCP_MSS_ADJUST			1
	#define RCV_IP_MULTICAST_ONLY	1
	#define PPPOE					1
	#define SMT_IPX					1
	#if 0
        #define BRIDGE_ONLY_MANAGEMENT  1
	#else
	#define DIRTY_BRIDGE 1		/* fix bridge problem */
	#endif
        #define ONE_LAN_BRIDGE                  1
        #define IGMP                                    1               /* IP multicast */
        #define IP_ALIAS                                1               /* IP aliasing support */
        #define IPPR                                    1               /* IPPR */

        #define NUM_SUA_ENTRY           256                     /* SUA Entry */
        #define N_NETWORK_EQ_CELL       20
	#define N_NETWORK_DQ_CELL	200
        /*#define N_NETWORK_DQ_CELL       1200*/
        #define N_TCPOUT_DQ_CELL        10
	#define MAX_NETWORK_COUNT	200
        /*#define MAX_NETWORK_COUNT               1200*/
        #define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
        #if 0
                #define RADIUS                  1                               /* RADIUS authentication */
                #define L2TP                    1                               /* L2TP support */
        #endif
        #ifndef ZYXM
                #define ZYXM                    -1
        #endif
#endif
/*_____ ZyXel Prestige P641 _____________________________________________*/
#ifdef  ZYXEL_P641
        #define ZYXP            ZYXP_P641
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1           /* FTP server support */
        #define SMT             1               /* SMT */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define BCP                     1
        #define MPOA                    1
        #define TCP_MSS_ADJUST          1
        #define RCV_IP_MULTICAST_ONLY   1
        #define PPPOE                   1
        #define SMT_IPX                 1
        #define BRIDGE_ONLY_MANAGEMENT  1
        #define ONE_LAN_BRIDGE          1
        #define IGMP            1       /* IP multicast */
        #define IP_ALIAS        1       /* IP aliasing support */
        #define IPPR            1       /* IPPR */
        #define DNS_QUERY       1       /* DNS Query SUPPORT */
        
        #define NUM_SUA_ENTRY 256       /* SUA Entry */
        #define N_NETWORK_EQ_CELL 20
        #define N_NETWORK_DQ_CELL 800
        #define N_TCPOUT_DQ_CELL 10
        #define MAX_NETWORK_COUNT       800
        #define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
  #if 0
        #define RADIUS          1               /* RADIUS authentication */
        #define L2TP            1               /* L2TP support */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif
/*_____ ZyXEL Prestige P643 router  _____*/
#ifdef	ZYXEL_P643
	#define ZYXP		ZYXP_P641
	#define IP_OPTION	1		/* IP protocol */
	#define SPT 		1		/* SPT */
	#define PPP 		1		/* Point-to-Point Protocol */
	#define BCP 		1		/* Bridge Protocol */
	#define SECURE		1		/* Security */
	#define SNMPD		1		/* SNMP agent deamon */
	#define IPX 		1		/* IPX protocol */
	#define HDAP		1		/* Host Discovery & Addr Assignment Protocol */
	#define TFTP		1		/* TFTP server */
	#define FTPSERV 	1	    /* FTP server support */
	#define SMT 		1		/* SMT */
	#define PKT_PARSE	1		/* Embedded ZPKTTOOL */
	#define BCP			1
	#define MPOA		1
	#define TCP_MSS_ADJUST			1
	#define BRIDGE_ONLY_MANAGEMENT	1
	#define ONE_LAN_BRIDGE		    1
	#define PPPOE			    	1
	#define SMT_IPX					1
	#define ONE_LAN_BRIDGE		1
	#define IGMP		1	/* IP multicast */
	#define IP_ALIAS	1	/* IP aliasing support */
	#define IPPR		1	/* IPPR */
	#define PHY_HUB_4PORT   1	/* support KS8995 4 port hub */
	#define QUICK_BRIDGE	1	/* performance inprove for bridge mode */
	#define CALL_SCH	1	/* call schedule for PPPoE */
    #define DNS_QUERY       1
	/* #define SUA_ONLY        1 */              /* Support for SUA_ONLY setting */
	#define NAT_OPT         1
	#define HTTPD           1               /* HTTP daemon and GUI */				

	#define NUM_SUA_ENTRY 256	/* SUA Entry */
	#define N_NETWORK_EQ_CELL 20
	#define N_NETWORK_DQ_CELL 800
	#define N_TCPOUT_DQ_CELL 10
	#define MAX_NETWORK_COUNT	800
	#define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
  #if 0
	#define RADIUS		1		/* RADIUS authentication */
	#define L2TP		1		/* L2TP support */
  #endif
  #ifndef ZYXM
	#define ZYXM		-1
  #endif
#endif

/*_____ ZyXEL Prestige P647 router  _____*/
#ifdef	ZYXEL_P647
	#define ZYXP		ZYXP_P641
	#define IP_OPTION	1		/* IP protocol */
	#define SPT 		1		/* SPT */
	#define PPP 		1		/* Point-to-Point Protocol */
	#define BCP 		1		/* Bridge Protocol */
	#define SECURE		1		/* Security */
	#define SNMPD		1		/* SNMP agent deamon */
	#define IPX 		1		/* IPX protocol */
	#define HDAP		1		/* Host Discovery & Addr Assignment Protocol */
	#define TFTP		1		/* TFTP server */
	#define FTPSERV 	1	    /* FTP server support */
	#define SMT 		1		/* SMT */
	#define PKT_PARSE	1		/* Embedded ZPKTTOOL */
	#define BCP			1
	#define MPOA		1
	#define TCP_MSS_ADJUST			1
	#define BRIDGE_ONLY_MANAGEMENT	1
	#define ONE_LAN_BRIDGE		    1
	#define PPPOE			    	1
	#define SMT_IPX					1
	#define ONE_LAN_BRIDGE		1
	#define IGMP		1	/* IP multicast */
	#define IP_ALIAS	1	/* IP aliasing support */
	#define IPPR		1	/* IPPR */
	#define PHY_HUB_4PORT   1	/* support KS8995 4 port hub */
	#define QUICK_BRIDGE	1	/* performance inprove for bridge mode */
	#define CALL_SCH	1	/* call schedule for PPPoE */
    #define DNS_QUERY       1
	#define PHY_SEEQ_SUPPORT		1
	#define	DDNS			1
	#define	TIME_SERVER		1
	/* #define SUA_ONLY        1 */              /* Support for SUA_ONLY setting */

	#define NUM_SUA_ENTRY 256	/* SUA Entry */
	#define N_NETWORK_EQ_CELL 20
	#define N_NETWORK_DQ_CELL 800
	#define N_TCPOUT_DQ_CELL 10
	#define MAX_NETWORK_COUNT	800
	#define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
  #if 0
	#define RADIUS		1		/* RADIUS authentication */
	#define L2TP		1		/* L2TP support */
  #endif
  #ifndef ZYXM
	#define ZYXM		-1
  #endif
#endif
/*_____ ZyXEL Prestige P642 OBM router - simplified version of P641 _____*/
#ifdef  ZYXEL_P642OFR
        #define ZYXP            ZYXP_P641
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1           /* FTP server support */
        #define SMT             1               /* SMT */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define BCP                     1
        #define MPOA            1
        #define TCP_MSS_ADJUST                  1
        #define BRIDGE_ONLY_MANAGEMENT  1
        #define ONE_LAN_BRIDGE              1
        #define PPPOE                           1
        #define SMT_IPX                                 1
        #define ONE_LAN_BRIDGE          1
        #define IGMP            1       /* IP multicast */
        #define IP_ALIAS        1       /* IP aliasing support */
        #define IPPR            1       /* IPPR */

        #define NUM_SUA_ENTRY 256       /* SUA Entry */
        #define N_NETWORK_EQ_CELL 20
        #define N_NETWORK_DQ_CELL 800
        #define N_TCPOUT_DQ_CELL 10
        #define MAX_NETWORK_COUNT       800
        #define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
  #if 0
        #define RADIUS          1               /* RADIUS authentication */
        #define L2TP            1               /* L2TP support */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXEL Prestige P642 CHT Version ____________________________________*/
#ifdef  ZYXEL_P642CHT
        #define ZYXP            ZYXP_P641
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1           /* FTP server support */
        #define SMT             1               /* SMT */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define BCP                     1
        #define MPOA            1
        #define TCP_MSS_ADJUST                  1
        #define BRIDGE_ONLY_MANAGEMENT  1
        #define ONE_LAN_BRIDGE          1
        /* #define PPPOE                                1  */
        #define SMT_IPX                                 1
    #define VERSION_REAL            1

	#define NUM_SUA_ENTRY 256	/* SUA Entry */
	#define N_NETWORK_EQ_CELL 20
	#define N_NETWORK_DQ_CELL 800
	#define N_TCPOUT_DQ_CELL 10
	#define MAX_NETWORK_COUNT	800
	#define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
  #if 0
	#define RADIUS		1		/* RADIUS authentication */
	#define L2TP		1		/* L2TP support */
  #endif
  #ifndef ZYXM
	#define ZYXM		-1
  #endif
#endif

/*_____ ZyXEL Prestige P642 Sprint Casino Version ___________________*/
#ifdef	ZYXEL_P642SPR
	#define ZYXP		ZYXP_P641
	#define IP_OPTION	1		/* IP protocol */
	#define SPT 		1		/* SPT */
	#define PPP 		1		/* Point-to-Point Protocol */
	#define BCP 		1		/* Bridge Protocol */
	#define SECURE		1		/* Security */
	#define SNMPD		1		/* SNMP agent deamon */
	#define IPX 		1		/* IPX protocol */
	#define HDAP		1		/* Host Discovery & Addr Assignment Protocol */
	#define TFTP		1		/* TFTP server */
	#define FTPSERV 	1	    /* FTP server support */
	#define SMT 		1		/* SMT */
	#define PKT_PARSE	1		/* Embedded ZPKTTOOL */
	#define BCP			1
	#define MPOA		1
	#define TCP_MSS_ADJUST			1
	#define BRIDGE_ONLY_MANAGEMENT	1
	#define ONE_LAN_BRIDGE		1
	/* #define PPPOE		1  */
	#define SMT_IPX			1
	#define QUICK_BRIDGE		1

        #define NUM_SUA_ENTRY 256       /* SUA Entry */
        #define N_NETWORK_EQ_CELL 20
        #define N_NETWORK_DQ_CELL 800
        #define N_TCPOUT_DQ_CELL 10
        #define MAX_NETWORK_COUNT       800
        #define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
  #if 0
        #define RADIUS          1               /* RADIUS authentication */
        #define L2TP            1               /* L2TP support */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P641FM/P641GM _________________________________________*/
#if defined ZYXEL_P641FM || defined ZYXEL_P641GM || defined ZYXEL_POEM
    #define ZYXP        ZYXP_P641
    #define IP_OPTION   1       /* IP protocol */
        #define SPT             1               /* SPT */
    #define PPP         1       /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
    #define HDAP        1       /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1           /* FTP server support */
        #define SMT             1               /* SMT */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define BRIDGE_ONLY 1
        #define BRIDGE_ONLY_MANAGEMENT  1
        #define BCP                     1
	#define PHY_SEEQ_SUPPORT   		1	
        #define MPOA                    1
        #define N_NETWORK_EQ_CELL 20
        #define N_NETWORK_DQ_CELL 800
        #define N_TCPOUT_DQ_CELL 10
        #define MAX_NETWORK_COUNT       800
        #define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
	#define QUICK_BRIDGE    		1
	#define SPTGEN					1
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P641-M _____________________________________________*/
#ifdef  ZYXEL_P641M
        #define ZYXP            ZYXP_P641
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
    #define TFTP        1       /* TFTP server */
        #define FTPSERV         1           /* FTP server support */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define N_NETWORK_EQ_CELL 20
        #define N_NETWORK_DQ_CELL 800
        #define N_TCPOUT_DQ_CELL 10
	#define MAX_NETWORK_COUNT	15
        #define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
  #if 0
        #define IP_OPTION       1               /* IP protocol */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define SMT             1               /* SMT */
        #define RADIUS          1               /* RADIUS authentication */
        #define L2TP            1               /* L2TP support */
        #define SECURE          1               /* Security */
        #define NUM_SUA_ENTRY 256       /* SUA Entry */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif


/*_____ ZyXel Prestige P681M _____________________________________________*/
/*#ph- */
#ifdef  ZYXEL_P681M
        #define ZYXP            ZYXP_P681
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define SMT             1               /* SMT */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */

	#define MAX_NETWORK_COUNT	15
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif


/*_____ ZyXel Prestige P691M _____________________________________________*/
/*#ph- */
#ifdef  ZYXEL_P691M
    #define ZYXP        ZYXP_P691M
    #define SPT         1       /* SPT */
    #define SMT         1       /* SMT */
        #define MPOA        1       /* cjyu */
    #define PKT_PARSE   1       /* Embedded ZPKTTOOL */
    #define FR_INTERWORKING     1

	#define MAX_NETWORK_COUNT	15
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P724V _____________________________________________*/
/*#ph- */
#ifdef  ZYXEL_P724V
    #define ZYXP        ZYXP_P724V
	#define IP_OPTION		1				/* IP protocol */
    #define SPT         1       /* SPT */
	#define PPP				1				/* Point-to-Point Protocol */
	#define BCP				1				/* Bridge Protocol */
	#define SNMPD		1		/* SNMP agent deamon */
	#define HDAP			1				/* Host Discovery & Addr Assignment Protocol */
	#define TFTP			1				/* TFTP server */
	#define FTPSERV 	1	    /* FTP server support */
    #define SMT         1       /* SMT */
    #define PKT_PARSE   1       /* Embedded ZPKTTOOL */
	#define MPOA		1
	#define FRELAY		1
    #define FR_INTERWORKING     1
	#define TCP_MSS_ADJUST			1

	#define NUM_SUA_ENTRY		256			/* SUA Entry */
	#define N_NETWORK_EQ_CELL	20
	#define N_NETWORK_DQ_CELL	800
	#define N_TCPOUT_DQ_CELL	10
	#define MAX_NETWORK_COUNT	800
	#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
	#define	CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 12)
    #define DNS_QUERY       1

    #ifndef ZYXM
        #define ZYXM            -1
    #endif
#endif

/*_____ ZyXel Prestige P681 _____________________________________________*/
#ifdef  ZYXEL_P681
        #define ZYXP            ZYXP_P681
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1       /* FTP server support */
        #define SMT             1               /* SMT */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define DIRTY_BRIDGE 1          /* fix bridge problem */

	#define MAX_NETWORK_COUNT	15
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P683 _____________________________________________*/
#ifdef  ZYXEL_P683
        #define ZYXP            ZYXP_P683
        #define IP_OPTION       1               /* IP protocol */
        #define SPT             1               /* SPT */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP             1               /* Bridge Protocol */
        #define SECURE          1               /* Security */
        #define SNMPD           1               /* SNMP agent deamon */
        #define IPX             1               /* IPX protocol */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1       /* FTP server support */
        #define SMT             1               /* SMT */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define DIRTY_BRIDGE 1          /* fix bridge problem */

	#define MAX_NETWORK_COUNT	15
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif


#if  defined ( P310_ST )
/*_____ ZyXel Prestige P310 _____________________________________________*/
#ifdef  ZYXEL_P310
		#define ZYXP            ZYXP_P310
		#define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -14)
		#define MAX_NETWORK_COUNT 800
		#define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
		#define NUM_SUA_ENTRY 256               /* SUA Entry */
		#define N_NETWORK_DQ_CELL 800
		#define N_NETWORK_EQ_CELL 20
		#define N_TCPOUT_DQ_CELL 10
		#define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)
		
		#define ADJUSTTIME      1               /* ADJUST Time */
		#define CALL_SCH        1               /* call scheduler */
		#define DDNS            1               /* Dynamic DNS */
		#define DHCP_RELAY		1				/* DHCP Relay */
		#define DNS_QUERY       1               /* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV         1               /* FTP server support */
		#define GRE             1               /* PPTP Client GRE */
		#define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
		#define HTTPD           1               /* HTTP daemon and GUI */				
		#define IGMP            1               /* IP multicast support */
		#define IP_ALIAS        1               /* IP aliasing support */
		#define IP_OPTION       1               /* IP protocol */
		#define NAIL_UP         1               /* Nail up opetion will show on SMT11_1 */
		#define PKT_PARSE       1               /* Embedded ZPKTTOOL */
		#define PPP             1               /* Point-to-Point Protocol */
		#define PPPOE           1               /* Support PPPOE */
		#define PPTP            1               /* PPTP Client support */
		#define PPTP_CLNT		1				/* PPTP Client support */
		#define PPTP_DBG        1               /* PPTP Debug */
		#define ROAD_RUNNER     1               /* RoadRunner application */ 
		#define SECURE          1               /* Security */
		#define SMT             1               /* SMT */
		#define SNMPD           1               /* SNMP agent daemon */
		#define SPT             1               /* SPT */
		#define StcpDebug       0               /* used to reduce complie warning */
		#define SUA_ONLY        1               /* Support for SUA_ONLY setting */		
		#define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
		#define TFTP            1               /* TFTP server */
		#define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
		
  #if 0
		#define APPL_TRACERT    1               /* TRACE_ROUTE */  
		#define BCP             1               /* Bridge Protocol */
		#define CLI             1               /* CLI */
		#define FIREWALL        1               /* FIREWALL */
		#define IPCOMP          1               /* IP Payload Compression */
		#define IPSEC           1
		#define IPX             1               /* IPX protocol */
		#define ISAKMP          1               /* ISAKMP/Oakley protocol */
		#define L2TP            1               /* L2TP support */
		#define RADIUS          1               /* RADIUS authentication */
		#define REMOTE_MANAGE_SETUP 1           /* SMT24_11 Remote Manage Setup enable */
        #define SMTP_CLNT		1				/* Enable Mail Client */
		#define SUA_ONLY        1               /* Support for SUA_ONLY setting */		
		#define TELNET_CLNT     1               /* TELNET Client */
  #endif
  #ifndef ZYXM
	#define ZYXM        -1
  #endif
#endif

#elif defined ( P310_FR )
/*_____ ZyXel Prestige P310 _____________________________________________*/
#ifdef  ZYXEL_P310
		#define ZYXP            ZYXP_P310
		#define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -14)
		#define MAX_NETWORK_COUNT 800
		#define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
		#define NUM_SUA_ENTRY 256               /* SUA Entry */
		#define N_NETWORK_DQ_CELL 800
		#define N_NETWORK_EQ_CELL 20
		#define N_TCPOUT_DQ_CELL 10
		#define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)
		
		#define ADJUSTTIME      1               /* ADJUST Time */
		#define CALL_SCH        1               /* call scheduler */
		#define DDNS            1               /* Dynamic DNS */
		#define DNS_QUERY       1               /* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV         1               /* FTP server support */
		#define GRE             1               /* PPTP Client GRE */
		#define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
		#define IGMP            1               /* IP multicast support */
		#define IP_ALIAS        1               /* IP aliasing support */
		#define IP_OPTION       1               /* IP protocol */
		#define NAIL_UP         1               /* Nail up opetion will show on SMT11_1 */
		#define PKT_PARSE       1               /* Embedded ZPKTTOOL */
		#define PPP             1               /* Point-to-Point Protocol */
		#define PPPOE           1               /* Support PPPOE */
		#define PPTP            1               /* PPTP Client support */
		#define PPTP_DBG        1               /* PPTP Debug */
		#define ROAD_RUNNER     1               /* RoadRunner application */ 
		#define SECURE          1               /* Security */
		#define SMT             1               /* SMT */
		#define SNMPD           1               /* SNMP agent daemon */
		#define SPT             1               /* SPT */
		#define StcpDebug       0               /* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
		#define TFTP            1               /* TFTP server */
		#define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
  #if 0
		#define APPL_TRACERT    1               /* TRACE_ROUTE */  
		#define BCP             1               /* Bridge Protocol */
		#define CLI             1               /* CLI */
		#define DHCP_RELAY		1				/* DHCP Relay */		
		#define FIREWALL        1               /* FIREWALL */
		#define HTTPD           1               /* HTTP daemon and GUI */		
		#define IPCOMP          1               /* IP Payload Compression */
		#define IPSEC           1
		#define IPX             1               /* IPX protocol */
		#define ISAKMP          1               /* ISAKMP/Oakley protocol */
		#define L2TP            1               /* L2TP support */
		#define RADIUS          1               /* RADIUS authentication */
		#define REMOTE_MANAGE_SETUP 1           /* SMT24_11 Remote Manage Setup enable */
        #define SMTP_CLNT		1				/* Enable Mail Client */		
		#define SUA_ONLY        1               /* Support for SUA_ONLY setting */		
		#define TELNET_CLNT     1               /* TELNET Client */
  #endif
  #ifndef ZYXM
	#define ZYXM        -1
  #endif
#endif

#else

#ifdef  ZYXEL_P310
        #define ZYXP            ZYXP_P310
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -14)
        #define MAX_NETWORK_COUNT 800
        #define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10
        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)
        
        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1               /* HTTP daemon and GUI */
        #define IGMP            1               /* IP multicast support */
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define PPPOE           1               /* Support PPPOE */
        #define ROAD_RUNNER     1               /* RoadRunner application */ 
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define SUA_ONLY        1               /* Support for SUA_ONLY setting */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TFTP            1               /* TFTP server */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
  #if 0
        #define ADJUSTTIME      1               /* ADJUST Time */
        #define APPL_TRACERT    1               /* TRACE_ROUTE */  
        #define BCP             1               /* Bridge Protocol */
        #define CALL_SCH        1               /* call scheduler */
        #define CLI             1               /* CLI */
		#define DHCP_RELAY		1				/* DHCP Relay */        
        #define FIREWALL        1               /* FIREWALL */
        #define GRE             1               /* PPTP Client GRE */
        #define IP_ALIAS        1               /* IP aliasing support */
        #define IPCOMP          1               /* IP Payload Compression */
        #define IPSEC           1
        #define IPX             1               /* IPX protocol */
        #define ISAKMP          1               /* ISAKMP/Oakley protocol */
        #define L2TP            1               /* L2TP support */
        #define NAIL_UP         1               /* Nail up opetion will show on SMT11_1 */
        #define PPTP            1               /* PPTP Client support */
        #define PPTP_DBG        1               /* PPTP Debug */
        #define RADIUS          1               /* RADIUS authentication */
        #define REMOTE_MANAGE_SETUP 1           /* SMT24_11 Remote Manage Setup enable */
        #define SMTP_CLNT		1				/* Enable Mail Client */
        #define SNMPD           1               /* SNMP agent daemon */
        #define TELNET_CLNT     1               /* TELNET Client */
  #endif
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif
#endif

/*_____ ZyXel Prestige P312 _______________________________________________*/
#ifdef  ZYXEL_P312
        #define ZYXP        ZYXP_P312
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -14)
        #define MAX_NETWORK_COUNT 800
        #define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10
        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)
        
        #define ADJUSTTIME      1               /* ADJUST Time */
        #define APPL_TRACERT    1               /* TRACE_ROUTE */       
        #define CALL_SCH        1               /* call scheduler */
        #define CLI             1               /* CLI */
        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1    
        #define FIREWALL        1               /* FIREWALL */ 
        #define FTPSERV         1               /* FTP server support */
        #define GRE             1               /* PPTP Client GRE */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1               /* HTTP daemon and GUI */
        #define IGMP            1               /* IP multicast support */
        #define IP_ALIAS        1               /* IP aliasing support */
        #define IP_OPTION       1               /* IP protocol */
        #define NAIL_UP         1               /* Nail up opetion will show on SMT11_1 */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define PPPOE           1               /* Support PPPOE */
        #define PPTP            1               /* PPTP Client support */
        #define PPTP_DBG        1               /* PPTP Debug */
        #define REMOTE_MANAGE_SETUP 1           /* SMT24_11 Remote Manage Setup enable */
        #define ROAD_RUNNER     1               /* RoadRunner application */ 
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SMTP_CLNT		1				/* Enable Mail Client */        
        #define SNMPD           1               /* SNMP agent deamon */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
        #define TELNET_CLNT     1               /* TELNET Client */
        #define TFTP            1               /* TFTP server */
  #if 0
        #define BCP             1               /* Bridge Protocol */
		#define DHCP_RELAY		1				/* DHCP Relay */        
        #define IPCOMP          1               /* IP Payload Compression */
        #define IPSEC           1
        #define IPX             1               /* IPX protocol */
        #define ISAKMP          1               /* ISAKMP/Oakley protocol */
        #define L2TP            1               /* L2TP support */
        #define RADIUS          1               /* RADIUS authentication */
        #define SUA_ONLY        1               /* Support for SUA_ONLY setting */
  #endif
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif

/*_____ ZyXel Prestige P314 _______________________________________________*/
#ifdef  ZYXEL_P314
        #define ZYXP            ZYXP_P314
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -14)
        #define MAX_NETWORK_COUNT 800
        #define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10
        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)
        
        #define DDNS            1               /* Dynamic DNS Support */ 
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1       
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1               /* HTTP daemon and GUI */
        #define IGMP            1               /* IP multicast support */
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define PPPOE           1               /* Support PPPOE */
        #define ROAD_RUNNER     1               /* RoadRunner application */
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */      
        #define StcpDebug       0               /* used to reduce complie warning */  
        #define SUA_ONLY        1               /* Support for SUA_ONLY setting */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size (MSS) Adjustment */
        #define TFTP            1               /* TFTP server */        
  #if 0
        #define ADJUSTTIME      1               /* ADJUST Time */
        #define APPL_TRACERT    1               /* TRACE_ROUTE */    
        #define BCP             1               /* Bridge Protocol */
        #define CALL_SCH        1               /* Call scheduler */
        #define CLI             1               /* CLI */
        #define FIREWALL        1               /* FIREWALL agent deamon */
        #define GRE             1               /* PPTP Client GRE */
        #define IP_ALIAS        1               /* IP aliasing support */
        #define IPCOMP          1               /* IP Payload Compression */
        #define IPSEC           1
        #define IPX             1               /* IPX protocol */
        #define ISAKMP          1               /* ISAKMP/Oakley protocol */
        #define L2TP            1               /* L2TP support */
        #define NAIL_UP         1               /* Nail up opetion will show on SMT11_1 */
        #define PPTP            1               /* PPTP Client support */
        #define PPTP_DBG        1               /* PPTP Debug */
        #define RADIUS          1               /* RADIUS authentication */
        #define REMOTE_MANAGE_SETUP 1           /* SMT24_11 Remote Manage Setup enable */
        #define SMTP_CLNT		1				/* Enable Mail Client */        
        #define SNMPD           1               /* SNMP */
        #define TELNET_CLNT     1               /* TELNET Client */
  #endif
  #ifndef ZYXM
        #define ZYXM            -1
  #endif
#endif

/*_____ ZyXel Prestige P316 _______________________________________________*/
#ifdef  ZYXEL_P316
        #define ZYXP        ZYXP_P316
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -14)
        #define MAX_NETWORK_COUNT 800
        #define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10
        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)
     
        #define ADJUSTTIME      1               /* ADJUST Time */
        #define APPL_TRACERT    1               /* TRACE_ROUTE */  
        #define BCP             1               /* Bridge Protocol */
        #define CALL_SCH        1               /* call scheduler */
        #define CLI             1               /* CLI */    
        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1    
        #define FTPSERV         1               /* FTP server support */
        #define GRE             1               /* PPTP Client GRE */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1               /* HTTP daemon and GUI */ 
        #define IGMP            1               /* IP multicast support */
        #define IP_ALIAS        1               /* IP aliasing support */
        #define IP_OPTION       1               /* IP protocol */
        #define NAIL_UP         1               /* Nail up opetion will show on SMT11_1 */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */

        #define PPPOE           1               /* Support PPPOE */
        #define PPTP            1               /* PPTP Client support */
        #define PPTP_DBG        1               /* PPTP Debug */
        #define REMOTE_MANAGE_SETUP 1           /* SMT24_11 Remote Manage Setup enable */
        #define ROAD_RUNNER     1               /* RoadRunner application */ 
        #define ROMFILE_BACKUP  1
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SNMPD           1               /* SNMP agent deamon */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define SUA_ONLY        1               /* Support for SUA_ONLY setting */	
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
        #define TELNET_CLNT     1               /* TELNET Client */   
        #define TFTP            1               /* TFTP server */   
        #define WLAN_BRIDGE     1               /* Bridge function only between WLAN & LAN */

  #if 0        
        #define FIREWALL        1               /* FIREWALL agent deamon */
        #define IPCOMP          1               /* IP Payload Compression */
        #define IPSEC           1
        #define IPX             1               /* IPX protocol */
        #define ISAKMP          1               /* ISAKMP/Oakley protocol */
        #define L2TP            1               /* L2TP support */
        #define RADIUS          1               /* RADIUS authentication */
        #define SMTP_CLNT		1				/* Enable Mail Client */    
  #endif
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif


/* (AP,MDU,Merge),7-8-99,Added P1600 section */
/*_____ ZyXel Prestige P1600 _____________________________________________*/
#ifdef ZYXEL_P1600
        #define ZYXP            ZYXP_P1600
        #define ZYX_MDU         1               /* zc990811#0 - P1600 is one of ZyXEL MDU series */
        #define IP_OPTION       1               /* IP protocol */
        #define SPT                     1               /* SPT */
        #define PPP                     1               /* Point-to-Point Protocol */
        #define TFTP            1               /* TFTP server */
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery and Address Assignment */
        #define SMT                     1               /* SMT */
        #define SPT                     1               /* SPT */
        #define RADIUS          1       /* RADIUS authentication */
        #define SECURE          1       /* Security */
        #define SNMPD           1       /* SNMP agent deamon */
        #define IPPR            1               /* IP policy routing */
        #define IP_ALIAS        1               /* IP aliasing support */
#if 0        
        #define IGMP            1               /* IP multicast */
        #define L2TP            1               /* L2TP Tunneling Protocol */
#endif
        #define PKT_PARSE       1               /* built-in packet parser */
//        #define FIREWALL        1
        #define CLI                     1
        #define MDU                     1
        #define FRELAY          1               /* (AP,FR),1-5-00,frame relay */
        #define DNS_QUERY       1
        #define NAT_OPT         1
        #define RTC             1
        #define N_CONNMGR_EQ_CELL 64 /* Horace move this from cmgrmain.c */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
		#define	CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL -12)
        #define NETWORK_TASK_PRIORITY   (TASK_PRI_NORMAL - 10)
		#define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
		#define N_NETWORK_EQ_CELL 48
		#define N_NETWORK_DQ_CELL 1600
		#define N_TCPOUT_DQ_CELL 10
		#define MAX_NETWORK_COUNT	48
	
	
	#define CBQ 		1
	#define WEB_REDIRECT 	1	/* web redirection - ijang */
	#define EMBEDDED_SVR_CFG	1  /* remote access control -yetseng 08/10/2001 */
	#define MAC_IP_ADDR_VALIDATE	1 /* MAC/IP Address Validation - cchang */
	#define ZEBRA_OSPF	1 /* ZEBRA OSPF - cchang */

#ifdef CBQ
	#define HIRES_TIMER 1
#endif

#ifdef WEB_REDIRECT		/* ijang */
	#define MAX_ACTIVE_TCB 10	/* maximum number of active tcb at the same time */
	#define webEntryMax 4	/* Maximun number of web table entry per index */
#endif
	

#endif /* P1600 */
/*_____ P647W WSR for netgear  _____*/
#ifdef	NETGEAR_P647W
	#define ZYXP		ZYXP_P641
	#define IP_OPTION				1		/* IP protocol */
	#define SPT 					1		/* SPT */
	#define PPP 					1		/* Point-to-Point Protocol */
	#define BCP 					1		/* Bridge Protocol */
	#define SECURE					1		/* Security */
//	#define SNMPD					1		/* SNMP agent deamon */
	#define HDAP					1		/* Host Discovery & Addr Assignment Protocol */
	#define TFTP					1		/* TFTP server */
	#define FTPSERV 				1	    /* FTP server support */
	#define SMT 					1		/* SMT */
	#define PKT_PARSE				1		/* Embedded ZPKTTOOL */
	#define ADJUSTTIME				1		/* ADJUST Time */
	#define BCP						1
	#define MPOA					1
	#define TCP_MSS_ADJUST			1
	#define BRIDGE_ONLY_MANAGEMENT	1
	#define ONE_LAN_BRIDGE		    1
	#define PPPOE			    	1
	#define SMT_IPX					1
	#define IGMP					1	/* IP multicast */
	#define IP_ALIAS				1	/* IP aliasing support */
	#define IPPR					1	/* IPPR */
	#define PHY_HUB_4PORT   		1	/* support KS8995 4 port hub */
	#define QUICK_BRIDGE			1	/* performance inprove for bridge mode */
	#define CALL_SCH				1	/* call schedule for PPPoE */
	#define DDNS					1	/* Dynamic DNS */
    #define DNS_QUERY       		1
	#define SMTP_CLNT				1	/* Enable Mail Client */
	#define SUA_ONLY        		1   /* Support for SUA_ONLY setting */
	#define REMOTE_MANAGE_SETUP		1	/* SMT24_11 Remote Manage Setup enable */
	#define EMBEDDED_SVR_CFG		1	/* Enhance server management */
	#define RANGE_PORT_FORWARDING	1	/* smt15 using range port forwarding */
	#define HTTPD           		1   /* HTTP daemon and GUI */				
	#define RAS_BOOT_CMD_SUPPORT 	1
//	#define ZYCFG_CLNT 				1
	#define NETGEAR					1
	#define StcpDebug				0				/* used to reduce complie warning */
	#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
	#define CONTENT_FILTER_FORWARD_LOG 1

	#define NUM_SUA_ENTRY 			256	/* SUA Entry */
	#define N_NETWORK_EQ_CELL		20
	#define N_NETWORK_DQ_CELL		800
	#define N_TCPOUT_DQ_CELL		10
	#define MAX_NETWORK_COUNT		800
	#define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)


  #ifndef ZYXM
	#define ZYXM		-1
  #endif
#endif /* NETGEAR_P647W */

#ifdef  ZYXEL_P654
        #define XDSL_CHIP		ALCATEL_ADSL
        #define ZYXP            ZYXP_P641
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 800 /* Timothy 0227, from 800 -> 2400 */
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
/*        #define HTTPD           1             */  /* HTTP daemon and GUI */
        #define IGMP            1               /* IP multicast support */
        
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP				1
		#define MPOA			1
		#define SNMPD			1				/* SNMP agent deamon */
        #define PPPOE           1               /* Support PPPOE */
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TFTP            1               /* TFTP server */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */

		#define QUICK_BRIDGE	1	            /* kai test */
		#define MBUF_2K_ENHANCE	1
		#define MBUF_DEBUG      1
		#define BRIDGE_ENHANCE	1
		#define ONE_LAN_BRIDGE	1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define DHCP			1

		#define IP_ALIAS		1		        /* IP aliasing support */
		#define IPPR			1		        /* IPPR */
        #define SUPPORT_POE     1               /* support PPPoE */
        #define CALL_SCH        1               /* call scheduler */
/*      #define VOA             1 */
        #define NAT_OPT         1
        #define RANGE_PORT_FORWARDING  1        
        /*#define VOICEPUMP       1               *//* use voicepump DSP chip */

  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif

/*_____ ZyXEL Prestige P654RA-A1 IAD router _____*/
#ifdef	ZYXEL_P654RA_A1
	#define LOGIN_DEFAULT_USER_NAME "admin"
	#define ZyNOS					1
//	#define XDSL_CHIP				SAMSUNG_ADSL
	#define ZYXP					ZYXP_P641

	#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6 ,21} /* System Object Identifier */
	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
	
	#define IP_OPTION				1		/* IP protocol */
	#define SPT 					1		/* SPT */
	#define PPP 					1		/* Point-to-Point Protocol */
	#define BCP 					1		/* Bridge Protocol */
	#define SECURE					1		/* Security */
	#define SNMPD					1		/* SNMP agent deamon */
	//#define IPX					1		/* IPX protocol */
	#define HDAP					1		/* Host Discovery & Addr Assignment Protocol */
	#define TFTP					1		/* TFTP server */
	#define FTPSERV 				1		/* FTP server support */
	#define SMT 					1		/* SMT */
	#define PKT_PARSE				1		/* Embedded ZPKTTOOL */
	#define BCP 					1
	#define MPOA					1	
	#define TCP_MSS_ADJUST			1
	#define BRIDGE_ONLY_MANAGEMENT	1
	#define ONE_LAN_BRIDGE			1
	#define PPPOE					1
	#define PPPOE_LED				1
	//#define SMT_IPX					1
	#define ONE_LAN_BRIDGE			1
	#define IGMP					1	/* IP multicast */
	#define IP_ALIAS				1	/* IP aliasing support */
	#define IPPR					1	/* IPPR */
	#define PHY_PHYAC101L			1	/* support AC101L PHY */
	#define QUICK_BRIDGE			1	/* performance inprove for bridge mode */
	#define CALL_SCH				1	/* call schedule for PPPoE */
	#define DNS_QUERY				1
	/* #define SUA_ONLY 			1 */			  /* Support for SUA_ONLY setting */
	#define NAT_OPT 				1
	#define HTTPD					1				/* HTTP daemon and GUI */				
	#define DDNS					1
	#define ROMFILE_BACKUP			1
	#define P622RA1_Trunk_Protect	1
	#define PPP_IDLE_TIMEOUT		1

	#define MBUF_2K_ENHANCE 	1
	#define MBUF_DEBUG			1
	#define BRIDGE_ENHANCE		1
	#define UPNP				1
	//#define DISABLE_INTERRUPT_IN_NETWORK_TASK 1

	#define NUM_SUA_ENTRY 256	/* SUA Entry */
	#define RANGE_PORT_FORWARDING	1	   
	#define N_NETWORK_EQ_CELL 20
	#define N_NETWORK_DQ_CELL 800
	#define N_TCPOUT_DQ_CELL 10
	#define MAX_NETWORK_COUNT	800
	#define NETWORK_TASK_PRIORITY (TASK_PRI_NORMAL - 10)
	#define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL - 11) 
	#define SUPPORT_POE 	1				/* support PPPoE */
	#define REMOTE_MANAGE_SETUP 1			/* SMT24_11 Remote Manage Setup enable */	
	#define EMBEDDED_SVR_CFG	1			/* Enhance server management */
	#define TIME_SERVER 	1
	#define SYS_TICK_ADJUST 0
  #if 0
	#define RADIUS		1		/* RADIUS authentication */
	#define L2TP		1		/* L2TP support */
  #endif
  #ifndef ZYXM
	#define ZYXM		-1
  #endif

  #define WAN_BACKUP
  #define WAN_BACKUP_DEBUG	1
  #define DIAL_BACKUP		1
  #define CONSOLE_DULE_MODE 1
  #define TRAFFIC_REDIRECT	1
  #ifdef DIAL_BACKUP
	#define DIAL_OUT_ONLY
  #else
	#define AUX_DEBUG_TOOL
  #endif
  
  #define VOA /* VMoA */
  #ifdef VOA
	#define VOA_TASK
	#define V5_PORT_CTRL //[Chris Yeh 2003.11.5]
    #define V5_BCC //[Chris Yeh 2003.11.5]
  #endif

  #if 1
	#define VP_INTERRUPT_MODE
	#define VPTASK
  #else
	#define VP_POLLING_MODE
  #endif
	#ifndef ARM_SDK
	#define ARM_SDK 	/* fonchi */
	#endif

#endif /* ZYXEL_P654RA_A1 */

/*______________________ ZyXel Prestige P650R Series ______________________________________*/
#if  defined( ZYXEL_P650R ) || defined( ZYXEL_P650ME )
		#define FTP_BUFFER_SIZE		0x186A00L
		#define WEB_OLD_WAN_BACKUP		1		/* For old Traffic Redirect*/

	#if !defined( ZYXEL_P650R_45 )
		#define XDSL_CHIP		ALCATEL_ADSL
	#else
		#define	XDSL_CHIP		GLOBALSPAN_ADSL
	#endif
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

	#if defined( ZYXEL_P650R_11)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 6}		/* System Object Identifier */
	#elif defined( ZYXEL_P650R_13)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 9}		/* System Object Identifier */
	#elif defined( ZYXEL_P650ME_11)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 10}	/* System Object Identifier */
	#elif defined( ZYXEL_P650ME_13)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 11}	/* System Object Identifier */
	#elif defined( ZYXEL_P650R_31)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 5}		/* System Object Identifier */		
	#elif defined( ZYXEL_P650R_33)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 14}		/* System Object Identifier */		
	#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 6}		/* System Object Identifier */
	#endif
        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
	#ifndef ZYXEL_P650ME
		#define IP_ALIAS			1				/* IP aliasing support */
	#endif
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define	DHCP				1
	#if  defined( ZYXEL_P650R_31 ) || defined( ZYXEL_P650R_33 )
		#define	PPPOE_LED			1
//		#define	HALF_BRIDGE			1
	#else
		#define	INTERNAL_CLK_UART	1
	#endif
		#define	WATCHDOG_FOR_DSP	1
		#define	ROMFILE_BACKUP		1
		#define	ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
	#ifndef ZYXEL_P650R_45
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
	#endif
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define TRAFFIC_REDIRECT	1
//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P650R Series */
/*______________________ ZyXel Trend Chip 3160 Series ______________________________________*/
#if  defined( ZYXEL_TC3160 )
	#if !defined( ZYXEL_P650R_45 )
		#define XDSL_CHIP		ALCATEL_ADSL
	#else
		#define	XDSL_CHIP		GLOBALSPAN_ADSL
	#endif
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)      
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
#if 1
		#define DDNS				1				/* Dynamic DNS */
		#define SNMPD					1		/* SNMP agent deamon */
		#define MBUF_DEBUG				1
		#define TCP_MSS_ADJUST			1	/* TCP Maximum Segment Size */
		#define PPPOE			    	1	/* Support PPPOE */
		#define IGMP					1	/* IP multicast */
		#define IP_ALIAS				1	/* IP aliasing support */
		#define IPPR					1	/* IPPR */
		#define DNS_QUERY       		1	/* DNS Query SUPPORT */
		#define PPP_IDLE_TIMEOUT		1
		#define NAT_OPT        			1
		#define RANGE_PORT_FORWARDING	1	/* smt15 using range port forwarding */
		#define SUPPORT_POE     1               /* support PPPoE */
		#define PPPOE_LED			1
#else
		#define BRIDGE_ONLY				1
#endif

		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define	DHCP				1
//	#if  defined( ZYXEL_P650R_31 ) || defined( ZYXEL_P650R_33 )
//		#define	HALF_BRIDGE			1
//	#else
//		#define	INTERNAL_CLK_UART	1
//	#endif
		#define	WATCHDOG_FOR_DSP	1
		#define	ROMFILE_BACKUP		1
		#define	ZyNOS				1
		#define 	EMBEDDED_SVR_CFG	1
		#define CLI_FOR_SMT			1
	#ifndef ZYXEL_P650R_45
		#define REMOTE_MANAGE_SETUP	1
	#endif
		#define ADJUSTTIME			1
		#define SPTGEN				1
		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
//		#define UPNP				1
		#define TRAFFIC_REDIRECT	1
	#ifdef WIRELESS_LAN_SUPPORT
		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_MAC_FILTERING	1		/* wireless LAN Mac filtering */
		#define WLAN_SCAN			1
	#endif
		#define TC_DMT				1		/* TrendChip DMT support*/
		#define CENTRALIZE_LED		1		/* Centralize LED support */
	#ifdef TC_DMT
		#define TC_OEM_VD			"TrendChip"
		#define TC_OEM_PN			"ADSL ATU-R"
	#endif
//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
//		#define CENTRALIZE_LOG		1		/* For Centralized log */
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* ZYXEL_TC3160 */

/*______________________ ZyXel P645R_T Series ______________________________________*/
#if  defined( ZYXEL_P645R_Tx )
	#if !defined( ZYXEL_P650R_45 )
		#define XDSL_CHIP		ALCATEL_ADSL
	#else
		#define	XDSL_CHIP		GLOBALSPAN_ADSL
	#endif
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)      
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)


		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
#if 1
		#define DDNS				1				/* Dynamic DNS */
		#define SNMPD					1		/* SNMP agent deamon */
		#define MBUF_DEBUG				1
		#define TCP_MSS_ADJUST			1	/* TCP Maximum Segment Size */
		#define PPPOE			    	1	/* Support PPPOE */
		#define IGMP					1	/* IP multicast */
		#define IP_ALIAS				1	/* IP aliasing support */
		#define IPPR					1	/* IPPR */
		#define DNS_QUERY       		1	/* DNS Query SUPPORT */
		#define PPP_IDLE_TIMEOUT		1
		#define NAT_OPT        			1
		#define RANGE_PORT_FORWARDING	1	/* smt15 using range port forwarding */
		#define SUPPORT_POE     1               /* support PPPoE */
		#define PPPOE_LED			1
#else
		#define BRIDGE_ONLY				1
#endif

		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define	DHCP				1
//	#if  defined( ZYXEL_P650R_31 ) || defined( ZYXEL_P650R_33 )
		#define	HALF_BRIDGE			1
//	#else
//		#define	INTERNAL_CLK_UART	1
//	#endif
		#define	WATCHDOG_FOR_DSP	1
		#define	ROMFILE_BACKUP		1
		#define	ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
	#ifndef ZYXEL_P650R_45
		#define REMOTE_MANAGE_SETUP	1
	#endif
		#define ADJUSTTIME			1
		#define SPTGEN				1
		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define TRAFFIC_REDIRECT	1
	#ifdef WIRELESS_LAN_SUPPORT
		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_MAC_FILTERING	1		/* wireless LAN Mac filtering */
		#define WLAN_SCAN			1
	#endif
		#define TC_DMT				1		/* TrendChip DMT support*/
//		#define CENTRALIZE_LED		1		/* Centralize LED support */
	#ifdef TC_DMT
		#define TC_OEM_VD			"TrendChip"
		#define TC_OEM_PN			"ADSL ATU-R"
	#endif
//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
//		#define CENTRALIZE_LOG		1		/* For Centralized log */
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* ZYXEL_P645R_Tx Series */

/*______________________ ZyXel P623R_T Series ______________________________________*/
#if  defined( ZYXEL_P623R_Tx )
		#define XDSL_CHIP		ALCATEL_ADSL
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)      
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)
	#if defined( ZYXEL_P623R_T1)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 28}		/* System Object Identifier */
	#elif defined( ZYXEL_P623R_T7)		
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 30}		/* System Object Identifier */
	#endif
        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */


		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
#if 1
		#define DDNS				1				/* Dynamic DNS */
		#define SNMPD					1		/* SNMP agent deamon */
		#define MBUF_DEBUG				1
		#define TCP_MSS_ADJUST			1	/* TCP Maximum Segment Size */
		#define PPPOE			    	1	/* Support PPPOE */
		#define IGMP					1	/* IP multicast */
		#define IP_ALIAS				1	/* IP aliasing support */
		#define IPPR					1	/* IPPR */
		#define DNS_QUERY       		1	/* DNS Query SUPPORT */
		#define PPP_IDLE_TIMEOUT		1
		#define NAT_OPT        			1
		#define RANGE_PORT_FORWARDING	1	/* smt15 using range port forwarding */
		#define SUPPORT_POE     1               /* support PPPoE */
		#define PPPOE_LED			1
#else
		#define BRIDGE_ONLY				1
#endif

		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define	DHCP				1
		#define	HALF_BRIDGE			1
		#define	WATCHDOG_FOR_DSP	1
		#define	ROMFILE_BACKUP		1
		#define	ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define TRAFFIC_REDIRECT	1
	#ifdef WIRELESS_LAN_SUPPORT
		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_MAC_FILTERING	1		/* wireless LAN Mac filtering */
		#define WLAN_SCAN			1
	#endif
		#define TC_DMT				1		/* TrendChip DMT support*/

	#ifdef TC_DMT
		#define TC_OEM_VD			"TrendChip"
		#define TC_OEM_PN			"ADSL ATU-R"
	#endif
//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
//		#define CENTRALIZE_LOG		1		/* For Centralized log */
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* ZYXEL_P623R_Tx Series */

/*______________________ ZyXel Prestige P650H Series ______________________________________*/
#ifdef  ZYXEL_P650H      
		#define DEBUG_FREE_MBUF 0
		#define XDSL_CHIP		ALCATEL_ADSL
        #define ZYXP            ZYXP_P641
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 800 /* Timothy 0227, from 800 -> 2400 */
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

        #define SYSOBJID		{1, 3, 6, 1, 4, 1, 3955, 2, 2, 1}	/* System Object Identifier */
        #define SYSOBJID_LEN	10			/* the number of Digits of System Object Identifier */

        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1              */ /* HTTP daemon and GUI */
        /* #define UPNP			0 */				/* Support UPnP */
        #define IGMP            1               /* IP multicast support */    
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define PPP_IDLE_TIMEOUT	1
        #define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
        #define PPPOE           	1               /* Support PPPOE */
        #define SECURE          	1               /* Security */
        #define SMT             	1               /* SMT */
        #define SPT             	1               /* SPT */
        #define SPTGEN				1
        #define StcpDebug			0               /* used to reduce complie warning */
        #define SUPPORT_DYNAMIC_PORT	1          /* Firewall application support */
        #define TFTP				1               /* TFTP server */
        #define TCP_MSS_ADJUST		1               /* TCP Maximum Segment Size */
        #define DHCP				1
		#define QUICK_BRIDGE		1	            /* kai test */
		#define MBUF_2K_ENHANCE	1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1		        /* IP aliasing support */
		#define IPPR				1		        /* IPPR */
        #define SUPPORT_POE		1               	/* support PPPoE */
        #define CALL_SCH			1               /* call scheduler */
        #define NAT_OPT				1
        #define RANGE_PORT_FORWARDING		1        
        /* #define FIREWALL        0               *//* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE		1	/* Firewall act when time scheduled */
		#define FW_ATTACK_ALERT_PERIOD		1	/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL		1	/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS			1	/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED		1	/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL				1	/* Misc FIREWALL configuration */
	#endif

/*	    #define SUPPORT_DYNAMIC_PORT 1 */       /* Firewall application support */
/*	    #define CONTENT_FILTER	1 */  			/* Content Filter support */
/*		#define CYBER_PATROL	1 */			/* Cyber Patrol List */		
        #define ROMFILE_BACKUP			1		/* Restore default romfile */
        #define CLI                             /* Command Line Interface */        
		#define REMOTE_MANAGE_SETUP		1		/* SMT24_11 Remote Manage Setup enable */
		#define	ZyNOS					1
		#define EMBEDDED_SVR_CFG		1
		#define ADJUSTTIME				1
		#define	INTERNAL_CLK_UART		1
		#define PPPOE_LED				1		/* h/w support PPPoE LED */
//		#define CPU_USE_80MHZ			1
		#define UPNP					1
		#define TRAFFIC_REDIRECT		1	
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif/* P650H Series */

/*______________________ ZyXel Prestige P650HW Series ______________________________________*/
#ifdef  ZYXEL_P650HW      
		#define DEBUG_FREE_MBUF 0
		#define XDSL_CHIP		ALCATEL_ADSL
        #define ZYXP            ZYXP_P641
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 800 /* Timothy 0227, from 800 -> 2400 */
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

        #define SYSOBJID		{1, 3, 6, 1, 4, 1, 3955, 2, 2, 1}	/* System Object Identifier */
        #define SYSOBJID_LEN	10			/* the number of Digits of System Object Identifier */

        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1              */ /* HTTP daemon and GUI */
        #define IGMP            1               /* IP multicast support */    
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define PPP_IDLE_TIMEOUT	1
        #define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
        #define PPPOE           	1               /* Support PPPOE */
        #define SECURE          	1               /* Security */
        #define SMT             	1               /* SMT */
        #define SPT             	1               /* SPT */
        #define SPTGEN				1
        #define StcpDebug			0               /* used to reduce complie warning */
        #define SUPPORT_DYNAMIC_PORT	1           /* Firewall application support */
        #define TFTP				1               /* TFTP server */
        #define TCP_MSS_ADJUST		1               /* TCP Maximum Segment Size */
        #define DHCP				1
		#define QUICK_BRIDGE		1	            /* kai test */
		#define MBUF_2K_ENHANCE	1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1		        /* IP aliasing support */
		#define IPPR				1		        /* IPPR */
        #define SUPPORT_POE		1               /* support PPPoE */
        #define CALL_SCH			1               /* call scheduler */
        #define NAT_OPT				1
        #define RANGE_PORT_FORWARDING		1        
        /* #define FIREWALL        0               *//* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE		1	/* Firewall act when time scheduled */
		#define FW_ATTACK_ALERT_PERIOD		1	/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL		1	/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS			1	/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED		1	/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL				1	/* Misc FIREWALL configuration */
	#endif

/*	    #define SUPPORT_DYNAMIC_PORT 1 */       /* Firewall application support */
/*	    #define CONTENT_FILTER	1 */  			/* Content Filter support */
/*		#define CYBER_PATROL	1 */			/* Cyber Patrol List */		
	
        #define ROMFILE_BACKUP			1		/* Restore default romfile */
        #define CLI                             /* Command Line Interface */        
		#define REMOTE_MANAGE_SETUP		1		/* SMT24_11 Remote Manage Setup enable */
		#define ZyNOS					1
		#define EMBEDDED_SVR_CFG		1
		#define ADJUSTTIME				1
		#define INTERNAL_CLK_UART		1
		#define PPPOE_LED				1		/* h/w support PPPoE LED */
		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define WATCHDOG_FOR_DSP		1
/*		#define WLAN_AP_PLUS_STA		1 	*/
/*		#define STATIC_IP_BY_MAC		1	*/
/*		#define	CLI_FOR_SMT				1	*/
		#define UPNP					1
		#define TRAFFIC_REDIRECT		1
		#define VLAN_TAGGING_BRIDGING		1	/* allow VLAN packets pass through */		
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif/* P650HW Series */

/*______________________ ZyXel Prestige P650H31 Series ______________________________________*/
#ifdef ZYXEL_P650H_31
		#define MULTI_LANGUAGE			1		/* Multi-lingual*/
		#define BW_MGNT 				1		/* Bandwidth Management */
		#ifdef BW_MGNT
		#define BM_NUM_IFACE			9		/* number of interfaces  */
		#define BM_NUM_CLASS			10		/* number of classes */
		#define BM_NUM_FILTER			10		/* number of fitlers */
		#define BM_MAX_DEPTH			5		/* max depth of classes in the tree */
		#endif
		#define XDSL_CHIP		ALCATEL_ADSL
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

	#if defined( ZYXEL_P650H_37)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 18}		/* System Object Identifier */			
	#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 18}		/* System Object Identifier */
	#endif
        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define TRAFFIC_REDIRECT	1
//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1
		#define WATCHDOG_FOR_DSP	1

	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P650H31 Series */


/*______________________ ZyXel Prestige P650HW31 Series ______________________________________*/
#ifdef ZYXEL_P650HW_31
		#define FTP_BUFFER_SIZE		0x1E8000L 
		#define WEB_OLD_WAN_BACKUP		1		/* For old Traffic Redirect*/
		#define MULTI_LANGUAGE			1		/* Multi-lingual*/
		
		#define BW_MGNT 				1		/* Bandwidth Management */
		#ifdef BW_MGNT
		#define BM_NUM_IFACE			10		/* number of interfaces  */
		#define BM_NUM_CLASS			10		/* number of classes */
		#define BM_NUM_FILTER			10		/* number of fitlers */
		#define BM_MAX_DEPTH			5		/* max depth of classes in the tree */
		#endif
		
		#define FIREWALL        1               /* FIREWALL agent deamon */        
		#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#endif   

	    #define CONTENT_FILTER		1			/* Content Filter support */
		#define CYBER_PATROL		1 			/* Cyber Patrol List */

		#define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1

		#define VC_HUNT						1	/*VC auto-hunt*/
		#define VC_HUNT_BY_DATA_CHANN		1


		/*Support 10 VPN tunnels*/
		#define IPSEC				1			/* IPSec-VPN */
		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
		#define FILTER_NETBIOS_BLOCK	1
		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */
		#define NUM_OF_MAX_IPSC_RULE		10 	/* max ipsec rules */ 
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	10	/* max active ipsec rules */
		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */

		#define XDSL_CHIP		ALCATEL_ADSL
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

	#if defined( ZYXEL_P650HW_33)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 16}		/* System Object Identifier */		
	#elif defined( ZYXEL_P650HW_31)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 15}		/* System Object Identifier */		
	#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 15}		/* System Object Identifier */
	#endif
        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
	    #define SUPPORT_DYNAMIC_PORT 1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define TRAFFIC_REDIRECT	1
//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1
		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */		
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define RADIUS			1
		#define IEEE802_1X		1
		#define IEEE802_1X_SMT	1
		#define WLAN_802_1X	1			/* Wireless port supports 802.1x */
		#define WLAN_SCAN		1
		#define WEP_1X_FIX		1
		#define WLAN_PRISM_SUPPORT	1

		#define WLAN_ZD1201_SUPPORT	1
		#define ZD1201_WEP_DELAY	1

		#define LOGIN_DEFAULT_USER_NAME "admin"
//		#define PASSWORD_HIDDEN	1		/* sptgen can't get ppp password(replace by ********) */

	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P650HW31 Series */


/*______________________ ZyXel Prestige P652 Series ______________________________________*/
#ifdef  ZYXEL_P652
        #define XDSL_CHIP		ALCATEL_ADSL
        #define ZYXP            ZYXP_P641
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 800 /* Timothy 0227, from 800 -> 2400 */
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

	#if defined( ZYXEL_P652_11)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 12}		/* System Object Identifier */
	#elif defined( ZYXEL_P652_13)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 13}		/* System Object Identifier */
	#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 12}		/* System Object Identifier */
	#endif
	
        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
	
        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */ 
		#define NUM_OF_MAX_IPSC_RULE		5 	/* max ipsec rules */ 
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	5	/* max active ipsec rules */
		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */

		#define ADJUSTTIME		1				/* ADJUST Time */
        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1               /* HTTP daemon and GUI */
        #define IGMP            1               /* IP multicast support */
        
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP				1
		#define MPOA			1
		#define SNMPD			1				/* SNMP agent deamon */
        #define PPPOE           1               /* Support PPPOE */
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TFTP            1               /* TFTP server */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
        #define DHCP			1
        #define SMTP_CLNT		1				/* Enable Mail Client */        
		#define QUICK_BRIDGE	1	            /* kai test */
		#define MBUF_2K_ENHANCE	1
		#define MBUF_DEBUG      1
		#define BRIDGE_ENHANCE	1
		#define ONE_LAN_BRIDGE	1
		#define BRIDGE_ONLY_MANAGEMENT	1

		#define IP_ALIAS			1			/* IP aliasing support */
		#define IPPR				1			/* IPPR */
        #define SUPPORT_POE			1			/* support PPPoE */
        #define CALL_SCH			1			/* call scheduler */
        #define NAT_OPT				1
        #define RANGE_PORT_FORWARDING	1
	    #define FIREWALL			1			/* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE	 1		/* Firewall act when time scheduled */
//		#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
//		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS	1			/* Bypass accessing router from LAN */
//		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MISC_FIREWALL		1			/* Misc FIREWALL configuration */
	#endif        

	    #define SUPPORT_DYNAMIC_PORT 1			/* Firewall application support */
	    #define CONTENT_FILTER		1			/* Content Filter support */
		#define CYBER_PATROL		1 			/* Cyber Patrol List */
        #define ROMFILE_BACKUP		1			/* Restore default romfile */
        #define CLI								/* Command Line Interface */
        #define UPNP				1
		#define IPSEC				1			/* IPSec-VPN */
		#define IKE_AES_SUPPORT	1               	/* AES Encryption/Decryption */ /* bchung debug */
		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
		#define HIGH_LBN_TASK 		1			/* IPSec rekey LBN task priority use */
		#define FILTER_NETBIOS_BLOCK	1		/* Hard-coded NetBIOS filter */
		#define SPTGEN				1			/* SPTGen support */
		#define REMOTE_MANAGE_SETUP 1			/* Remote Manage Setup support */
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define DIAL_BACKUP 		1			/* Dial Backup */
	#ifdef DIAL_BACKUP
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
////	#define DLBKUP_FEATURE	1				/* Dial Backup (full feature) */
	#else
		#define AUX_DEBUG_TOOL	1				/* Aux port for debug */
	#endif
		#define PPP_IDLE_TIMEOUT 	1
		#define VLAN_TAGGING_BRIDGING 1
		#define PPPOE_LED			1			/* h/w support PPPoE LED */
		#define TRAFFIC_REDIRECT	1	/* For traffic redirect */
		#define CENTRALIZE_LOG		1	/* For Centralized log */
		#define	WATCHDOG_FOR_DSP	1
		#define ZYCNM				1			/* Goalie enable firmware */

		#define SSH_CRYPT_LIBRARY 1
//		#define CERTIFICATE_SUPPORT 1   /* SSH certificate toolkit support *//* bchung debug */
//		#define SSH 1					/* bchung debug */
	#ifdef CERTIFICATE_SUPPORT
		#define SPT_FILE_SYSTEM_CERTIFICATE						1 /* Support CERT SPT file system */
		#define IKE_RSA_SIG_SUPPORT								1 /* Support RSA signature authentication for IKE */
		#define MAX_NUM_OF_MY_CERT								5 /* Maximum number of my certificates */
		#define MAX_NUM_OF_TRUSTED_CA							5 /* Maximum number of trusted CAs */
		#define MAX_NUM_OF_TRUSTED_REMOTE_HOST					5 /* Maximum number of trusted remote hosts */
		#define MAX_NUM_OF_DIRECTORY_SERVICE					5 /* Maximum number of directory services */
		#define SPT_FS_CERT_SIZE								32000 /* The size of certificate file system in spt.dat */
	#endif	
//		#define XAUTH			1			/* XAUTH support */
//		#define RADIUS			1			/* RADIUS support */
//		#define IEEE802_1X		1			/* IEEE 802.1X */
//		#define NEW_IPSEC_LOG	1			/* New IPSec log support */


  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif/* P652R Series */


/*______________________ LinkSys BEFDSR41 Series ______________________________________*/
#ifdef  BEFDSR41
        #define XDSL_CHIP		ALCATEL_ADSL
        #define ZYXP            ZYXP_P641
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 800 /* Timothy 0227, from 800 -> 2400 */
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

        #define SYSOBJID		{1, 3, 6, 1, 4, 1, 3955, 2, 2, 1}	/* System Object Identifier */
        #define SYSOBJID_LEN	10			/* the number of Digits of System Object Identifier */

        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define HTTPD           1               /* HTTP daemon and GUI */
        #define IGMP            1               /* IP multicast support */
        
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP				1
		#define MPOA			1
		#define SNMPD			1				/* SNMP agent deamon */
        #define PPPOE           1               /* Support PPPOE */
        #define SECURE          1               /* Security */
//      #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TFTP            1               /* TFTP server */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
        #define DHCP			1
		#define QUICK_BRIDGE	1	            /* kai test */
		#define MBUF_2K_ENHANCE	1
		#define MBUF_DEBUG      1
		#define BRIDGE_ENHANCE	1
		#define ONE_LAN_BRIDGE	1
		#define BRIDGE_ONLY_MANAGEMENT	1

		#define IP_ALIAS		1		        /* IP aliasing support */
		#define IPPR			1		        /* IPPR */
        #define SUPPORT_POE     1               /* support PPPoE */
        #define CALL_SCH        1               /* call scheduler */
        #define NAT_OPT         1
        #define RANGE_PORT_FORWARDING  1        
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
	#endif        

	    #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
/*	    #define CONTENT_FILTER	1 */  			/* Content Filter support */
/*		#define CYBER_PATROL	1 */			/* Cyber Patrol List */
		#define MISC_FIREWALL   1        
        #define ROMFILE_BACKUP	1				/* Restore default romfile */
        #define CLI                             /* Command Line Interface */
        #define UPNP		    1
		#define REMOTE_MANAGE_SETUP		 1	    /* SMT24_11 Remote Manage Setup enable */
		#define ZyNOS			1
		#define EMBEDDED_SVR_CFG         1
		#define SMTP_CLNT		1				/* Enable Mail Client */
//		#define DMZ_PORT       1
		#define ADJUSTTIME		1
		#define WLAN_MAC_FILTERING 1			/* Wireless LAN MAC filter */
		#define CI_RN_CONF	1					/* CI Commands to Configure Romote Node */
		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed, added by fonchi on 20021022 */
		#define SERVER_SET_BIND_ACL_RULE	1		
		#define	PPPOE_LED			1
		#define	PPP_IDLE_TIMEOUT 		1
		#define INTERNAL_CLK_UART		1
		#define VLAN_TAGGING_BRIDGING 1
		#define WATCHDOG_FOR_DSP	1

  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif/* LinkSys BEFDSR41 Series */

/*______________________ ZyXel Prestige P650M Series ______________________________________*/
#ifdef  ZYXEL_P650M
		#define XDSL_CHIP		ALCATEL_ADSL
        #define ZYXP            ZYXP_P641
       
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 800 /* Timothy 0227, from 800 -> 2400 */
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
    
        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP				1
		#define MPOA			1
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define TFTP            1               /* TFTP server */
		#define QUICK_BRIDGE	1	            /* kai test */
		#define MBUF_2K_ENHANCE	1
		#define MBUF_DEBUG      1
		#define BRIDGE_ENHANCE	1
		#define ONE_LAN_BRIDGE	1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define BRIDGE_ONLY     1
		#define ROMFILE_BACKUP		1
		#define DHCP				1
#ifndef ZD2001
        #define INTERNAL_CLK_UART	1
#endif
        #define WATCHDOG_FOR_DSP	1	/* Solve Alcatel DSP code hang problem */
        #define ZyNOS				1
		#define VLAN_TAGGING_BRIDGING 1

  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif	/* P650M */

/*______________________ ZyXel Prestige P791 Series ______________________________________*/
#ifdef  ZYXEL_P791
        #define XDSL_CHIP		GLOBALSPAN_SDSL
        #define ZYXP            ZYXP_P791
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 1200
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

//        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
#if !(defined(TX39) || defined(ZD2001))
        #define HTTPD           1               /* HTTP daemon and GUI */
#endif       
        #define IGMP            1               /* IP multicast support */
        
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP				1
		#define MPOA			1
		#define SNMPD			1				/* SNMP agent deamon */
        #define PPPOE           1               /* Support PPPOE */
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define NAT_OPT 		1 				/* internet single-user account */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TFTP            1               /* TFTP server */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
        #define SMT_IPX         1               /* SMT IPX Menu */
        #define CALL_SCH        1               /* call scheduler */

        #define BRIDGE_ONLY_MANAGEMENT  1
        #define DHCP			1
		#define QUICK_BRIDGE	1
		#define BRIDGE_FOR_ONE_LAN_ONE_VC	1	/* Should use this to replace QUICK_BRIDGE */
		#define ONE_LAN_BRIDGE	1
		#define MBUF_2K_ENHANCE	1				/* Timothy 0605 */
		#define BRIDGE_ENHANCE	1
		#define HTTPD			1
		
		#define IP_ALIAS		1		        /* IP aliasing support */
		#define IPPR			1		        /* IPPR */
        #define SUPPORT_POE     1               /* support PPPoE */
        #define RANGE_PORT_FORWARDING	1		/* NAT range port setting */
	
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif	/* P791 */

/*______________________ ZyXel Prestige P794RB Series ______________________________________*/
#ifdef  ZYXEL_P794RB
        #define XDSL_CHIP		GLOBALSPAN_SDSL
        #define ZYXP            ZYXP_P791
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 1200
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

//        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
#if !(defined(TX39) || defined(ZD2001))
        #define HTTPD           1               /* HTTP daemon and GUI */
#endif       
        #define IGMP            1               /* IP multicast support */
        
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP				1
		#define MPOA			1
		#define SNMPD			1				/* SNMP agent deamon */
        #define PPPOE           1               /* Support PPPOE */
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define NAT_OPT 		1 				/* internet single-user account */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TFTP            1               /* TFTP server */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
        #define SMT_IPX         1               /* SMT IPX Menu */
        #define CALL_SCH        1               /* call scheduler */

        #define BRIDGE_ONLY_MANAGEMENT  1
        #define DHCP			1
		#define QUICK_BRIDGE	1
		#define BRIDGE_FOR_ONE_LAN_ONE_VC	1	/* Should use this to replace QUICK_BRIDGE */
		#define ONE_LAN_BRIDGE	1
		#define MBUF_2K_ENHANCE	1				/* Timothy 0605 */
		#define BRIDGE_ENHANCE	1
		#define HTTPD			1
		
		#define IP_ALIAS		1		        /* IP aliasing support */
		#define IPPR			1		        /* IPPR */
        #define SUPPORT_POE     1               /* support PPPoE */
        #define RANGE_PORT_FORWARDING	1		/* NAT range port setting */
	
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif	/* P794RB */

/*______________________ ZyXel Prestige P790 Series ______________________________________*/
#ifdef  ZYXEL_P790
        #define XDSL_CHIP		GLOBALSPAN_SDSL
        #define ZYXP            ZYXP_P791
        #define CONN_MGNT_TASK_PRIORITY (TASK_PRI_NORMAL -11)        
        #define MAX_NETWORK_COUNT 1200
        #define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 7, 4}		/* System Object Identifier */
        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */

        #define NUM_SUA_ENTRY 256               /* SUA Entry */
        #define N_NETWORK_DQ_CELL 800
        #define N_NETWORK_EQ_CELL 20
        #define N_TCPOUT_DQ_CELL 10

        #define PPTP_TASK_PRIORITY      (TASK_PRI_NORMAL - 5)
        #define PPTP_TNL_TASK_PRIORITY  (TASK_PRI_NORMAL -12)

        #define DDNS            1               /* Dynamic DNS */
        #define DNS_QUERY       1               /* DNS Query SUPPORT */
        #define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
        #define FTPSERV         1               /* FTP server support */
        #define HDAP            1               /* Host Discovery & Addr Assignment Protocol */
        #define IGMP            1               /* IP multicast support */
        
        #define IP_OPTION       1               /* IP protocol */
        #define PKT_PARSE       1               /* Embedded ZPKTTOOL */
        #define PPP             1               /* Point-to-Point Protocol */
        #define BCP				1
		#define MPOA			1
		#define SNMPD			1				/* SNMP agent deamon */
        #define PPPOE           1               /* Support PPPOE */
        #define SECURE          1               /* Security */
        #define SMT             1               /* SMT */
        #define SPT             1               /* SPT */
        #define StcpDebug       0               /* used to reduce complie warning */
        #define NAT_OPT 		1 				/* internet single-user account */
        #define SUPPORT_DYNAMIC_PORT 1          /* Firewall application support */
        #define TFTP            1               /* TFTP server */
        #define TCP_MSS_ADJUST  1               /* TCP Maximum Segment Size */
//		#define MBUF_DEBUG			1
//        #define SMT_IPX         1               /* SMT IPX Menu */
        #define CALL_SCH        1               /* call scheduler */

        #define BRIDGE_ONLY_MANAGEMENT  1
        #define DHCP			1
		#define QUICK_BRIDGE	1
//		#define BRIDGE_FOR_ONE_LAN_ONE_VC	1	/* Should use this to replace QUICK_BRIDGE */
		#define ONE_LAN_BRIDGE	1
		#define MBUF_2K_ENHANCE	1				/* Timothy 0605 */
		#define BRIDGE_ENHANCE	1
		#define HTTPD			1
		
		#define IP_ALIAS		1		        /* IP aliasing support */
		#define IPPR			1		        /* IPPR */
        #define SUPPORT_POE     1               /* support PPPoE */
        #define RANGE_PORT_FORWARDING	1		/* NAT range port setting */
		#define SPTGEN					1
		#define	ROMFILE_BACKUP		1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define VLAN_TAGGING_BRIDGING 1
  	    #define DIAL_BACKUP		1
	#ifdef DIAL_BACKUP
		#define DIAL_OUT_ONLY	1				/* Dial Out Only */
//	#define DLBKUP_FEATURE	1				/* Dial Backup (full feature) */
	#else
		#define AUX_DEBUG_TOOL	1				/* Aux port for debug */
	#endif
  		#define CONSOLE_DULE_MODE 1
		#define UPNP				1
		#define PPPOE_LED			1
//		#define TRAFFIC_REDIRECT	1
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
	
  #ifndef ZYXM
    #define ZYXM        -1
  #endif
#endif	/* P790 */

/*______________________ ZyXel Prestige P652HW Series ______________________________________*/
#ifdef ZYXEL_P652HW
		#define FTP_BUFFER_SIZE		0x300000L 
		#define XDSL_CHIP		ALCATEL_ADSL
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
	#ifdef ZYXEL_P652HW_31
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 19}		/* System Object Identifier */
	#elif defined(ZYXEL_P652HW_33)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 20}		/* System Object Identifier */
	#elif defined(ZYXEL_P652HW_37)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 26}		/* System Object Identifier */
	#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 19}		/* System Object Identifier */
	#endif

        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

//Obsolete		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
//Obsolete		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
//Obsolete		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		
		#define IPSEC				1			/* IPSec-VPN */
		#define IPSEC_NAT_TRAVERSAL	1		/* IPSec NAT Traversal */
		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
		#define MAX_SA_ITEM 				20 	/* Dynamic/IKE SA */
		#define NUM_OF_MAX_IPSC_RULE		20 	/* max ipsec rules */ 
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	20	/* max active ipsec rules */
		#define SPD_NUM_ENTRY				20 	/* #entry of SPD */
		#define IKE_AES_SUPPORT		1
		#define SSH_CRYPT_LIBRARY	1
//		#define HIGH_LBN_TASK 		1			/* IPSec rekey LBN task priority use */
		// added by Ta-nien 3/20/2003
		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */
		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1

		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1
		
		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */		
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_802_1X			1
		#define WLAN_PRISM_SUPPORT			1
		#define WLAN_SCAN			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define IEEE802_1X			1
		#define WEP_1X_FIX			1
		#define WLAN_ZD1201_SUPPORT	1
		#define ZD1201_WEP_DELAY	1
		//#define DYNAMIC_WEP_KEY 		1			/* support 802.1x key management protocol */
		#define WEP_KEY_MANAGEMENT		1		/* support WEP key management protocol , for WPA feature */
		#define DRIVER_WPA_SUPPORT		1		/* support software WPA feature */
		#define IAPP_SUPPORT		1
		#define IEEE802_1X_SMT		1

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

//		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
  	    #define DIAL_BACKUP		1
  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		
		#define DMZ_PORT		1
		#define VLAN_PORT		1
		#define ANTI_PROB_SET_FLAG	1			/* Anti-probe */
		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
//		#define FW_BW_MGNT		1				/* mark by bchung , don't know what is this */
		//#define DOS_IPSPOOFING_LAN_INGORE 1 	/* Ignore IP spoofing from LAN */
		//#define DOS_PORTSCAN	1				/* Anti-DoS : port scan */
////	#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
////	#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define FIREWALL_USE_SCHEDULE	1		/* Firewall rule based schedule ACL field */
		#define ICSA_CRITERIA	1				/* ICSA Criteria */
		#define ICMP_TOS_HANDLE	1				/* Change ICMP handle to TOS */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define MAX_FW_CUSTOM_PORT	10
		#define FIREWALL_ONE_LOG_PER_PACKET		1		
/* BEGIN - Extended ACL rule number to 50 */
		#define LARGE_ROMFILE	1				/* Romfile usage over than 65535 bytes */
	#ifdef LARGE_ROMFILE
		#define EXTEND_SPF_HDR	1				/*  Extend SPF header support over than 65535 bytes */
	#ifdef EXTEND_SPF_HDR
		#define EXTEND_SPT_SIZE			0x19AB0	/* 0x3ab0(orig) + 0x10000(ext) */
		#define EXTEND_FW_ACL_BUFFER	1		/* Extend FW ACL buffer from 2K to 4K */
		#define FW_ACL_BUFFER_SIZE		(1024*20) /* ZyWALL 70W Support 50K */
		#define MAX_FW_ACL_RULE			100
//		#define EXTEND_FW_ACL_BUFFER_DBG 1
	#endif        
//		#define LARGE_ROMFILE_DBG 1
		#endif
/* END - Extended ACL rule number to 400 */
	#endif

	    #define CONTENT_FILTER	1   			/* Content Filter support */
		/*#define CYBER_PATROL		1*/ 			/* Cyber Patrol List */
	    	/*Add by bjfan from Robin(zw100)  2003/11/17*/
		#ifndef CF_TRUSTED_DOMAIN_NUM
			#define CF_TRUSTED_DOMAIN_NUM 32 /* maximal num = [kHtmlMemorySize / CF_DOMAIN_STRLEN(64)] */
		#endif /* !CF_TRUSTED_DOMAIN_NUM */		
		#ifndef CF_FORBIDDED_DOMAIN_NUM
			#define CF_FORBIDDED_DOMAIN_NUM 32 /* maximal num = [kHtmlMemorySize / CF_DOMAIN_STRLEN(64)] */
		#endif /* !CF_FORBIDDED_DOMAIN_NUM */		
		#ifndef CF_KEYWORD_NUM
			#define CF_KEYWORD_NUM 32 /* maximal num = [kHtmlMemorySize / CF_KEYWORD_STRLEN(32)] */
		#endif /* !CF_KEYWORD_NUM */
		/*End Add*/
	#ifdef	CONTENT_FILTER
		#define CF_FORWARD_LOG_ANY 1			/* Always log content filter */
		#define kRpUserDataSize	65536
	#endif

		#define CENTRALIZE_LOG	1				/* For Centralized log */
        #define CLI                             /* Command Line Interface */
        #define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1
		#define SIP_PASS_DEBUG		1

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EXTENDED_PING	1

		#define BW_MGNT 		1		/* Bandwidth Management */
		#ifdef BW_MGNT
		#define BM_NUM_IFACE	10		/* number of interfaces  */
		#define BM_NUM_CLASS	10		/* number of classes */
		#define BM_NUM_FILTER	10		/* number of fitlers */
		#define BM_MAX_DEPTH	5		/* max depth of classes in the tree */
		#define BM_TRAFFIC_CONDITIONING	1	/* DiffServ with DSCP */
		#endif

		#define NAT_SESSION_TABLE_SIZE		1024	/* number of NAT session table size */
		#define NAT_HASH_TABLE_SIZE			1024	/* number of NAT hash table size */
		#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE-1)
		
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define WEB_ROMFILE_BACKUP	1
		#define MULTI_LANGUAGE	1
		
//		#define WAN_USER_LIMIT	1
//		#define SERVER_SET_BIND_ACL_RULE	1
		//#define UPDATE_BOOTBASE	1
	#ifdef UPDATE_BOOTBASE
		#define BOOTBASEVER		"V1.14"
		#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P652HW Series */

/*______________________ ZyXel Prestige P660HW Series ______________________________________*/
#ifdef ZYXEL_P660HW_61
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#ifdef ZYXEL_P660HW_61
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 34}		/* System Object Identifier */
#elif defined(ZYXEL_P660HW_63)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 36}		/* System Object Identifier */
#elif defined(ZYXEL_P660HW_67)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 37}		/* System Object Identifier */
#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 34}		/* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
	#if 0		// remove from cjalee 2003/12/31
	//#ifndef ZYXEL_P660HW_61_TELEFONICA
		#define IPSEC				1			/* IPSec-VPN */
		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */
		#define NUM_OF_MAX_IPSC_RULE		10 	/* max ipsec rules */ 
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	10	/* max active ipsec rules */
		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */
	#endif
/* hchsu remove ike and ssh */
//		#define IKE_AES_SUPPORT		1
//		#define SSH_CRYPT_LIBRARY	1

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define ILMI_AUTOCFG		1		/* support ILMI autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */

		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1
		
	#ifdef WIRELESS_LAN_SUPPORT
		#define WLAN_TI_SUPPORT		1		/*add by ccshen for VLYNQ interface*/
		
//		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */		
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_802_1X			1
//		#define WLAN_PRISM_SUPPORT			1
//		#define WLAN_SCAN			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define IEEE802_1X			1
		#define IEEE802_1X_SMT		1
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
		#define WEP_1X_FIX			1
//		#define WLAN_ZD1201_SUPPORT	1
		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1
	#endif

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
	#ifndef ZYXEL_P660HW_61_TELEFONICA		
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		//#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		//#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MAX_FW_CUSTOM_PORT	10
		#define ICMP_TOS_HANDLE	1			/* Change ICMP handle to TOS */
		#define FIREWALL_ONE_LOG_PER_PACKET		1	
	#endif

		#define WEB_REDIRECT				1
		#define WEB_REDIRECT_TO_ROUTER	1
//		#define RP_AUTH						1			/* web redirect login page */
		#ifdef WEB_REDIRECT
			#define MAX_ACTIVE_TCB			10			/* maximum number of active tcb at the same time */
			#define webEntryMax				4			/* Maximun number of web table entry per index */
		#endif
	    #define CONTENT_FILTER	1   			/* Content Filter support */
	#endif	    
/*		#define CYBER_PATROL	1 		*/		/* Cyber Patrol List */
		#define CENTRALIZE_LOG	1				/* For Centralized log */
        #define CLI                             /* Command Line Interface */
        #define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1
		
		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
	#ifndef ZYXEL_P660HW_61_TELEFONICA
		#define VC_HUNT						1	/*VC auto-hunt*/
		#ifdef VC_HUNT
		  #define VC_HUNT_BY_DATA_CHANN	1		
		  #define ENCAP_HUNT				1	/* hunt encapsulation */
		#endif
		#define ZERO_CONFIGURE			1
		#define ANY_IP					1

//		#define MULTI_LANGUAGE	1

		#define BW_MGNT 		1		/* Bandwidth Management */
		#ifdef BW_MGNT
			#ifdef WIRELESS_LAN_SUPPORT
				#define BM_NUM_IFACE	10		/* number of interfaces ENET+WLAN+8*MPOA */
			#else
				#define BM_NUM_IFACE	9		/* number of interfaces ENET+8*MPOA */
			#endif /*WIRELESS_LAN_SUPPORT*/
			#define BM_NUM_CLASS	10		/* number of classes */
			#define BM_NUM_FILTER	10		/* number of fitlers */
			#define BM_MAX_DEPTH	5		/* max depth of classes in the tree */
		#endif /*BW_MGNT*/
	#endif

	#ifdef ZYXEL_P660HW_61_TELEFONICA
		#define TELEFONICA_AUTOTRIGGER		1	
		#define TELEFONICA_SPAIN			1
		#define CLI_FOR_SMT					1
	  #ifdef BW_MGNT
		#define BM_TRAFFIC_CONDITIONING	1	/* DiffServ with DSCP */
	  #endif
	#endif

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
		#ifdef EXTEND_SPF_HDR
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0 (48 KBytes) */
	  	#ifndef ZYXEL_P660HW_61_TELEFONICA
		#define EXTEND_FW_ACL_BUFFER	1		/* Extend FW ACL buffer from 2K to 4K */
		#define FW_ACL_BUFFER_SIZE		(1024*20) /* ZyWALL 70W Support 50K */
		#define MAX_FW_ACL_RULE			100
//		#define EXTEND_FW_ACL_BUFFER_DBG 1
		#endif
	  	#endif
	  #endif
	  
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660HW_61 Series */

/*______________________ ZyXel Prestige P662HW Series ______________________________________*/
#ifdef ZYXEL_P662HW_6x
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
		#if defined(ZYXEL_P662HW_61)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 45}		/* System Object Identifier */
		#elif defined(ZYXEL_P662HW_63)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 46}		/* for P662HW-63/67 */
		#elif defined(ZYXEL_P662HW_67)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 47}		
		#endif
        #define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS					1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1

	#if 1 /* IPSEC */
		#define IPSEC				1			/* IPSec-VPN */
		#define IKE_AES_SUPPORT	1
		#define SSH_CRYPT_LIBRARY	1
		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
		#define MAX_SA_ITEM 				20 	/* Dynamic/IKE SA */
		#define NUM_OF_MAX_IPSC_RULE		20 	/* max ipsec rules */ 
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	20	/* max active ipsec rules */
		#define SPD_NUM_ENTRY				20 	/* #entry of SPD */
	#endif
/* hchsu remove ike and ssh */

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define ILMI_AUTOCFG		1		/* support ILMI autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1

		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1
		
		#define WLAN_TI_SUPPORT		1		/*add by ccshen for VLYNQ interface*/
		
//		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */		
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_802_1X			1
//		#define WLAN_PRISM_SUPPORT			1
//		#define WLAN_SCAN			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define IEEE802_1X			1
		#define IEEE802_1X_SMT		1
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
		#define WEP_1X_FIX			1
//		#define WLAN_ZD1201_SUPPORT	1
		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1

		#define STATIC_IP_BY_MAC	1
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1
		#define DIAL_BACKUP			1
  		#define CONSOLE_DULE_MODE 	1
		#define WAN_BACKUP_DEBUG	1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		#define ANTI_PROB_SET_FLAG	1			/* Anti-probe */
		#define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		//#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		//#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MAX_FW_CUSTOM_PORT	10
		#define ICMP_TOS_HANDLE	1			/* Change ICMP handle to TOS */
		#define FIREWALL_ONE_LOG_PER_PACKET		1	
	#endif        
		#define WEB_REDIRECT				1
		#define WEB_REDIRECT_TO_ROUTER	1
		#define RP_AUTH						1			/* web redirect login page */
		#ifdef WEB_REDIRECT
			#define MAX_ACTIVE_TCB			10			/* maximum number of active tcb at the same time */
			#define webEntryMax				4			/* Maximun number of web table entry per index */
		#endif
		#define CONTENT_FILTER	1   			/* Content Filter support */
		#ifdef	CONTENT_FILTER
			#define CF_FORWARD_LOG_ANY 1			/* Always log content filter */
			#define kRpUserDataSize	65536
		#endif
		//#define CBR_FILTER		1			/* Cerberian content filter */
		#ifdef CBR_FILTER
			#define	CERBERIAN_LOCAL_CACHE_SIZE	256
			#define	CBR_MAX_CONNECTION_NUM		20
		#endif		
		#define CENTRALIZE_LOG	1				/* For Centralized log */
		#define CLI                             /* Command Line Interface */
		#define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1		
		#define VC_HUNT						1	/*VC auto-hunt*/
		#ifdef VC_HUNT
		  #define VC_HUNT_BY_DATA_CHANN	1		
		  #define ENCAP_HUNT				1	/* hunt encapsulation */
		#endif
		#define ZERO_CONFIGURE			1
		#define ANY_IP					1
	#if 0	/* anti-virus */
		#define TM_SDK					1		/* Trend Micro SDK support */
		#define DSO						1		/* BEGIN - DSO (Dynamic Shared Objects) */
		#ifdef DSO
		#define ANTI_VIRUS				1
		#define AV_DBG					1
		#endif
	#endif
		#define SW_ADSL_LED_TRAIN		1		/* support adsl training LED to be controled by SW */
		#define SW_AUXWAN_ACT_LED	1		/* AUX WAN led is controlled by software */
		// added by Ta-nien 3/20/2003
		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
		#define MULTI_LANGUAGE	1
		#define BW_MGNT 		1		/* Bandwidth Management */
		#ifdef BW_MGNT
		#define BM_NUM_IFACE	9		/* number of interfaces , (RN 8 is dial backup) */
		#define BM_NUM_CLASS	10		/* number of classes */
		#define BM_NUM_FILTER	10		/* number of fitlers */
		#define BM_MAX_DEPTH	5		/* max depth of classes in the tree */
		#endif

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	#ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
		#ifdef EXTEND_SPF_HDR
		#define EXTEND_SPT_SIZE			0x19AB0	/* 0x3ab0(orig) + 0x10000(ext) */
		#define EXTEND_FW_ACL_BUFFER	1		/* Extend FW ACL buffer from 2K to 4K */
		#define FW_ACL_BUFFER_SIZE		(1024*20) /* ZyWALL 70W Support 50K */
		#define MAX_FW_ACL_RULE			100
//		#define EXTEND_FW_ACL_BUFFER_DBG 1
		#endif        
	#endif
		
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P662HW_6x Series */

/*______________________ ZyXel Prestige P660R Series ______________________________________*/
#ifdef ZYXEL_P660R_61
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#ifdef ZYXEL_P660R_61
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 41}		/* System Object Identifier */
#elif defined(ZYXEL_P660R_63)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 42}		/* System Object Identifier */
#elif defined(ZYXEL_P660R_67)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 43}		/* System Object Identifier */
#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 41}		/* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		
//		#define IPSEC				1			/* IPSec-VPN */
//		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
//		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
//		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */
//		#define NUM_OF_MAX_IPSC_RULE		10 	/* max ipsec rules */ 
//		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	10	/* max active ipsec rules */
//		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */
//		#define IKE_AES_SUPPORT		1
//		#define SSH_CRYPT_LIBRARY	1

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define ILMI_AUTOCFG		1		/* support ILMI autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1
//#ifdef ZYXEL_P660W_67_DT
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
//#endif

		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1
		
		#define PHY_PHYAC101L			1	/* support AC101L PHY */

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		
//        #define CLI                             /* Command Line Interface */
        #define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1
		#define SIP_PASS_DEBUG		1
		
		#define VC_HUNT						1	/*VC auto-hunt*/
		#define VC_HUNT_BY_DATA_CHANN		1		

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660R_61 Series */


/*______________________ ZyXel Prestige P660W Series ______________________________________*/
#ifdef ZYXEL_P660W_61
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#ifdef ZYXEL_P660W_61
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 38}		/* System Object Identifier */
#elif defined(ZYXEL_P660W_63)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 39}		/* System Object Identifier */
#elif defined(ZYXEL_P660W_67)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 40}		/* System Object Identifier */
#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 38}		/* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		
//		#define IPSEC				1			/* IPSec-VPN */
//		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
//		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
//		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */
//		#define NUM_OF_MAX_IPSC_RULE		10 	/* max ipsec rules */ 
//		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	10	/* max active ipsec rules */
//		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */
//		#define IKE_AES_SUPPORT		1
//		#define SSH_CRYPT_LIBRARY	1

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define ILMI_AUTOCFG		1		/* support ILMI autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1
#ifdef ZYXEL_P660W_67_DT
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
#endif

		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1
		
		#define PHY_PHYAC101L			1	/* support AC101L PHY */
		#define WLAN_TI_SUPPORT		1		/*add by ccshen for VLYNQ interface*/
		
//		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */		
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_802_1X			1
//		#define WLAN_PRISM_SUPPORT			1
//		#define WLAN_SCAN			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define IEEE802_1X			1
		#define IEEE802_1X_SMT		1
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
		#define WEP_1X_FIX			1
//		#define WLAN_ZD1201_SUPPORT	1
		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
	#endif        
	    #define CONTENT_FILTER	1   			/* Content Filter support */
		#define CYBER_PATROL	1 				/* Cyber Patrol List */
		#define CENTRALIZE_LOG	1				/* For Centralized log */
        #define CLI                             /* Command Line Interface */
        #define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1
		#define SIP_PASS_DEBUG		1
		
		#define VC_HUNT						1	/*VC auto-hunt*/
		#define VC_HUNT_BY_DATA_CHANN		1		

		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
		#define MULTI_LANGUAGE	1
//		#define BW_MGNT 		1		/* Bandwidth Management */
		#ifdef BW_MGNT
		#define BM_NUM_IFACE	10		/* number of interfaces  */
		#define BM_NUM_CLASS	10		/* number of classes */
		#define BM_NUM_FILTER	10		/* number of fitlers */
		#define BM_MAX_DEPTH	5		/* max depth of classes in the tree */
		#endif

	  	#define LARGE_ROMFILE	1
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0*/
	  #endif

	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660W_61 Series */

/*______________________ ZyXel Prestige P660HW_63 Series ______________________________________*/
#ifdef ZYXEL_P660HW_63
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)

		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 36}		/* System Object Identifier */
       	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
	#if 0		// remove from cjalee 2003/12/31
	//#ifndef ZYXEL_P660HW_63_TELEFONICA
		#define IPSEC				1			/* IPSec-VPN */
		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */
		#define NUM_OF_MAX_IPSC_RULE		10 	/* max ipsec rules */ 
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	10	/* max active ipsec rules */
		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */
	#endif
/* hchsu remove ike and ssh */
//		#define IKE_AES_SUPPORT		1
//		#define SSH_CRYPT_LIBRARY	1

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define ILMI_AUTOCFG		1		/* support ILMI autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
		
		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1
		
		#define WLAN_TI_SUPPORT		1		/*add by ccshen for VLYNQ interface*/
		
//		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */		
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_802_1X			1
//		#define WLAN_PRISM_SUPPORT			1
//		#define WLAN_SCAN			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define IEEE802_1X			1
		#define IEEE802_1X_SMT		1
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
		#define WEP_1X_FIX			1
//		#define WLAN_ZD1201_SUPPORT	1
		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
	#ifndef ZYXEL_P660HW_63_TELEFONICA		
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
	#endif        
		
	    #define CONTENT_FILTER	1   			/* Content Filter support */
	#endif	    
/*		#define CYBER_PATROL	1 		*/		/* Cyber Patrol List */
		#define CENTRALIZE_LOG	1				/* For Centralized log */
        #define CLI                             /* Command Line Interface */
        #define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1
		
		#define VC_HUNT						1	/*VC auto-hunt*/
		#define VC_HUNT_BY_DATA_CHANN		1		

		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
	#ifndef ZYXEL_P660HW_63_TELEFONICA
//		#define MULTI_LANGUAGE	1

//		#define BW_MGNT 		1		/* Bandwidth Management */
		#ifdef BW_MGNT
		#define BM_NUM_IFACE	10		/* number of interfaces  */
		#define BM_NUM_CLASS	10		/* number of classes */
		#define BM_NUM_FILTER	10		/* number of fitlers */
		#define BM_MAX_DEPTH	5		/* max depth of classes in the tree */
		#endif
	#endif

	#ifdef ZYXEL_P660HW_63_TELEFONICA
		#define TELEFONICA_AUTOTRIGGER		1	
		#define TELEFONICA_SPAIN			1
		#define CLI_FOR_SMT					1
	  #ifdef BW_MGNT
		#define BM_TRAFFIC_CONDITIONING	1	/* DiffServ with DSCP */
	  #endif
	#endif

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0*/
	  #endif
		
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660HW_63 Series */


/*______________________ ZyXel Prestige P660M Series ______________________________________*/
#ifdef ZYXEL_P660M_67
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#if 0 //senjore mark for 660M
#ifdef ZYXEL_P660R_61
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 41}		/* System Object Identifier */
#elif defined(ZYXEL_P660R_63)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 42}		/* System Object Identifier */
#elif defined(ZYXEL_P660R_67)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 43}		/* System Object Identifier */
#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 41}		/* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
#endif        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

#if 0 //senjore mark for 660M
		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
#endif
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
#if 0 //senjore mark for 660M
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
#endif
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
#if 0 //senjore mark for 660M
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
#endif
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
#if 0 //senjore mark for 660M
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
#endif
		#define TFTP				1				/* TFTP server */
#if 0 //senjore mark for 660M
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
#endif
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define BRIDGE_ONLY     1 //senjore add for 660M
#if 0 //senjore mark for 660M
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
#endif
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
#if 0 //senjore mark for 660M
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
#endif		
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
//		#define UPNP				1 senjore
		
//		#define IPSEC				1			/* IPSec-VPN */
//		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
//		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
//		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */
//		#define NUM_OF_MAX_IPSC_RULE		10 	/* max ipsec rules */ 
//		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	10	/* max active ipsec rules */
//		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */
//		#define IKE_AES_SUPPORT		1
//		#define SSH_CRYPT_LIBRARY	1

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define ILMI_AUTOCFG		1		/* support ILMI autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
#if 0 //senjore mark for 660M
		#define PPPOE_LED			1
#endif
//#ifdef ZYXEL_P660W_67_DT
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
//#endif

#if 0 //senjore mark for 660M
//senjore		#define PASSWORD_HIDDEN		1

//senjore		#define PPPoE_PASS			1
//senjore		#define PPPoE_PASS_Debug	1
#endif

		#define PHY_PHYAC101L			1	/* support AC101L PHY */

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

#if 0 //senjore mark for 660M
		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
		#define TRAFFIC_REDIRECT	1
#endif
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		
//        #define CLI                             /* Command Line Interface */
#if 0 //senjore mark for 660M
        #define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1
		#define SIP_PASS_DEBUG		1
		
		#define VC_HUNT						1	/*VC auto-hunt*/
		#define VC_HUNT_BY_DATA_CHANN		1		

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660M_67 Series */


/*______________________ ZyXel Prestige P660H Series ______________________________________*/
#ifdef ZYXEL_P660H_61
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#ifdef ZYXEL_P660H_61
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 48}		/* System Object Identifier */
#elif defined(ZYXEL_P660H_63)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 49}		/* System Object Identifier */
#elif defined(ZYXEL_P660H_67)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 50}		/* System Object Identifier */
#else
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 48}		/* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
	#if 0		// remove from cjalee 2003/12/31
	//#ifndef ZYXEL_P660H_61_TELEFONICA
		#define IPSEC				1			/* IPSec-VPN */
		#define ISAKMP				1			/* ISAKMP/Oakley protocol */
		#define FILTER_NETBIOS_BLOCK	1
//		#define FILTER_BROADCAST_BLOCK	1
		#define MAX_SA_ITEM 				10 	/* Dynamic/IKE SA */
		#define NUM_OF_MAX_IPSC_RULE		10 	/* max ipsec rules */ 
		#define NUM_OF_MAX_ACTIVE_IPSC_RULE	10	/* max active ipsec rules */
		#define SPD_NUM_ENTRY				10 	/* #entry of SPD */
	#endif
/* hchsu remove ike and ssh */
//		#define IKE_AES_SUPPORT		1
//		#define SSH_CRYPT_LIBRARY	1

//		#define ADSL_MIB			1		/* support ADSL MIB Group */
//		#define ATM_MIB				1		/* support ATM MIB Group */	/* ccw marked because un-implement at mips platform */
//		#define AUTOCFG				1		/* support autoconfiguration */
//		#define ILMI_AUTOCFG		1		/* support ILMI autoconfiguration */
//		#define COMTREND			1		/* supprot comtrend specify MIB */	/* ccw marked because had bugs */
		#define PPPOE_LED			1
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */

		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1
		
		#define WLAN_TI_SUPPORT		1		/*add by ccshen for VLYNQ interface*/
		
//		#define WLAN_INTERSIL_25_30_SUPPORT 1		/* special flag for wirelress to be changed */		
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define WLAN_802_1X			1
//		#define WLAN_PRISM_SUPPORT			1
//		#define WLAN_SCAN			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define IEEE802_1X			1
		#define IEEE802_1X_SMT		1
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
		#define WEP_1X_FIX			1
//		#define WLAN_ZD1201_SUPPORT	1
		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
	#ifndef ZYXEL_P660H_61_TELEFONICA		
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
	#endif        
		
	    #define CONTENT_FILTER	1   			/* Content Filter support */
	#endif	    
/*		#define CYBER_PATROL	1 		*/		/* Cyber Patrol List */
		#define CENTRALIZE_LOG	1				/* For Centralized log */
        #define CLI                             /* Command Line Interface */
        #define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1
		
		#define VC_HUNT						1	/*VC auto-hunt*/
		#define VC_HUNT_BY_DATA_CHANN		1		

		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
	#ifndef ZYXEL_P660H_61_TELEFONICA
//		#define MULTI_LANGUAGE	1

		#define BW_MGNT 		1		/* Bandwidth Management */
		#ifdef BW_MGNT
		#define BM_NUM_IFACE	10		/* number of interfaces  */
		#define BM_NUM_CLASS	10		/* number of classes */
		#define BM_NUM_FILTER	10		/* number of fitlers */
		#define BM_MAX_DEPTH	5		/* max depth of classes in the tree */
		#endif
	#endif

	#ifdef ZYXEL_P660H_61_TELEFONICA
		#define TELEFONICA_AUTOTRIGGER		1	
		#define TELEFONICA_SPAIN			1
		#define CLI_FOR_SMT					1
	  #ifdef BW_MGNT
		#define BM_TRAFFIC_CONDITIONING	1	/* DiffServ with DSCP */
	  #endif
	#endif

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0*/
	  #endif
		
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660H_61 Series */

/*______________________ ZyXel Prestige P660HW Series ______________________________________*/
#ifdef ZYXEL_P660RU_TX
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#ifdef ZYXEL_P660RU_T1
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 54}		/* System Object Identifier */
#elif ZYXEL_P660RU_T3_T7
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 55}		/* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#ifdef NAT_OPT
			#define NAT_SESSION_TABLE_SIZE		1024	/* number of NAT session table size */
			#define NAT_HASH_TABLE_SIZE			1024	/* number of NAT hash table size */
			#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE-1)
		#endif
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define PPPOE_LED			1
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
		#define SW_ADSL_LED_ACT		1	/* support software ADSL ACT LED display */
		#define SW_USB_LED_ACT		1	/* support software USB ACT LED display */
		#ifdef PPPOE_LED
			#define SW_PPPOE_LED_ACT	1	/* support software PPPOE ACT LED display */
		#endif
		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1

//		#define STATIC_IP_BY_MAC		1
		#define WATCHDOG_FOR_DSP	1

//		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */	
//	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		//#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		//#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MAX_FW_CUSTOM_PORT	10
		#define ICMP_TOS_HANDLE	1			/* Change ICMP handle to TOS */
		#define FIREWALL_ONE_LOG_PER_PACKET		1	
	#endif

		#define WEB_REDIRECT				1
		#define WEB_REDIRECT_TO_ROUTER	1
//		#define RP_AUTH						1			/* web redirect login page */
		#ifdef WEB_REDIRECT
			#define MAX_ACTIVE_TCB			10			/* maximum number of active tcb at the same time */
			#define webEntryMax				4			/* Maximun number of web table entry per index */
		#endif
//	    #define CONTENT_FILTER	1   			/* Content Filter support */
/*		#define CYBER_PATROL	1 		*/		/* Cyber Patrol List */
//		#define CENTRALIZE_LOG	1				/* For Centralized log */
//	        #define CLI                             /* Command Line Interface */
    	  	#define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1
		
		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

//		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
		#define VC_HUNT						1	/*VC auto-hunt*/
		#ifdef VC_HUNT
		  #define VC_HUNT_BY_DATA_CHANN	1		
		  #define ENCAP_HUNT				1	/* hunt encapsulation */
		#endif
		#define ZERO_CONFIGURE			1
		#define ANY_IP					1

//		#define MULTI_LANGUAGE	1

//		#define BW_MGNT 		1		/* Bandwidth Management */
		#ifdef BW_MGNT
			#ifdef WIRELESS_LAN_SUPPORT
				#define BM_NUM_IFACE	10		/* number of interfaces ENET+WLAN+8*MPOA */
			#else
				#define BM_NUM_IFACE	9		/* number of interfaces ENET+8*MPOA */
			#endif /*WIRELESS_LAN_SUPPORT*/
			#define BM_NUM_CLASS	10		/* number of classes */
			#define BM_NUM_FILTER	10		/* number of fitlers */
			#define BM_MAX_DEPTH	5		/* max depth of classes in the tree */
		#endif /*BW_MGNT*/

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
		#ifdef EXTEND_SPF_HDR
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0 (48 KBytes) */
		#define EXTEND_FW_ACL_BUFFER	1		/* Extend FW ACL buffer from 2K to 4K */
		#define FW_ACL_BUFFER_SIZE		(1024*20) /* ZyWALL 70W Support 50K */
		#define MAX_FW_ACL_RULE			100
//		#define EXTEND_FW_ACL_BUFFER_DBG 1
	  	#endif
	  #endif

	  #define TC_DMT				1		/* TrendChip DMT support*/
	#ifdef ZYXEL_P660RU_T3_T7
	  #define ANNEXB				1		/* For ADSL ANNEX B mode */
	#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660HW_61 Series */

/*______________________ ZyXel Prestige P660HW Series ______________________________________*/
#ifdef ZYXEL_P660HW_TX
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#if defined (ZYXEL_P660HW_T1) //keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 58}		/* System Object Identifier *///keil 05/17/2005
#endif
#if defined (ZYXEL_P660HW_T3) || defined (ZYXEL_P660HW_T3_TELENOR)
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 56}		/* System Object Identifier */
#endif
#if defined (ZYXEL_P660HW_T7) //keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 61}		/* System Object Identifier *///keil 06/24
#endif
#if defined (ZYXEL_P660HW_T3_TELENOR)
		#define WAN_REMOVE    1
		#define BWM_REMOVE    1
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define QUICKROUTE                 1
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#ifdef NAT_OPT
			//#define NAT_SESSION_TABLE_SIZE		1024	/* number of NAT session table size */  //keil merge cone nat
			#define NAT_HASH_TABLE_SIZE			1024	/* number of NAT hash table size */
			#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE-1)
		#endif
		//keil merge cone nat start
		#define CONE_NAT_SUPPORT  1           //Cone NAT
      		#define NAT_COMM_SESSION_POOL 1 
	   		#ifdef NAT_COMM_SESSION_POOL  
				#define NAT_COMM_SESSION_POOL_SIZE 3000
	   		#endif
		#define NAT_COMM_IAMT_POOL 1 
	  		 #ifdef NAT_COMM_IAMT_POOL
				#define NAT_COMM_IAMT_POOL_SIZE 10000
	 		  #endif	
		//keil merge cone nat end	

		#define PORT_FORWARD_GUI_ENABLE  1    /*Ross enhance port forward feature*/
		#define PPP_DIAL_DELAY		1	/*Garis Add*/
		#define PPPOE_BUFFER	1
		#define MANUAL_MTU_SUPPORT    1
		
		#define DSLFORUM_CFG  1  
		#ifdef DSLFORUM_CFG
			#define TR069    1   
			#define RP_AUTH		1			/* web redirect login page *//*Garis Add for Rompage4.5*/
		#endif 
	  
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
		#define SW_ADSL_LED_ACT		1	/* support software ADSL ACT LED display */
		#if defined (ZYXEL_P660HW_T1) || defined (ZYXEL_P660HW_T3) || defined (ZYXEL_P660HW_T3_TELENOR)//keil 05/10/2005
			#define INTERNET_LED			1
		#endif
		#if defined (ZYXEL_P660HW_T7)
			#define ARCOR_DSLPPP_LED   1  //keil modify 06/24/2005 to support Arcor LED
		#endif
		#ifdef INTERNET_LED
			#define SW_INTERNET_LED_ACT	1	/* support software INTERNET ACT LED display */
		#else 
			#define PPPOE_LED			1
			#define PPP_LED			1
		#ifdef PPPOE_LED
			#define SW_PPPOE_LED_ACT	1	/* support software PPPOE ACT LED display */
		#endif
		#endif
		#define SW_WLAN_LED_BLINK	1
		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1

		#define STATIC_IP_BY_MAC		1  //keil open the flag 05/10/2005 because P660HW-T3 PS has this feature
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		#define ANTI_PROB_SET_FLAG	1			/* Anti-probe */
	#if defined (ZYXEL_P660HW_T3_TELENOR)
		#define ROMT_FWRULE_SUPPORT   1
	#endif		
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		//#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		//#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MAX_FW_CUSTOM_PORT	10
		#define ICMP_TOS_HANDLE	1			/* Change ICMP handle to TOS */
		#define FIREWALL_ONE_LOG_PER_PACKET		1	
	#endif
		#define UNIFIED_ALG		1               /* Unified Application Layer Gateway */
		#define TEMP_OPEN_SESSION	1
		#define WEB_REDIRECT				1
		#define WEB_REDIRECT_TO_ROUTER	1
//		#define RP_AUTH						1			/* web redirect login page */
		#ifdef WEB_REDIRECT
			#define MAX_ACTIVE_TCB			10			/* maximum number of active tcb at the same time */
			#define webEntryMax				4			/* Maximun number of web table entry per index */
		#endif
	    #define CONTENT_FILTER	1   			/* Content Filter support */
/*		#define CYBER_PATROL	1 		*/		/* Cyber Patrol List */
		#define CENTRALIZE_LOG	1				/* For Centralized log */
	        #define CLI                             /* Command Line Interface */
    	  	#define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1
		
		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
		#define VC_HUNT						1	/*VC auto-hunt*/
		#ifdef VC_HUNT
		  #define VC_HUNT_BY_DATA_CHANN	1		
		  #define ENCAP_HUNT				1	/* hunt encapsulation */
		#endif
		#define ZERO_CONFIGURE			1
		#define ANY_IP					1

//		#define MULTI_LANGUAGE	1

		#define BW_MGNT 		1		/* Bandwidth Management */
	#ifdef BW_MGNT
		#ifdef WIRELESS_LAN_SUPPORT
			#define BM_NUM_IFACE	10		/* number of interfaces ENET+WLAN+8*MPOA */
		#else
			#define BM_NUM_IFACE	9		/* number of interfaces ENET+8*MPOA */
		#endif /*WIRELESS_LAN_SUPPORT*/
		#define BM_NUM_CLASS	30		/* number of classes *///keil modify 05/12/2005 to add GUI MBM wizrad
		#define BM_NUM_FILTER	30		/* number of fitlers *///keil modify 05/12/2005 to add GUI MBM wizrad
		#define BM_MAX_DEPTH	1		/* max depth of classes in the tree */
	#endif /*BW_MGNT*/

	#ifdef BW_MGNT//keil add 05/10/2005
		#define RP_BW_WIZARD    1  /*to open this flag must set BM_NUM_CLASS and BM_NUM_FILTER to >20*/
		//#define BM_TRAFFIC_CONDITIONING	1	/* DiffServ with DSCP */
		//#define BM_TRAFFIC_RECLASSFY 1 /*Remark the exceded packet with DSCP 0 into default queue*/
	#endif

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
		#ifdef EXTEND_SPF_HDR
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0 (48 KBytes) */
		#define EXTEND_FW_ACL_BUFFER	1		/* Extend FW ACL buffer from 2K to 4K */
		#define FW_ACL_BUFFER_SIZE		(1024*20) /* ZyWALL 70W Support 50K */
		#define MAX_FW_ACL_RULE			100
//		#define EXTEND_FW_ACL_BUFFER_DBG 1
	  	#endif
	  #endif
//support ZD1212
#ifdef WIRELESS_LAN_SUPPORT
//		#define WLAN_AP			1		/* I don't know this feature */
//		#define WLAN_BRIDGE		1 		/* I don't know this feature */
		#define Block_WLAN_LAN     1  //keil add 07/20/2005 to block the traffics between WLAN and LAN
		#define TX_TEST	1
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
//		#define WLAN_NO_LOOPBACK	1
//		#define WLAN_BREATHING_LED	1
		#define WLAN_SCAN			1 /*senjore debug 1227*/
		#define WLAN_EXT		1 /* senjore debug 1227 */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define IEEE802_1X			1
		#ifdef IEEE802_1X 	
			#define WLAN_802_1X		1
			#define WEP_1X_FIX 		1
		#endif
//		#define WLAN_PRISM_SUPPORT			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
		#define IEEE802_1X_SMT		1
		#define WLAN_SUPPORT_WPA2	1
		#define CallBack2Stage          1
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
//		#define WLAN_ZD1201_SUPPORT	1
//		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1
#endif
//end to support ZD1212
		
		#define PORT_BASE_POLICY   	1 		/* Triple-play Qos *///keil add triple play feature 05/31/2005

		#define TC_DMT				1		/* TrendChip DMT support*/
	#if defined (ZYXEL_P660HW_T3) || defined (ZYXEL_P660HW_T3_TELENOR) || defined (ZYXEL_P660HW_T7)  //keil 05/10/2005
		  #define ANNEXB				1		/* For ADSL ANNEX B mode */
	#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
	#if defined (ZYXEL_P660HW_T3_TELENOR)
	#define BM_PRI_QUE 1
	#define AUTO_SIP_SERVER_DECT 1
	#define RANDOM_ESSID_AND_WEPKEY  1
	#define RANDOM_ESSID_AND_WEPKEY_DEBUG 1
	#endif

	#define RESET_TEST    1
#endif /* P660HW_TX Series */

//keil add 05/10/2005 start
/*______________________ ZyXel Prestige P660H Series ______________________________________*/
#ifdef ZYXEL_P660H_TX
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#if defined (ZYXEL_P660H_T1) //keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 62}		/* System Object Identifier */
#endif
#if defined (ZYXEL_P660H_T3) || defined (ZYXEL_P660H_T3_TELENOR)||defined(ZYXEL_P660H_T3_TELENORRESIDENTIAL)//keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 59}		/* System Object Identifier *///keil 05/17/2005
#endif
#if defined (ZYXEL_P660H_T7) //keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 56}		/*same as P660HW-T3 ???*/  /* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#ifdef NAT_OPT
			//#define NAT_SESSION_TABLE_SIZE		1024	/* number of NAT session table size */
			#define NAT_HASH_TABLE_SIZE			1024	/* number of NAT hash table size */
			#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE-1)
		#endif
		//keil merge cone nat start
		#define CONE_NAT_SUPPORT  1           //Cone NAT
      		#define NAT_COMM_SESSION_POOL 1 
	   		#ifdef NAT_COMM_SESSION_POOL  
				#define NAT_COMM_SESSION_POOL_SIZE 3000
	   		#endif
		#define NAT_COMM_IAMT_POOL 1 
	  		 #ifdef NAT_COMM_IAMT_POOL
				#define NAT_COMM_IAMT_POOL_SIZE 10000
	 		  #endif	
		//keil merge cone nat end

		#define PORT_FORWARD_GUI_ENABLE  1    /*Ross enhance port forward feature*/
		#define PPP_DIAL_DELAY		1	/*Garis Add*/
		#define PPPOE_BUFFER	1
		#define MANUAL_MTU_SUPPORT    1
		
		#define DSLFORUM_CFG  1  
		#ifdef DSLFORUM_CFG
			#define TR069    1   
			#define RP_AUTH		1			/* web redirect login page *//*Garis Add for Rompage4.5*/
		#endif 
		
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
		#define SW_ADSL_LED_ACT		1	/* support software ADSL ACT LED display */
		#if defined (ZYXEL_P660H_T1) || defined (ZYXEL_P660H_T3)  || defined (ZYXEL_P660H_T3_TELENOR) ||defined(ZYXEL_P660H_T3_TELENORRESIDENTIAL)|| defined (ZYXEL_P660H_T7)//keil 05/10/2005
			#define INTERNET_LED			1
		#endif
		#ifdef INTERNET_LED
			#define SW_INTERNET_LED_ACT	1	/* support software INTERNET ACT LED display */
		#else INTERNET_LED
			#define PPPOE_LED			1
			#define PPP_LED			1
		#ifdef PPPOE_LED
			#define SW_PPPOE_LED_ACT	1	/* support software PPPOE ACT LED display */
		#endif
		#endif
		#define SW_WLAN_LED_BLINK	1
		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1

		#define STATIC_IP_BY_MAC		1  //keil open the flag 05/10/2005 because P660HW-T3 PS has this feature(P660H-T3's feature is the same to P660HW-T3)
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		#define ANTI_PROB_SET_FLAG	1			/* Anti-probe */
	#if defined (ZYXEL_P660H_T3_TELENOR)||defined(ZYXEL_P660H_T3_TELENORRESIDENTIAL)
		#define ROMT_FWRULE_SUPPORT   1
	#endif	
	       #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		//#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		//#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MAX_FW_CUSTOM_PORT	10
		#define ICMP_TOS_HANDLE	1			/* Change ICMP handle to TOS */
		#define FIREWALL_ONE_LOG_PER_PACKET		1	
	#endif
		#define UNIFIED_ALG		1               /* Unified Application Layer Gateway */
		#define TEMP_OPEN_SESSION	1
		#define WEB_REDIRECT				1
		#define WEB_REDIRECT_TO_ROUTER	1
//		#define RP_AUTH						1			/* web redirect login page */
		#ifdef WEB_REDIRECT
			#define MAX_ACTIVE_TCB			10			/* maximum number of active tcb at the same time */
			#define webEntryMax				4			/* Maximun number of web table entry per index */
		#endif
	    #define CONTENT_FILTER	1   			/* Content Filter support */
/*		#define CYBER_PATROL	1 		*/		/* Cyber Patrol List */
		#define CENTRALIZE_LOG	1				/* For Centralized log */
	        #define CLI                             /* Command Line Interface */
    	  	#define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1
		
		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
		#define VC_HUNT						1	/*VC auto-hunt*/
		#ifdef VC_HUNT
		  #define VC_HUNT_BY_DATA_CHANN	1		
		  #define ENCAP_HUNT				1	/* hunt encapsulation */
		#endif
		#define ZERO_CONFIGURE			1
		#define ANY_IP					1

//		#define MULTI_LANGUAGE	1

		#define BW_MGNT 		1		/* Bandwidth Management */
	#ifdef BW_MGNT
		#ifdef WIRELESS_LAN_SUPPORT
			#define BM_NUM_IFACE	10		/* number of interfaces ENET+WLAN+8*MPOA */
		#else
			#define BM_NUM_IFACE	9		/* number of interfaces ENET+8*MPOA */
		#endif /*WIRELESS_LAN_SUPPORT*/
		#define BM_NUM_CLASS	30		/* number of classes *///keil modify 05/12/2005 to add GUI MBM wizrad
		#define BM_NUM_FILTER	30		/* number of fitlers *///keil modify 05/12/2005 to add GUI MBM wizrad
		#define BM_MAX_DEPTH	1		/* max depth of classes in the tree */
	#endif /*BW_MGNT*/

	#ifdef BW_MGNT//keil add 05/10/2005
		#define RP_BW_WIZARD    1  /*to open this flag must set BM_NUM_CLASS and BM_NUM_FILTER to >20*/
		//#define BM_TRAFFIC_CONDITIONING	1	/* DiffServ with DSCP */
		//#define BM_TRAFFIC_RECLASSFY 1 /*Remark the exceded packet with DSCP 0 into default queue*/
	#endif

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
		#ifdef EXTEND_SPF_HDR
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0 (48 KBytes) */
		#define EXTEND_FW_ACL_BUFFER	1		/* Extend FW ACL buffer from 2K to 4K */
		#define FW_ACL_BUFFER_SIZE		(1024*20) /* ZyWALL 70W Support 50K */
		#define MAX_FW_ACL_RULE			100
//		#define EXTEND_FW_ACL_BUFFER_DBG 1
	  	#endif
	  #endif
//support ZD1212
#ifdef WIRELESS_LAN_SUPPORT
//		#define WLAN_AP			1		/* I don't know this feature */
//		#define WLAN_BRIDGE		1 		/* I don't know this feature */
		#define TX_TEST	1
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
//		#define WLAN_NO_LOOPBACK	1
//		#define WLAN_BREATHING_LED	1
		#define WLAN_SCAN			1 /*senjore debug 1227*/
		#define WLAN_EXT		1 /* senjore debug 1227 */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define IEEE802_1X			1
		#ifdef IEEE802_1X 	
			#define WLAN_802_1X		1
			#define WEP_1X_FIX 		1
		#endif
//		#define WLAN_PRISM_SUPPORT			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
		#define IEEE802_1X_SMT		1
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
//		#define WLAN_ZD1201_SUPPORT	1
//		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1
#endif
//end to support ZD1212

		#define PORT_BASE_POLICY   	1 		/* Triple-play Qos *///keil add triple play feature 05/31/2005
		
		#define TC_DMT				1		/* TrendChip DMT support*/
	#if defined (ZYXEL_P660H_T3) || defined (ZYXEL_P660H_T3_TELENOR)||defined(ZYXEL_P660H_T3_TELENORRESIDENTIAL) ||defined (ZYXEL_P660H_T7) //keil 05/10/2005
		  #define ANNEXB				1		/* For ADSL ANNEX B mode */
	#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660H_TX Series */

/*______________________ ZyXel Prestige P660W Series ______________________________________*/
#ifdef ZYXEL_P660W_TX
		#define ZYXP			ZYXP_P641
		#define CONN_MGNT_TASK_PRIORITY	(TASK_PRI_NORMAL - 11)        
		#define MAX_NETWORK_COUNT	800				/* Timothy 0227, from 800 -> 2400 */
		#define NETWORK_TASK_PRIORITY	(TASK_PRI_NORMAL - 10)
#if defined (ZYXEL_P660W_T1) //keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 56}		/* System Object Identifier */
#endif
#if defined (ZYXEL_P660W_T3) //keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 56}		/* System Object Identifier */
#endif
#if defined (ZYXEL_P660W_T7) //keil 05/10/2005
		#define SYSOBJID		{1, 3, 6, 1, 4, 1, 890, 1, 2, 6, 56}		/* System Object Identifier */
#endif
        	#define SYSOBJID_LEN	11			/* the number of Digits of System Object Identifier */
        
		#define NUM_SUA_ENTRY		256				/* SUA Entry */
		#define N_NETWORK_DQ_CELL	800
		#define N_NETWORK_EQ_CELL	20
		#define N_TCPOUT_DQ_CELL	10

		#define PPTP_TASK_PRIORITY		(TASK_PRI_NORMAL - 5)
		#define PPTP_TNL_TASK_PRIORITY	(TASK_PRI_NORMAL -12)

		#define DDNS				1				/* Dynamic DNS */
		#define DNS_QUERY			1				/* DNS Query SUPPORT */
		#define ENABLE_INTERRUP_ON_NETWORK_TASK 1     
		#define FTPSERV				1				/* FTP server support */
		#define HDAP				1				/* Host Discovery & Addr Assignment Protocol */
		#define HTTPD				1				/* HTTP daemon and GUI */
		#define IGMP				1				/* IP multicast support */
		#define IP_OPTION			1				/* IP protocol */
		#define PKT_PARSE			1				/* Embedded ZPKTTOOL */
		#define PPP					1				/* Point-to-Point Protocol */
		#define BCP					1
		#define MPOA				1
		#define SNMPD				1				/* SNMP agent deamon */
		#define PPPOE				1				/* Support PPPOE */
		#define SECURE				1				/* Security */
		#define SMT					1				/* SMT */
		#define SPT					1				/* SPT */
		#define StcpDebug			0				/* used to reduce complie warning */
		#define SUPPORT_DYNAMIC_PORT	1			/* Firewall application support */
		#define TFTP				1				/* TFTP server */
		#define TCP_MSS_ADJUST		1				/* TCP Maximum Segment Size */
		#define QUICK_BRIDGE		1				/* kai test */
		#define MBUF_2K_ENHANCE		1
		#define MBUF_DEBUG			1
		#define BRIDGE_ENHANCE		1
		#define ONE_LAN_BRIDGE		1
		#define BRIDGE_ONLY_MANAGEMENT	1
		#define IP_ALIAS			1				/* IP aliasing support */
		#define IPPR				1				/* IPPR */
		#define SUPPORT_POE			1				/* support PPPoE */
		#define CALL_SCH			1				/* call scheduler */
		/* #define VOA				1 */
		#define NAT_OPT				1
		#ifdef NAT_OPT
			#define NAT_SESSION_TABLE_SIZE		2048	/* number of NAT session table size *///keil modify 05/10/2005
			#define NAT_HASH_TABLE_SIZE			2048	/* number of NAT hash table size *///keil modify 05/10/2005
			#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE-1)
		#endif
		#define RANGE_PORT_FORWARDING	1        
		#define DHCP				1
		#define ROMFILE_BACKUP		1
		#define ZyNOS				1
		#define EMBEDDED_SVR_CFG	1
		#define REMOTE_MANAGE_SETUP	1
		#define PPP_IDLE_TIMEOUT	1
		#define ADJUSTTIME			1
		#define SPTGEN				1
//		#define SMT_HIDE			1
		#define VLAN_TAGGING_BRIDGING 1
		#define UPNP				1
		#define SW_ADSL_LED_TRAIN	1	/* support software ADSL trainning LED display */
		#define SW_ADSL_LED_ACT		1	/* support software ADSL ACT LED display */
		#if defined (ZYXEL_P660W_T1) ||defined (ZYXEL_P660W_T3) ||defined (ZYXEL_P660W_T7) //keil 05/10/2005
			#define INTERNET_LED			1
		#endif
		#ifdef INTERNET_LED
			#define SW_INTERNET_LED_ACT	1	/* support software INTERNET ACT LED display */
		#else INTERNET_LED
			#define PPPOE_LED			1
			#define PPP_LED			1
		#ifdef PPPOE_LED
			#define SW_PPPOE_LED_ACT	1	/* support software PPPOE ACT LED display */
		#endif
		#endif
		#define SW_WLAN_LED_BLINK	1
		#define PASSWORD_HIDDEN		1

		#define PPPoE_PASS			1
		#define PPPoE_PASS_Debug	1

		#define STATIC_IP_BY_MAC		1  //keil open the flag 05/10/2005 because P660W-T1 PS has this feature
		#define WATCHDOG_FOR_DSP	1

		#define CLI_FOR_SMT			1

		#define WAN_BACKUP			1
		#define WAN_BACKUP_DEBUG	1
//  	    #define DIAL_BACKUP		1
//  		#define CONSOLE_DULE_MODE 1
		#define TRAFFIC_REDIRECT	1
		#define DIAL_OUT_ONLY		1			/* Dial Out Only */
		#define ANTI_PROB_SET_FLAG	1			/* Anti-probe */
	    #define FIREWALL        1               /* FIREWALL agent deamon */        
	#ifdef	FIREWALL
		#define FIREWALL_USE_SCHEDULE 1 		/* Firewall act when time scheduled */
		//#define FW_ATTACK_ALERT_PERIOD 1		/* Log attaction every xxx minutes */
		#define FW_CLEAR_LOG_AFTER_MAIL 1		/* Clear firewall log after e-mail notification */
		//#define FW_LAN_FACE_PASS 1				/* Bypass accessing router from LAN */
		#define LOG_TIME_INITIALIZED 1			/* Log time calibration into CF & FW logs */
		#define MISC_FIREWALL	1				/* Misc FIREWALL configuration */
		#define ICSA_CRITERIA		1			/* ICSA Criteria */
		#define MAX_FW_CUSTOM_PORT	10
		#define ICMP_TOS_HANDLE	1			/* Change ICMP handle to TOS */
		#define FIREWALL_ONE_LOG_PER_PACKET		1	
	#endif
		#define UNIFIED_ALG		1               /* Unified Application Layer Gateway */
		#define TEMP_OPEN_SESSION	1
		#define WEB_REDIRECT				1
		#define WEB_REDIRECT_TO_ROUTER	1
//		#define RP_AUTH						1			/* web redirect login page */
		#ifdef WEB_REDIRECT
			#define MAX_ACTIVE_TCB			10			/* maximum number of active tcb at the same time */
			#define webEntryMax				4			/* Maximun number of web table entry per index */
		#endif
	    #define CONTENT_FILTER	1   			/* Content Filter support */
/*		#define CYBER_PATROL	1 		*/		/* Cyber Patrol List */
		#define CENTRALIZE_LOG	1				/* For Centralized log */
	        #define CLI                             /* Command Line Interface */
    	  	#define SMTP_CLNT		1				/* Enable Mail Client */

		#define SIP_PASS_THROUGH	1			/* SIP Pass-through */
		#define SIP_PASS_DEBUG		1
		
		// added by Ta-nien 3/20/2003
//		#define ZX1600			1				/* ZX1600 DES/3DES ASIC support */  //change by chihjia 2003/08/18
//		#define DCBUSWIDTH16	1				/* define bus width between ZD2001 and ZX1600 */

		#define TELNET_CLNT		1
		#define APPL_TRACERT	1
		#define EMB_HELP 		1				/* embedded help */
		#define VC_HUNT						1	/*VC auto-hunt*/
		#ifdef VC_HUNT
		  #define VC_HUNT_BY_DATA_CHANN	1		
		  #define ENCAP_HUNT				1	/* hunt encapsulation */
		#endif
		#define ZERO_CONFIGURE			1
		#define ANY_IP					1

//		#define MULTI_LANGUAGE	1

		#define BW_MGNT 		1		/* Bandwidth Management */
	#ifdef BW_MGNT
		#ifdef WIRELESS_LAN_SUPPORT
			#define BM_NUM_IFACE	10		/* number of interfaces ENET+WLAN+8*MPOA */
		#else
			#define BM_NUM_IFACE	9		/* number of interfaces ENET+8*MPOA */
		#endif /*WIRELESS_LAN_SUPPORT*/
		#define BM_NUM_CLASS	30		/* number of classes *///keil modify 05/10/2005 for P660W-T1 have GUI MBM Wizrad
		#define BM_NUM_FILTER	30		/* number of fitlers *///keil modify 05/10/2005 for P660W-T1 have GUI MBM Wizrad
		#define BM_MAX_DEPTH	1		/* max depth of classes in the tree */
	#endif /*BW_MGNT*/

	#ifdef BW_MGNT//keil add 05/10/2005
		#define RP_BW_WIZARD    1  /*to open this flag must set BM_NUM_CLASS and BM_NUM_FILTER to >20*/
		#define BM_TRAFFIC_CONDITIONING	1	/* DiffServ with DSCP */
		//#define BM_TRAFFIC_RECLASSFY 1 /*Remark the exceded packet with DSCP 0 into default queue*/
	#endif

	  	#define LARGE_ROMFILE	1			/* Add by cjalee for Large Romfile 2003/12/17 */
	  #ifdef LARGE_ROMFILE
	  	#define EXTEND_SPF_HDR	1
		#ifdef EXTEND_SPF_HDR
	  	#define EXTEND_SPT_SIZE	39600		/* 39600 =  9AB0 (48 KBytes) */
		#define EXTEND_FW_ACL_BUFFER	1		/* Extend FW ACL buffer from 2K to 4K */
		#define FW_ACL_BUFFER_SIZE		(1024*20) /* ZyWALL 70W Support 50K */
		#define MAX_FW_ACL_RULE			100
//		#define EXTEND_FW_ACL_BUFFER_DBG 1
	  	#endif
	  #endif
//support ZD1212
#ifdef WIRELESS_LAN_SUPPORT
//		#define WLAN_AP			1		/* I don't know this feature */
//		#define WLAN_BRIDGE		1 		/* I don't know this feature */
		#define TX_TEST	1
		#define WLAN_MAC_FILTERING		1		/* wireless LAN Mac filtering */
//		#define WLAN_NO_LOOPBACK	1
//		#define WLAN_BREATHING_LED	1
		#define WLAN_SCAN			1 /*senjore debug 1227*/
		#define WLAN_EXT		1 /* senjore debug 1227 */
		#define WLAN_FILTER			1		/* support WLAN channel filter */
		#define IEEE802_1X			1
		#ifdef IEEE802_1X 	
			#define WLAN_802_1X		1
			#define WEP_1X_FIX 		1
		#endif
//		#define WLAN_PRISM_SUPPORT			1
        #define RADIUS          	1       /* RADIUS authentication */
		#define WEP_KEY_MANAGEMENT 1		/* support WEP key management protocol */
		#define IEEE802_1X_SMT		1
//		#define DYNAMIC_WEP_KEY		1		/* support 802.1x key management protocol */
//		#define WLAN_ZD1201_SUPPORT	1
//		#define ZD1201_WEP_DELAY	1
		#define WEP_256BIT			1
#endif
//end to support ZD1212

		#define TC_DMT				1		/* TrendChip DMT support*/
	#if defined (ZYXEL_P660W_T3) ||defined (ZYXEL_P660W_T7)  //keil 05/10/2005
		  #define ANNEXB				1		/* For ADSL ANNEX B mode */
	#endif
	#ifndef ZYXM
		#define ZYXM			-1
	#endif
#endif /* P660W_TX Series */
//keil add 05/10/2005 end
/*____________________________________________________________________________*/

#ifdef IP_OPTION 
	#ifndef BRIDGE_ONLY
        #define NAT_OPT 1 /* internet single-user account */
	#endif
#endif

#if 0  //keil merge cone nat
#ifdef NAT_OPT
	#ifndef NAT_HASH_TABLE_SIZE
		#ifndef NAT_SESSION_TABLE_SIZE
			#define NAT_HASH_TABLE_SIZE   256
		#else
			#if (NAT_SESSION_TABLE_SIZE >= 131072)		
				#define NAT_HASH_TABLE_SIZE	  131072
			#elif (NAT_SESSION_TABLE_SIZE >= 65536)		
				#define NAT_HASH_TABLE_SIZE	  65536
			#elif (NAT_SESSION_TABLE_SIZE >= 32768)		
				#define NAT_HASH_TABLE_SIZE   32768
			#elif (NAT_SESSION_TABLE_SIZE >= 16384)		
				#define NAT_HASH_TABLE_SIZE   16384
			#elif (NAT_SESSION_TABLE_SIZE >= 8192) 	
				#define NAT_HASH_TABLE_SIZE   8192
			#elif (NAT_SESSION_TABLE_SIZE >= 4096) 	
				#define NAT_HASH_TABLE_SIZE   4096
			#elif (NAT_SESSION_TABLE_SIZE >= 2048) 	
				#define NAT_HASH_TABLE_SIZE   2048
			#elif (NAT_SESSION_TABLE_SIZE >= 1024) 	
				#define NAT_HASH_TABLE_SIZE   1024
			#elif (NAT_SESSION_TABLE_SIZE >= 512) 	
				#define NAT_HASH_TABLE_SIZE   512
			#elif (NAT_SESSION_TABLE_SIZE >= 256) 	
				#define NAT_HASH_TABLE_SIZE   256
			#else
				#define NAT_HASH_TABLE_SIZE   256
			#endif
		#endif
		
		#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE-1)
	#endif
	
	#ifndef NAT_SERVER_RULE_PER_SET
		#define NAT_SERVER_RULE_PER_SET	12
	#endif
#endif
#else
#ifdef NAT_OPT
	#ifndef NAT_HASH_TABLE_SIZE	  
		#ifdef NAT_COMM_SESSION_POOL
			#if (NAT_COMM_SESSION_POOL_SIZE >= 131072)		
				#define NAT_HASH_TABLE_SIZE   131072
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 65536) 	
				#define NAT_HASH_TABLE_SIZE   65536
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 32768) 	
				#define NAT_HASH_TABLE_SIZE   32768
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 16384) 	
				#define NAT_HASH_TABLE_SIZE   16384
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 8192)	
				#define NAT_HASH_TABLE_SIZE   8192
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 4096)				
				#define NAT_HASH_TABLE_SIZE   4096
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 2048)			
				#define NAT_HASH_TABLE_SIZE   2048
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 1024)	
				#define NAT_HASH_TABLE_SIZE   1024
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 512)	
				#define NAT_HASH_TABLE_SIZE   512
			#elif (NAT_COMM_SESSION_POOL_SIZE >= 256)	
				#define NAT_HASH_TABLE_SIZE   256
			#else
				#define NAT_HASH_TABLE_SIZE   256
			#endif
		#else
			#if (NAT_SESSION_TABLE_SIZE >= 131072)		
				#define NAT_HASH_TABLE_SIZE	  131072
			#elif (NAT_SESSION_TABLE_SIZE >= 65536)		
				#define NAT_HASH_TABLE_SIZE	  65536
			#elif (NAT_SESSION_TABLE_SIZE >= 32768)		
				#define NAT_HASH_TABLE_SIZE   32768
			#elif (NAT_SESSION_TABLE_SIZE >= 16384)		
				#define NAT_HASH_TABLE_SIZE   16384
			#elif (NAT_SESSION_TABLE_SIZE >= 8192) 	
				#define NAT_HASH_TABLE_SIZE   8192
			#elif (NAT_SESSION_TABLE_SIZE >= 4096) 	
				#define NAT_HASH_TABLE_SIZE   4096
			#elif (NAT_SESSION_TABLE_SIZE >= 2048) 	
				#define NAT_HASH_TABLE_SIZE   2048
			#elif (NAT_SESSION_TABLE_SIZE >= 1024) 	
				#define NAT_HASH_TABLE_SIZE   1024
			#elif (NAT_SESSION_TABLE_SIZE >= 512) 	
				#define NAT_HASH_TABLE_SIZE   512
			#elif (NAT_SESSION_TABLE_SIZE >= 256) 	
				#define NAT_HASH_TABLE_SIZE   256
			#else
				#define NAT_HASH_TABLE_SIZE   256
			#endif
		#endif	
		
		#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE-1)
	#endif
	
	#ifndef NAT_SERVER_RULE_PER_SET
		#define NAT_SERVER_RULE_PER_SET	12
	#endif

	#ifndef NAT_ADDRESS_MAPPING_RULE_NUM //for GUI display
		#define NAT_ADDRESS_MAPPING_RULE_NUM 10
	#endif
#endif
#endif

#ifdef UPNP
	#ifndef UPNP_RULE_PER_SET
		#define UPNP_RULE_PER_SET 12
	#endif
#else
	#ifndef UPNP_RULE_PER_SET
		#define UPNP_RULE_PER_SET 0
	#endif
#endif

#ifdef CONTENT_FILTER
	#ifndef CF_TRUSTED_DOMAIN_NUM
		#define CF_TRUSTED_DOMAIN_NUM 32 /* maximal num = [kHtmlMemorySize / CF_DOMAIN_STRLEN(64)] */
	#endif /* !CF_TRUSTED_DOMAIN_NUM */		
	#ifndef CF_FORBIDDED_DOMAIN_NUM
		#define CF_FORBIDDED_DOMAIN_NUM 32 /* maximal num = [kHtmlMemorySize / CF_DOMAIN_STRLEN(64)] */
	#endif /* !CF_FORBIDDED_DOMAIN_NUM */		
	#ifndef CF_KEYWORD_NUM
		#define CF_KEYWORD_NUM 64 /* maximal num = [kHtmlMemorySize / CF_KEYWORD_STRLEN(32)] */
	#endif /* !CF_KEYWORD_NUM */		
#endif /* CONTENT_FILTER */

#ifdef XAUTH	
	#ifndef ISAKMPCFG
		#define ISAKMPCFG	1
	#endif			
	#ifndef RADIUS
		#define RADIUS		1
	#endif
#endif

#ifndef FW_ACL_BUFFER_SIZE
	#define FW_ACL_BUFFER_SIZE		(1024*2) 
#endif

/* #undef  IP_OPTION */
/* #undef  BCP    */
/* #undef  IPX */
/* #undef  ATALK */
/* #undef  PPP */
/* #undef  SPT */
/* #undef  SMT */
/* #undef  SNMPD */

/*_____ Hardware driver options ______________________________________________*/
#define PACKET                  1               /* FTP Software's Packet Driver interface */
#define ISDN                    1               /* ISDN driver code */
#ifndef HAL_API
#define BIG_ENDIAN              1
#define LITTLE_ENDIAN   2
#define ENDIAN          BIG_ENDIAN
#endif

#if (defined(PACKET))
#define ETHER   1                               /* Generic Ethernet code */
#endif


/*_____ test option __________________________________________________________*/
#define __PACKED_STRUCTS__              1
#define __ICE_TRACE__                   0

/* only for the development debug, not release to product 10/25/95 TH */
#ifdef  DEV_DEBUG
#define TEST                                    1
//#define SYS_MBUF_DEBUG                  1//keil delete to merge dmt 3.2.0.4
#define IP_FTP_CLIENT                   1
#define SYS_LOCAL_SOCKET                1
#define IP_FTP_Stresstest               1
#define PPP_BOD_DEBUG                   1
#define TCP_DEBUG               1
#endif

/* Turn mbuf debug on for BETA testers, and turn off when production release */
//#define SYS_MBUF_DEBUG                  1//keil delete to merge dmt 3.2.0.4

/*_____ wan driver option ____________________________________________________*/
#define SYS_NMS                 1
#define SYS_P2864               2
#define SYS_P128                3
#define SYS_PPPC                4
#define SYS_ARMC5K              5
#define SYS_TX39                6
#define SYS_ZD                  7
#define SYS_ETNA_ARM9           8


#ifdef PPTP
        #ifndef GRE
                #define GRE
        #endif
#endif

#ifndef LOGIN_DEFAULT_USER_NAME
#define LOGIN_DEFAULT_USER_NAME		"admin"
#endif

#ifdef BEFDSR41
#ifdef NAT_OPT
	#ifndef NAT_SERVER_RULE_PER_SET
		#define NAT_SERVER_RULE_PER_SET	21
	#endif
#endif

#ifdef UPNP
	#ifndef UPNP_RULE_PER_SET
		#define UPNP_RULE_PER_SET 15
	#endif
#else
	#ifndef UPNP_RULE_PER_SET
		#define UPNP_RULE_PER_SET 0
	#endif
#endif
#endif
#endif  /*_SWITCH_H*/
