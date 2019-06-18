/*
 * Copyright (c) 2019 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*
 * nas_os_int_utils.c
 *
 *  Created on: May 19, 2015
 */

#include "nas_os_int_utils.h"

#include "std_error_codes.h"
#include "std_utils.h"
#include "std_socket_tools.h"
#include "cps_api_interface_types.h"
#include "event_log.h"
#include "std_mac_utils.h"
#include "dell-interface.h"
#include "dell-base-if.h"
#include "dell-base-if-linux.h"
#include "dell-base-interface-common.h"
#include "netlink_tools.h"

#include <net/if_arp.h>
#include <linux/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/stat.h>


#define NAS_MAX_STATS_COUNT     (150) /* Max interface stats count */
#define NAS_STATS_SET_MASK      (0x2)        /* stats sset mask value */

/* Stats set size */
#define NAS_SSET_SIZE           (sizeof(struct ethtool_sset_info) + sizeof(uint_t))

/* Stats strings size */
#define NAS_SECMD_SIZE          (sizeof(struct ethtool_gstrings) + \
                               (NAS_MAX_STATS_COUNT * ETH_GSTRING_LEN))

/* Stats counters size */
#define NAS_STATS_SIZE        (sizeof(struct ethtool_stats) + \
                               (NAS_MAX_STATS_COUNT * sizeof(uint64_t)))

t_std_error nas_os_util_int_mtu_get(const char *name, unsigned int *mtu) {
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock==-1) return STD_ERR(INTERFACE,FAIL,errno);

    t_std_error err = STD_ERR_OK;

    do {
        if (ioctl(sock, SIOCGIFMTU, &ifr) >= 0) {
            *mtu = (ifr.ifr_mtu ) ;
            break;
        }
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-GET",STD_ERR_EXT_PRIV(err));
    } while(0);

    close(sock);
    return err;
}

t_std_error nas_os_util_int_admin_state_get(const char *name, db_interface_state_t *state,
        db_interface_operational_state_t *ostate) {
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock==-1) return STD_ERR(INTERFACE,FAIL,errno);

    t_std_error err = STD_ERR_OK;

    do {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
            *state = (ifr.ifr_flags & IFF_UP) ? DB_ADMIN_STATE_UP : DB_ADMIN_STATE_DN;
            if (ostate!=NULL) {
                *ostate = (ifr.ifr_flags & IFF_RUNNING) ? DB_OPER_STATE_UP : DB_OPER_STATE_DN;
            }
            break;
        }
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-GET",STD_ERR_EXT_PRIV(err));
    } while(0);

    close(sock);
    return err;
}

t_std_error nas_os_util_int_mac_addr_get(const char *name, hal_mac_addr_t *macAddr) {
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock==-1) return STD_ERR(INTERFACE,FAIL,errno);
    t_std_error err = STD_ERR_OK;

    do {
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) >= 0) {
            memcpy(*macAddr, ifr.ifr_hwaddr.sa_data,sizeof(*macAddr));
            break;
        }
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-SET",STD_ERR_EXT_PRIV(err));
    } while (0);
    close(sock);
    return err;
}

t_std_error nas_os_util_int_admin_state_set(const char *name, db_interface_state_t state,
        db_interface_operational_state_t ostate) {
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock==-1) return STD_ERR(INTERFACE,FAIL,errno);

    t_std_error err = STD_ERR_OK;

    do {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
            if (state == DB_ADMIN_STATE_UP) {
                ifr.ifr_flags |= IFF_UP;
            } else {
                ifr.ifr_flags &= ~IFF_UP;
            }
            if (ioctl(sock, SIOCSIFFLAGS, &ifr) >=0) {
                break;
            }
        }
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-SET",STD_ERR_EXT_PRIV(err));
    } while(0);

    close(sock);
    return err;
}

t_std_error nas_os_util_int_mtu_set(const char *name, unsigned int mtu)
{
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock==-1) return STD_ERR(INTERFACE,FAIL,errno);

    t_std_error err = STD_ERR_OK;
    ifr.ifr_mtu = mtu;

    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-SET",errno);
    }
    close(sock);
    return err;
}

t_std_error nas_os_util_int_mac_addr_set(const char *name, hal_mac_addr_t *macAddr) {
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock==-1) return STD_ERR(INTERFACE,FAIL,errno);
    t_std_error err = STD_ERR_OK;

    do {

        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, *macAddr, sizeof(*macAddr));
        if (ioctl(sock, SIOCSIFHWADDR, &ifr) >=0 ) {
            break;
        }
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-SET",STD_ERR_EXT_PRIV(err));
    } while (0);
    close(sock);
    return err;
}

t_std_error nas_os_util_int_flags_get(const char *vrf_name, const char *name, unsigned *flags)
{
    int sock = 0;
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    if (os_sock_create(vrf_name, e_std_sock_INET4, e_std_sock_type_DGRAM, 0, &sock) != STD_ERR_OK) {
        return STD_ERR(INTERFACE,FAIL,errno);
    }

    t_std_error err = STD_ERR_OK;

    do {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
            *flags = ifr.ifr_flags;
            break;
        }
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-GET",STD_ERR_EXT_PRIV(err));
    } while(0);

    close(sock);
    return err;
}

t_std_error nas_os_util_int_get_if_details(const char *name, cps_api_object_t obj)
{
    struct ifreq  ifr;
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);
    const int NAS_LINK_MTU_HDR_SIZE = 32;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock==-1) return STD_ERR(INTERFACE,FAIL,errno);

    t_std_error err = STD_ERR(INTERFACE,FAIL,errno);

    cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME, name, (strlen(name)+1));

    do {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
            cps_api_object_attr_add_u32(obj,BASE_IF_LINUX_IF_INTERFACES_INTERFACE_IF_FLAGS, ifr.ifr_flags);
            cps_api_object_attr_add_u32(obj,IF_INTERFACES_INTERFACE_ENABLED,
                (ifr.ifr_flags & IFF_UP) ? true :false);
        } else break;

        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) >= 0) {
            char buff[40];
            const char *_p = std_mac_to_string((const hal_mac_addr_t *)(ifr.ifr_hwaddr.sa_data),
                                                buff, sizeof(buff));
            cps_api_object_attr_add(obj,DELL_IF_IF_INTERFACES_INTERFACE_PHYS_ADDRESS,_p,strlen(_p)+1);
        } else break;

        if (ioctl(sock, SIOCGIFMTU, &ifr) >= 0) {
            cps_api_object_attr_add_u32(obj, DELL_IF_IF_INTERFACES_INTERFACE_MTU,
                                        (ifr.ifr_mtu  + NAS_LINK_MTU_HDR_SIZE));
        } else break;

        err = STD_ERR_OK;
    } while(0);

    close(sock);
    return err;
}

t_std_error nas_os_util_int_if_index_get(const char *vrf_name, const char *if_name, int *if_index) {

    int sock = 0;
    t_std_error err = STD_ERR(INTERFACE,FAIL,errno);

    if (os_sock_create(vrf_name, e_std_sock_INET4, e_std_sock_type_DGRAM, 0, &sock) != STD_ERR_OK)
        return err;

    struct ifreq  ifr;

    memset(&ifr, 0, sizeof(ifr));

    safestrncpy(ifr.ifr_ifrn.ifrn_name, if_name,
                sizeof(ifr.ifr_ifrn.ifrn_name));

    if (ioctl(sock, SIOCGIFINDEX, &ifr) >= 0) {
        *if_index = (ifr.ifr_ifindex);
        err = STD_ERR_OK;
    }

    close(sock);
    return err;
}

t_std_error nas_os_util_int_if_name_get(const char *vrf_name, int if_index, char *if_name) {

    int sock = 0;
    t_std_error err = STD_ERR(INTERFACE,FAIL,errno);

    if (os_sock_create(vrf_name, e_std_sock_INET4, e_std_sock_type_DGRAM, 0, &sock) != STD_ERR_OK)
        return err;

    struct ifreq  ifr;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_ifindex = if_index;
    if (ioctl(sock, SIOCGIFNAME, &ifr) >= 0) {
        safestrncpy(if_name, ifr.ifr_ifrn.ifrn_name, HAL_IF_NAME_SZ);
        err = STD_ERR_OK;
    }

    close(sock);
    return err;
}

t_std_error nas_os_util_int_oper_status_get (const char *vrf_name, const char *name,
                                             IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_t *oper_state)
{
    int sock = 0;
    t_std_error err = STD_ERR(INTERFACE,FAIL,errno);

    if (os_sock_create(vrf_name, e_std_sock_INET4, e_std_sock_type_DGRAM, 0, &sock) != STD_ERR_OK)
        return err;

    struct ifreq  ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
        *oper_state = ((ifr.ifr_flags & IFF_RUNNING) != 0)
            ? IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_UP
            : IF_INTERFACES_STATE_INTERFACE_OPER_STATUS_DOWN;
        err = STD_ERR_OK;
    }
    close(sock);
    return err;
}
t_std_error nas_os_util_int_ethtool_cmd_data_get (const char *vrf_name, const char *name, ethtool_cmd_data_t *eth_cmd)
{
    struct ifreq         ifr;
    struct ethtool_cmd   ecmd;
    int                  sock;
    t_std_error err = STD_ERR_OK;

    if ((name == NULL) || (eth_cmd == NULL)) return STD_ERR(INTERFACE,FAIL, 0);

    memset(eth_cmd, 0, sizeof(*eth_cmd));
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    if (os_sock_create(vrf_name, e_std_sock_INET4, e_std_sock_type_DGRAM, 0, &sock) != STD_ERR_OK)
        return STD_ERR(INTERFACE,FAIL,errno);

    ecmd.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (caddr_t)&ecmd;

    do {
        if (ioctl(sock, SIOCETHTOOL, &ifr) >= 0) {
            switch (ethtool_cmd_speed(&ecmd)) {
                case SPEED_10 :
                    eth_cmd->speed = BASE_IF_SPEED_10MBPS;
                    break;
                case SPEED_100 :
                    eth_cmd->speed = BASE_IF_SPEED_100MBPS;
                    break;
                case SPEED_1000 :
                    eth_cmd->speed = BASE_IF_SPEED_1GIGE;
                    break;
                default :
                    eth_cmd->speed = BASE_IF_SPEED_AUTO;
                    break;
            }

            switch (ecmd.duplex) {
                case DUPLEX_HALF :
                    eth_cmd->duplex = BASE_CMN_DUPLEX_TYPE_HALF;
                    break;
                case DUPLEX_FULL :
                    eth_cmd->duplex = BASE_CMN_DUPLEX_TYPE_FULL;
                    break;
                case DUPLEX_UNKNOWN :
                default:
                    eth_cmd->duplex = BASE_CMN_DUPLEX_TYPE_AUTO;
                    break;
            }

            switch (ecmd.autoneg) {
                case AUTONEG_DISABLE :
                    eth_cmd->autoneg = false;
                    break;
                case AUTONEG_ENABLE :
                    eth_cmd->autoneg = true;
                    break;
                default:
                    eth_cmd->autoneg = true;
                    break;
            }

            if ((ecmd.supported & SUPPORTED_10baseT_Half)
                    || (ecmd.supported & SUPPORTED_10baseT_Full)) {
                eth_cmd->supported_speed[BASE_IF_SPEED_10MBPS] = true;
            }
            if ((ecmd.supported & SUPPORTED_100baseT_Half)
                    || (ecmd.supported & SUPPORTED_100baseT_Full)) {
                eth_cmd->supported_speed[BASE_IF_SPEED_100MBPS] = true;
            }
            if ((ecmd.supported & SUPPORTED_1000baseT_Half)
                    || (ecmd.supported & SUPPORTED_1000baseT_Full)) {
                 eth_cmd->supported_speed[BASE_IF_SPEED_1GIGE] = true;
            }
        } else {
            err = STD_ERR(INTERFACE,FAIL,errno);
            EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-SET",errno);
        }

    } while (0);

    close(sock);
    return err;
}


static void nas_util_int_sup_adv_speed_populate(struct ethtool_cmd *ecmd, uint_t speed)
{
    int speed_sup, speed_adv;

    speed_sup = speed_adv = 0;

    switch (speed) {
        case SPEED_10000:
            speed_sup |= SUPPORTED_10000baseT_Full;
            speed_adv |= ADVERTISED_10000baseT_Full;
            speed_sup |= SUPPORTED_1000baseT_Half | SUPPORTED_1000baseT_Full;
            speed_adv |= ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full;
            speed_sup |= SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full;
            speed_adv |= ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full;
            speed_sup |= SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full;
            speed_adv |= ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full;
            break;
        case SPEED_1000:
            speed_sup |= SUPPORTED_1000baseT_Half | SUPPORTED_1000baseT_Full;
            speed_adv |= ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full;
            speed_sup |= SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full;
            speed_adv |= ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full;
            speed_sup |= SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full;
            speed_adv |= ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full;
            break;
        case SPEED_100:
            speed_sup |= SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full;
            speed_adv |= ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full;
            speed_sup |= SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full;
            speed_adv |= ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full;
            break;
        case SPEED_10:
            speed_sup |= SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full;
            speed_adv |= ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full;
            break;
        default:
            speed_sup = SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full;
            speed_adv = ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full;
            break;
    }
    ecmd->advertising = ADVERTISED_Autoneg | ADVERTISED_TP | speed_adv;
    ecmd->supported = SUPPORTED_Autoneg | SUPPORTED_TP | speed_sup;
}

t_std_error nas_os_util_int_ethtool_cmd_data_set (const char *vrf_name, const char *name, ethtool_cmd_data_t *eth_cmd)
{
    struct ifreq         ifr;
    struct ethtool_cmd   ecmd;
    int                  sock;
    uint_t               speed, duplex;
    t_std_error          err = STD_ERR_OK;

    if ((name == NULL) || (eth_cmd == NULL)) return STD_ERR(INTERFACE,FAIL, 0);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name,name,sizeof(ifr.ifr_ifrn.ifrn_name)-1);

    if (os_sock_create(vrf_name, e_std_sock_INET4, e_std_sock_type_DGRAM, 0, &sock) != STD_ERR_OK)
        return STD_ERR(INTERFACE,FAIL,errno);

    ecmd.cmd = ETHTOOL_SSET;
    ifr.ifr_data = (caddr_t)&ecmd;

    switch (eth_cmd->speed) {
        case BASE_IF_SPEED_10MBPS:
            speed = SPEED_10;
            break;
        case BASE_IF_SPEED_100MBPS:
            speed = SPEED_100;
            break;
        case BASE_IF_SPEED_1GIGE:
            speed = SPEED_1000;
            break;
        default:
            speed = SPEED_1000;
            break;
    }
    nas_util_int_sup_adv_speed_populate(&ecmd, speed);
    ethtool_cmd_speed_set(&ecmd, speed);

    switch (eth_cmd->duplex) {
        case BASE_CMN_DUPLEX_TYPE_HALF:
            duplex = DUPLEX_HALF;
            break;
        case BASE_CMN_DUPLEX_TYPE_FULL:
        case BASE_CMN_DUPLEX_TYPE_AUTO:
            duplex = DUPLEX_FULL;
            break;
        default:
            duplex = DUPLEX_UNKNOWN;
            break;
    }
    ecmd.duplex = duplex;

    if ((eth_cmd->autoneg) || (eth_cmd->speed == BASE_IF_SPEED_AUTO)) {
        ecmd.autoneg = AUTONEG_ENABLE;
    } else {
        ecmd.autoneg = AUTONEG_DISABLE;
    }

    if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
        err = STD_ERR(INTERFACE,FAIL,errno);
        EV_LOG_ERRNO(ev_log_t_INTERFACE,3,"DB-LINUX-SET",errno);
    }
    close(sock);
    return err;

}


static const struct {
    char     os_name[ETH_GSTRING_LEN];
    char     name[ETH_GSTRING_LEN];
    uint_t   offset;
} stats_map[] = {
    {"rx_packets", "input_packets", offsetof(os_int_stats_t, input_packets)},
    {"rx_bytes", "input_bytes", offsetof(os_int_stats_t, input_bytes)},
    {"rx_multicast", "input_multicast", offsetof(os_int_stats_t, input_multicast)},
    {"rx_errors", "input_errors", offsetof(os_int_stats_t, input_errors)},
    {"rx_errors", "input_discards", offsetof(os_int_stats_t, input_discards)},
    {"tx_packets", "output_packets", offsetof(os_int_stats_t, output_packets)},
    {"tx_bytes", "output_bytes", offsetof(os_int_stats_t, output_bytes)},
    {"tx_multicast", "output_multicast", offsetof(os_int_stats_t, output_multicast)},
    {"tx_errors", "output_errors", offsetof(os_int_stats_t, output_errors)},
    {"tx_tcp_seg_failed", "output_invalid_protocol", offsetof(os_int_stats_t,
                               output_invalid_protocol)}
};

static void os_intf_stats_parse (os_int_stats_t *data,
                struct ethtool_gstrings *secmd, struct ethtool_stats *stats)
{
    uint32_t     count, index, size;
    char         *ptr;

    size = sizeof(stats_map) /sizeof(stats_map[0]);

    for (index = 0, ptr = (char *)&secmd->data[0];
            index < secmd->len && index < stats->n_stats;
            index++, ptr = ptr + ETH_GSTRING_LEN) {
        for (count = 0; count < size; count++) {
            if (strcmp(ptr, stats_map[count].os_name) == 0) {
                *(uint64_t *)(((char *) data) + stats_map[count].offset) =
                    stats->data[index];
                break;
            }
        }
    }
}

t_std_error nas_os_util_int_stats_get (const char *vrf_name, const char *name, os_int_stats_t *data)
{

    struct ifreq               ifr;
    char                       sset_data[NAS_SSET_SIZE];
    char                       secmd_data[NAS_SECMD_SIZE];
    char                       stats_data[NAS_STATS_SIZE];
    struct ethtool_gstrings    *secmd = (struct ethtool_gstrings *)secmd_data;
    struct ethtool_sset_info   *sset_info = (struct ethtool_sset_info *) sset_data;
    struct ethtool_stats       *stats = (struct ethtool_stats *) stats_data;
    int                        sock;
    t_std_error                ret = STD_ERR_OK;

    if (os_sock_create(vrf_name, e_std_sock_INET4, e_std_sock_type_DGRAM, 0, &sock) != STD_ERR_OK)
        return STD_ERR(INTERFACE,FAIL,errno);

    memset(&ifr, 0, sizeof(ifr));
    memset(sset_data, 0, NAS_SSET_SIZE);
    memset(secmd_data, 0, NAS_SECMD_SIZE);
    memset(stats_data, 0, NAS_STATS_SIZE);

    safestrncpy(ifr.ifr_ifrn.ifrn_name, name,
            sizeof(ifr.ifr_ifrn.ifrn_name));

    sset_info->cmd = ETHTOOL_GSSET_INFO;
    sset_info->sset_mask = NAS_STATS_SET_MASK;

    ifr.ifr_data = (caddr_t)sset_info;

    do {
        if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
            ret = STD_ERR(INTERFACE,FAIL,errno);
            break;
        }
        secmd->cmd = ETHTOOL_GSTRINGS;
        secmd->string_set = ETH_SS_STATS;
        ifr.ifr_data = (caddr_t)secmd;

        if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
            ret = STD_ERR(INTERFACE,FAIL,errno);
            break;
        }

        stats->cmd = ETHTOOL_GSTATS;
        ifr.ifr_data = (caddr_t)stats;

        if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
            ret = STD_ERR(INTERFACE,FAIL,errno);
            break;
        }
        os_intf_stats_parse(data, secmd, stats);
    } while (0);

    close(sock);
    return ret;
}

