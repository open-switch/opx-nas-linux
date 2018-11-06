/*
 * Copyright (c) 2016 Dell Inc.
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


#include "dell-base-l2-mac.h"
#include "event_log.h"
#include "std_error_codes.h"
#include "nas_nlmsg.h"
#include "netlink_tools.h"
#include "nas_os_vlan_utils.h"
#include "std_mac_utils.h"
#include "nas_os_if_priv.h"
#include "ds_api_linux_interface.h"
#include "nas_os_if_conversion_utils.h"
#include "std_thread_tools.h"
#include "std_socket_tools.h"

#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <unordered_set>
#include <unordered_map>
#include <string>
#include <mutex>
#include <sstream>
#include <vector>
#include <chrono>


#define NL_MSG_BUFF_LEN 4096
#define MAC_STRING_LEN 20

static std_rw_lock_t static_mac_lock = PTHREAD_RWLOCK_INITIALIZER;
static std_rw_lock_t dynamic_mac_lock = PTHREAD_RWLOCK_INITIALIZER;
static std::mutex _mac_ls_mutex;
static auto _if_mac_learn_state = new std::unordered_map<hal_ifindex_t, bool> ;
static auto _static_mac_list = *new std::unordered_map<std::string, uint32_t>;
static auto _dynamic_mac_list = *new std::unordered_map<std::string, uint32_t>;
static auto _port_to_dynamic_mac_list = *new std::unordered_map<uint32_t,std::unordered_set<std::string>>;
static std_thread_create_param_t nas_os_mac_thread;
static int nas_os_mac_fd[2];


static bool nas_os_mac_read_pending_mac_if(hal_ifindex_t * ifindex) {
    int len = 0;
    do {
        len = read(nas_os_mac_fd[0],ifindex,sizeof(*ifindex));
        if (len<0 && errno==EINTR) break;
    } while (0);
    return len == sizeof(*ifindex);
}

static void nas_os_mac_write_pending_mac_if(hal_ifindex_t *ifindex) {
    int rc = 0;
    if ((rc=write(nas_os_mac_fd[1],ifindex,sizeof(*ifindex)))!=sizeof(*ifindex)) {
       EV_LOGGING(NAS_OS,ERR,"DMAC-OS-PROGRAM","Writing pending mac if failed");
    }
}

static bool nas_os_update_mac_learning(hal_ifindex_t ifindex, bool enable){
    char buff[NL_MSG_BUFF_LEN];
    memset(buff,0,sizeof(nlmsghdr));
    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ifinfomsg *ifmsg = (struct ifinfomsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ifinfomsg));

    nlh->nlmsg_pid = 0 ;
    nlh->nlmsg_seq = 0 ;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_type = RTM_SETLINK ;
    ifmsg->ifi_family = PF_BRIDGE;
    ifmsg->ifi_index = ifindex;

    struct nlattr *mac_attr = nlmsg_nested_start(nlh, sizeof(buff));
    mac_attr->nla_len = 0;
    mac_attr->nla_type = IFLA_PROTINFO | NLA_F_NESTED;
    uint8_t learning = (uint8_t)enable;
    nlmsg_add_attr(nlh,sizeof(buff),IFLA_BRPORT_LEARNING,(void *)&learning,sizeof(uint8_t));
    nlmsg_nested_end(nlh, mac_attr);

    if(nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_INT,nlh, buff, sizeof(buff)) != STD_ERR_OK){
        EV_LOG(ERR,NAS_OS,0,"NAS-L2-MAC","Failed to set mac learn mode to %d for interface %d "
                "in Kernel",enable,ifindex);
        return false;
    }

    EV_LOG(INFO,NAS_OS,3,"NAS-L2-MAC","Set the MAC learning for interface index %d to %d in kernel",ifindex,enable);
    return true;
}

static void nas_mac_split_string(std::string input_str, char delim, std::vector<std::string> & tokenized_strings){
    std::istringstream ss(input_str);
    std::string tokenized_string;
    while(std::getline(ss,tokenized_string,delim)){
        tokenized_strings.push_back(tokenized_string);
    }
    return;
}

bool nas_os_update_tagged_intf_mac_learning(hal_ifindex_t ifindex, hal_ifindex_t vlan_index){
    std::lock_guard<std::mutex> lock(_mac_ls_mutex);
    auto mac_learn_it = _if_mac_learn_state->find(ifindex);
    if(mac_learn_it != _if_mac_learn_state->end()){
        if(!mac_learn_it->second){
            nas_os_update_mac_learning(vlan_index,mac_learn_it->second);
        }
        return true;
    }
    return false;
}

void nas_os_dump_static_macs() {
    for(auto& itr : _static_mac_list)
        EV_LOGGING(NAS_OS,ERR,"L2-MAC-DUMP","Key:%s mbr:%d", itr.first.c_str(), itr.second);
}

extern "C"{

t_std_error nas_os_handle_mac_port_chg(const char *vlan_name, const char *mac_str, hal_mac_addr_t *mac,
                                              uint32_t mbr_if_index, bool is_static) {
    std::string key = std::string(vlan_name)+"."+std::string(mac_str);
    uint32_t cfg_mbr_if_index = mbr_if_index;
    if(is_static){
        std_rw_lock_read_guard l(&static_mac_lock);
        auto itr = _static_mac_list.find(key);
        if (itr == _static_mac_list.end()) {
            EV_LOGGING(NAS_OS,INFO,"L2-MAC-CHG", "Static MAC doesnt exist - MAC VLAN:%s MAC:%s mbr:%d",
                   vlan_name, mac_str, mbr_if_index);
            return STD_ERR_OK;
        }
        if (itr->second == mbr_if_index) {
            EV_LOGGING(NAS_OS,INFO,"L2-MAC-CHG", "Static MAC exists but port doesnt change - MAC VLAN:%s MAC:%s mbr:%d",
                   vlan_name, mac_str, mbr_if_index);
            return STD_ERR_OK;
        }
        EV_LOGGING(NAS_OS,INFO,"L2-MAC-CHG", "Port-chg for MAC VLAN:%s MAC:%s cfg-mbr:%d chg-mbr:%d",
                vlan_name, mac_str, itr->second, mbr_if_index);
        cfg_mbr_if_index = itr->second;
    }

    char buff[NL_MSG_BUFF_LEN];
    memset(buff,0,sizeof(nlmsghdr));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ndmsg *req = (struct ndmsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ndmsg));
    memset(req, 0, sizeof(struct ndmsg));

    req->ndm_family = PF_BRIDGE;
    req->ndm_state =  NUD_REACHABLE;

    if(is_static){
        req->ndm_state |= NUD_NOARP;
    }

    req->ndm_flags = NTF_MASTER;

    req->ndm_ifindex = cfg_mbr_if_index;

    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_APPEND;
    nlh->nlmsg_type = RTM_NEWNEIGH;

    nlmsg_add_attr(nlh,sizeof(buff), NDA_LLADDR, mac, sizeof(hal_mac_addr_t));
    t_std_error rc;
    rc = nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_NEI,nlh, buff, sizeof(buff));
    int err_code = STD_ERR_EXT_PRIV (rc);
    if(err_code != 0){
        EV_LOGGING(NAS_OS,DEBUG,"L2-MAC-CHG", "FAILED Port-chg for MAC VLAN:%s MAC:%s cfg:%d chg-mbr:%d",
                   vlan_name, mac_str, cfg_mbr_if_index, mbr_if_index);
        return STD_ERR(L2MAC,FAIL,0);
    }
    return STD_ERR_OK;
}

/*
 * If port stp state is not forwarding/learning when programming the dynamic macs
 * in kernel fails. To fix it we cache the failed dynamic mac entries and when
 * ports stp state becomes forwarding, we will try to re-pgoram the macs. Below
 * thread reads from socket where ports which have pending macs, its ifindex will be
 * pushed. This thread will keep trying to re-program the pending macs and will clear
 * it from cache when it successfully programs the pending mac.
 */

static void nas_os_mac_main(void){
     hal_ifindex_t ifindex;

     while (true) {
         if (!nas_os_mac_read_pending_mac_if(&ifindex)) {
             continue;
         }
         std_rw_lock_write_guard l(&dynamic_mac_lock);

         auto it = _port_to_dynamic_mac_list.find(ifindex);
         if(it != _port_to_dynamic_mac_list.end()){

             EV_LOGGING(NAS_OS,DEBUG,"DMAC-STG-PROGRAM","Pending MAC count %d for ifindex %d",it->second.size(),ifindex);
             for(auto mac_it = it->second.begin(); mac_it != it->second.end() ; ){
                 std::string key = *mac_it;
                 std::vector<std::string> t_strings;
                 nas_mac_split_string(key,'.',t_strings);
                 if(t_strings.size() != 2) continue;
                 hal_mac_addr_t mac_addr;
                 const char * vlan = t_strings[0].c_str();
                 const char * mac = t_strings[1].c_str();
                 std_string_to_mac(&mac_addr,mac,t_strings[1].length());

                 if(nas_os_handle_mac_port_chg(vlan,mac,&mac_addr,ifindex,false) == STD_ERR_OK){
                     mac_it = it->second.erase(mac_it);
                     _dynamic_mac_list.erase(key);
                 }else{
                     ++mac_it;
                 }
             }

             if(_port_to_dynamic_mac_list[ifindex].size() == 0){
                 _port_to_dynamic_mac_list.erase(ifindex);
             }
         }
     }
}

t_std_error nas_os_mac_add_pending_mac_if_event(hal_ifindex_t ifindex){
    std_rw_lock_read_guard l(&dynamic_mac_lock);
    auto it = _port_to_dynamic_mac_list.find(ifindex);
    if(it != _port_to_dynamic_mac_list.end()){
        nas_os_mac_write_pending_mac_if(&ifindex);
    }
    return STD_ERR_OK;
}


t_std_error nas_os_mac_update_entry(cps_api_object_t obj){

    cps_api_object_attr_t ifindex_attr = cps_api_object_attr_get(obj,BASE_MAC_TABLE_IFINDEX);
    cps_api_object_attr_t mac_attr = cps_api_object_attr_get(obj,BASE_MAC_TABLE_MAC_ADDRESS);
    cps_api_object_attr_t static_attr = cps_api_object_attr_get(obj,BASE_MAC_TABLE_STATIC);
    cps_api_object_attr_t vlan_attr = cps_api_object_attr_get(obj,BASE_MAC_TABLE_VLAN);
    cps_api_object_attr_t ifname_attr = cps_api_object_attr_get(obj,BASE_MAC_TABLE_IFNAME);
    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));

    if(ifindex_attr == NULL ||  mac_attr == NULL || vlan_attr == NULL || ifname_attr == NULL){
        EV_LOG(ERR,NAS_OS,0,"NAS-OS-MAC","Ifindex/MAC/VLAN Missing for creating/updating MAC"
            "Entry in the kernel bridge");
        return STD_ERR(L2MAC,PARAM,0);
    }

    char buff[NL_MSG_BUFF_LEN];
    memset(buff,0,sizeof(nlmsghdr));

    struct nlmsghdr *nlh = (struct nlmsghdr *) nlmsg_reserve((struct nlmsghdr *)buff,sizeof(buff),sizeof(struct nlmsghdr));
    struct ndmsg *req = (struct ndmsg *) nlmsg_reserve(nlh,sizeof(buff),sizeof(struct ndmsg));

    bool is_static = false;
    if(static_attr){
        is_static = cps_api_object_attr_data_u32(static_attr);
    }
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    std::string s;
    if(op == cps_api_oper_CREATE){
        nlh->nlmsg_flags |=   NLM_F_CREATE | (is_static ? NLM_F_APPEND : NLM_F_EXCL) ;
        nlh->nlmsg_type = RTM_NEWNEIGH ;
        s = "create";
    }else if (op == cps_api_oper_SET){
        nlh->nlmsg_flags |=   NLM_F_CREATE | NLM_F_APPEND ;
        nlh->nlmsg_type = RTM_NEWNEIGH ;
        s = "set";
    }else if(op == cps_api_oper_DELETE){
        nlh->nlmsg_type = RTM_DELNEIGH ;
        s = "delete";

    }else{
        EV_LOG(ERR,NAS_OS,0,"NAS-L2-MAC","Invalid/No operation passed when configuring MAC "
                "entry in the kernel");
        return STD_ERR(L2MAC,PARAM,0);
    }

    req->ndm_family = PF_BRIDGE;
    req->ndm_state =  NUD_REACHABLE;

    if(is_static){
        req->ndm_state |= NUD_NOARP;
    }
    req->ndm_flags = NTF_MASTER;

    hal_vlan_id_t vid = cps_api_object_attr_data_u16(vlan_attr);
    hal_ifindex_t ifindex = cps_api_object_attr_data_u32(ifindex_attr);

    if(ifname_attr){
        char * intf_name = (char *)cps_api_object_attr_data_bin(ifname_attr);
        char vlan_intf_name[HAL_IF_NAME_SZ+1];
        nas_os_get_vlan_if_name(intf_name,cps_api_object_attr_len(ifname_attr),vid,vlan_intf_name);
        get_tagged_intf_index_from_name(vlan_intf_name,ifindex);
    }

    req->ndm_ifindex = ifindex;

    nlmsg_add_attr(nlh,sizeof(buff),NDA_LLADDR,(void *)cps_api_object_attr_data_bin(mac_attr),sizeof(hal_mac_addr_t));
    hal_mac_addr_t *mac_addr = (hal_mac_addr_t*)cps_api_object_attr_data_bin(mac_attr);
    char mac_buff[MAC_STRING_LEN];
    char vlan_name[HAL_IF_NAME_SZ+1];
    snprintf(vlan_name, HAL_IF_NAME_SZ, "br%d", vid);
    std_mac_to_string(mac_addr,mac_buff,sizeof(mac_buff));
    std::string key = std::string(vlan_name)+"."+std::string(mac_buff);
    EV_LOGGING(NAS_OS,INFO,"NAS-L2-MAC","Op:%s MAC:%s VLAN:%s Key:%s mbr:%d",
                    ((op == cps_api_oper_DELETE) ? "Del" : "Add/Set"), mac_buff, vlan_name, key.c_str(), ifindex);
    if (is_static) {
        /*
         * In case of static mac, when mac is programmed in the kernel expectation is that mac
         * will not move since it is programmed as static. However, kernel moves the mac when
         * same mac is learned on a different interface. To prevent this application programmed
         * static macs are cached and when we get a mac move notification from kernel we check this
         * cache and re-program the mac to its correct interface
         */
        std_rw_lock_write_guard l(&static_mac_lock);

        if(op == cps_api_oper_DELETE) {
            auto itr = _static_mac_list.find(key);
            if (itr != _static_mac_list.end()) {
                _static_mac_list.erase(itr);
            }
        } else {
            _static_mac_list[key] = ifindex;
        }
    }

    t_std_error rc;
    rc = nl_do_set_request(NL_DEFAULT_VRF_NAME, nas_nl_sock_T_NEI,nlh, buff, sizeof(buff));
    int err_code = STD_ERR_EXT_PRIV (rc);
    if(err_code != 0){
        EV_LOGGING(NAS_OS,DEBUG,"NAS-L2-MAC","Failed to %s mac address entry %s for Interface %d "
                "with cps operation %d in Kernel",s.c_str(),std_mac_to_string(mac_addr,mac_buff,sizeof(mac_buff)),
                req->ndm_ifindex,op);

        if(!is_static){
            /*
             * When mac programmed to kernel is dynamic, kernel will reject the mac programming
             * if stp state of the interface the mac being programmed to is not learning or forwarding.
             * In this case cache the failed dynamic mac and when the interface becomes forwarding in kernel
             * and we get a netlink notification re-program the mac in the kernel.
             */
             std_rw_lock_write_guard l(&dynamic_mac_lock);

             if(op == cps_api_oper_DELETE || op == cps_api_oper_SET) {
                 auto itr = _dynamic_mac_list.find(key);
                 if (itr != _dynamic_mac_list.end()) {
                     _port_to_dynamic_mac_list[itr->second].erase(key);
                     _dynamic_mac_list.erase(itr);
                 }
             }

             if(op != cps_api_oper_DELETE){
                 _dynamic_mac_list[key] = ifindex;
                 _port_to_dynamic_mac_list[ifindex].insert(key);
             }
        }
        return STD_ERR_OK;
    }
    EV_LOGGING(NAS_OS,INFO,"NAS-L2-MAC","%sd mac address entry %s for Interface %d with"
            "cps operation %d in Kernel",s.c_str(),std_mac_to_string(mac_addr,mac_buff,sizeof(mac_buff)),
            req->ndm_ifindex,op);
    return STD_ERR_OK;
}

}


extern "C"{

t_std_error nas_os_mac_change_learning(hal_ifindex_t ifindex,bool enable){

    nas_os_update_mac_learning(ifindex,enable);

    std::lock_guard<std::mutex> lock(_mac_ls_mutex);
    auto it = _if_mac_learn_state->find(ifindex);
    if(it == _if_mac_learn_state->end()){
        if(!enable){
        _if_mac_learn_state->insert({ifindex,enable});
        }else{
            return STD_ERR_OK;
        }
    }else{
        it->second = enable;
    }


    std::unordered_set<hal_ifindex_t> _intf_list;
    if (get_tagged_intf_list(ifindex, _intf_list)){
        for (auto it : _intf_list){
            nas_os_update_mac_learning(it,enable);
        }
    }

    if(enable){
        _if_mac_learn_state->erase(ifindex);
    }

    return STD_ERR_OK;

}

bool nas_os_mac_get_learning(hal_ifindex_t ifindex) {

    std::lock_guard<std::mutex> lock(_mac_ls_mutex);
    auto it = _if_mac_learn_state->find(ifindex);
    if(it == _if_mac_learn_state->end()){
        return true;
    }

    return it->second;
}

t_std_error nas_os_mac_init(){
    t_std_error rc = STD_ERR_OK;
    e_std_soket_type_t domain = e_std_sock_UNIX;
    if (( rc = std_sock_create_pair(domain, true, nas_os_mac_fd)) != STD_ERR_OK) {
        EV_LOGGING(NAS_OS,ERR,"NAS-OS-MAC-INIT","Failed to create socketpair for ndi events");
        return STD_ERR(NPU,FAIL,0);
    }
    std_thread_init_struct(&nas_os_mac_thread);
    nas_os_mac_thread.name = "nas-os-mac-thr";
    nas_os_mac_thread.thread_function = (std_thread_function_t)nas_os_mac_main;
    if ((rc = std_thread_create(&nas_os_mac_thread))!=STD_ERR_OK) {
        EV_LOGGING(NAS_OS,ERR,"NAS-OS-MAC-INIT","Failed to create the nas os mac thread");
        return rc;
    }

    return rc;
}

}
