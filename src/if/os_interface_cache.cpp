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

/*!
 * \file   os_interface_cache.cpp
 */

#include "os_if_utils.h"
#include "event_log.h"

int INTERFACE::if_info_update(hal_ifindex_t ifx, if_info_t& if_info)
{
    int track_ = OS_IF_CHANGE_NONE;
    std_rw_lock_write_guard lg(&rw_lock);

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-CACHE", "Add/Update for ifindex %d type %d name %s",
                             ifx, if_info.if_type, if_info.if_name.c_str());

    auto it = if_map_.find(ifx);
    if(it == if_map_.end()) {
        EV_LOGGING(NAS_OS, INFO, "NAS-OS-CACHE", " ### Add ifindex in the map %d", ifx);
        if (!(if_info.if_name.empty())) {
            name_ifindex_map_[if_info.if_name] = ifx;
        }
        if_map_.insert(std::make_pair(ifx, std::move(if_info)));
        track_ = OS_IF_CHANGE_ALL;
    } else {
        EV_LOGGING(NAS_OS, INFO, "NAS-OS-CACHE", " #### Update for ifindex %d", ifx);
        if(it->second.admin != if_info.admin) {
            track_ |= OS_IF_ADM_CHANGE;
            it->second.admin = if_info.admin;
        }

        if(it->second.oper != if_info.oper) {
            track_ |= OS_IF_OPER_CHANGE;
            it->second.oper = if_info.oper;
        }

        if(it->second.mtu != if_info.mtu) {
            track_ |= OS_IF_MTU_CHANGE;
            it->second.mtu = if_info.mtu;
        }
        if(it->second.master_idx != if_info.master_idx) {
            track_ |= OS_IF_MASTER_CHANGE;
            it->second.master_idx = if_info.master_idx;
        }

        const hal_mac_addr_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        if(!memcmp(if_info.phy_addr, zero_mac, sizeof(hal_mac_addr_t))) {
            //Zero mac need not be published
            memcpy(it->second.phy_addr, if_info.phy_addr, sizeof(hal_mac_addr_t));
        } else if(memcmp(it->second.phy_addr, if_info.phy_addr, sizeof(hal_mac_addr_t))) {
            track_ |= OS_IF_PHY_CHANGE;
            memcpy(it->second.phy_addr, if_info.phy_addr, sizeof(hal_mac_addr_t));
        }
    }

    return track_;
}

bool INTERFACE::if_info_setmask(hal_ifindex_t ifx, if_change_t mask_val)
{
    std_rw_lock_write_guard lg(&rw_lock);

    auto it = if_map_.find(ifx);

    if(it == if_map_.end()) {
        return false;
    } else {
        // In future, mask_val can be compared and set/reset accordingly
        it->second.ev_mask = mask_val;
    }
    return true;
}

if_change_t INTERFACE::if_info_getmask(hal_ifindex_t ifx)
{
    std_rw_lock_read_guard lg(&rw_lock);

    auto it = if_map_.find(ifx);

    if(it == if_map_.end()) {
        return OS_IF_CHANGE_NONE;
    } else {
        return (it->second.ev_mask);
    }
}

std::string INTERFACE::if_info_get_name(hal_ifindex_t ifx)
{
    std_rw_lock_read_guard lg(&rw_lock);

    auto it = if_map_.find(ifx);

    if(it == if_map_.end()) {
        EV_LOGGING(NAS_OS, DEBUG, "NAS-OS-CACHE", "interface not present in the map %d", ifx);
        return std::string("");
    }

    return (it->second.if_name);
}
BASE_CMN_INTERFACE_TYPE_t INTERFACE::if_info_get_type(hal_ifindex_t ifx)
{
    std_rw_lock_read_guard lg(&rw_lock);

    auto it = if_map_.find(ifx);

    if(it == if_map_.end()) {
        EV_LOGGING(NAS_OS, DEBUG, "NAS-OS-CACHE", "interface not present in the map %d", ifx);
        return BASE_CMN_INTERFACE_TYPE_NULL;
    }

    return (it->second.if_type);
}

bool INTERFACE::if_info_get_admin(hal_ifindex_t ifx, bool& admin)
{
    std_rw_lock_read_guard lg(&rw_lock);

    auto it = if_map_.find(ifx);

    if(it == if_map_.end()) {
        return false;
    }
    admin = it->second.admin;
    return true;;
}

bool INTERFACE::if_info_present(hal_ifindex_t ifx) {
    std_rw_lock_read_guard lg(&rw_lock);

    auto it = if_map_.find(ifx);
    if(it == if_map_.end()) {
        return false;
    }
    return true;
}

bool INTERFACE::if_info_get(hal_ifindex_t ifx, if_info_t& if_info)
{
    std_rw_lock_read_guard lg(&rw_lock);

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-CACHE", "Get for ifindex %d", ifx);

    auto it = if_map_.find(ifx);

    if(it == if_map_.end()) {
        return false;
    } else {
        if_info.admin = it->second.admin;
        if_info.mtu = it->second.mtu;
        memcpy(if_info.phy_addr, it->second.phy_addr, sizeof(hal_mac_addr_t));
    }

    return true;
}

void INTERFACE::if_info_delete(hal_ifindex_t ifx, std::string &name) {

    std_rw_lock_write_guard lg(&rw_lock);

    EV_LOGGING(NAS_OS, INFO, "NAS-OS-CACHE", "Deleting ifix %d", ifx);

    if_map_.erase(ifx);
    if (name.empty()) {
       EV_LOGGING(NAS_OS, ERR, "NAS-OS-CACHE", "Deleting ifix %d name is empty", ifx);
    } else {
        name_ifindex_map_.erase(name);
    }

    return;
}

bool INTERFACE::get_ifindex_from_name(std::string &if_name, hal_ifindex_t &if_index)
{
    std_rw_lock_read_guard lg(&rw_lock);

    auto it = name_ifindex_map_.find(if_name);
    if (it == name_ifindex_map_.end()) {
        EV_LOGGING(NAS_OS, ERR, "NAS-OS-CACHE","couldn't find ifindex in name cache %d", if_index);
        return false;
    } else {
        if_index = it->second;
        return true;
    }
}

void INTERFACE::for_each_mbr(std::function <void (int ix, if_info_t& if_info)> fn)
{
    std_rw_lock_read_guard lg(&rw_lock);

    for (auto it = if_map_.begin(); it != if_map_.end(); ++it)
        fn(it->first, it->second);
}

void if_mbr_data::member_add(hal_ifindex_t master_idx, hal_ifindex_t mbr_idx)
{
    auto it = mbr_map_.find(master_idx);

    if(it == mbr_map_.end()) {
        os_port_list_t port_list;
        port_list.insert(mbr_idx);
        mbr_map_.insert(os_member_pair(master_idx, std::move(port_list)));
    } else {
        it->second.insert(mbr_idx);
    }
}

bool if_mbr_data::member_del(hal_ifindex_t master_idx, hal_ifindex_t mbr_idx)
{
    auto it = mbr_map_.find(master_idx);

    if(it == mbr_map_.end()) {
        // Fall through;
    } else if(it->second.erase(mbr_idx)) {
        return true;
    }

    return false;
}

bool if_mbr_data::member_present(hal_ifindex_t master_idx, hal_ifindex_t mbr_idx) const
{
    auto it = mbr_map_.find(master_idx);

    if(it == mbr_map_.end()) {
        return false;
    } else {
        auto m_it = it->second.find(mbr_idx);
        if (m_it == it->second.end()) {
            return false;
        }
    }

    return true;
}

bool if_mbr_data::member_list_check_empty(hal_ifindex_t master_idx) const
{
    auto it = mbr_map_.find(master_idx);

    if(it == mbr_map_.end()) {
        return true;
    } else {
        return it->second.empty();
    }
}

void if_mbr_data::for_each_mbr(int m_idx, std::function <void (int mbr)> fn)
{
    auto it = mbr_map_.find(m_idx);

    if(it == mbr_map_.end()) {
        return;
    }
    else {
        for (auto port_it = it->second.begin() ; port_it != it->second.end(); ) {
            fn(*port_it);
            ++port_it;
        }
    }
}
