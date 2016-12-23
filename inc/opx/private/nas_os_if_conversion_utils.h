

#ifndef NAS_OS_IF_CONVERSION_UTILS_H_
#define NAS_OS_IF_CONVERSION_UTILS_H_

#include "ds_common_types.h"
#include <unordered_set>

bool get_tagged_intf_list(hal_ifindex_t intf_name,std::unordered_set<hal_ifindex_t> & intf_list);

bool get_tagged_intf_index_from_name(const char * intf_name,hal_ifindex_t & intf_index);

bool nas_os_update_tagged_intf_mac_learning(hal_ifindex_t ifindex, hal_ifindex_t vlan_ifindex);



#endif /* NAS_OS_IF_CONVERSION_UTILS_H_ */
