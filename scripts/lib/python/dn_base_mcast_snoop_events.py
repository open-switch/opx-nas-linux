#!/usr/bin/python
# Copyright (c) 2018 Dell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.
import cps
import cps_object

def singleton(cls):
    inst = {}
    def get_inst():
        if cls not in inst:
            inst[cls] = cls()
        return inst[cls]
    return get_inst


@singleton
class MCast_CpsEvents:

    def __init__(self):
        """
        This function initializes the instance variable: CPS handle
        @param[in] None
        @returns None

        """

        self.handle = cps.event_connect()
    def publish_events(self, mod, event_data, op):
        """
        This function publishes/raises CPS Events with the information from event_data
        @param[in] event_data: Input Dictionary which will be used when publishing events
        @returns None

        """

        obj = cps_object.CPSObject(module=mod,qual="observed")

        for key in event_data:
            if isinstance(key, tuple) and len(key) > 1:
                obj.add_embed_attr(list(key), event_data[key], len(key))
            else:
                obj.add_attr(key, event_data[key])

        d = obj.get()
        d['operation'] = op
        cps.event_send(self.handle,d)


    def publish_igmp_events(self, event_data, op):
        """
        This function publishes/raises IGMP CPS Events with the information from event_data
        @param[in] event_data: Input Dictionary which will be used when publishing events
        @returns None

        """

        self.publish_events("igmp-mld-snooping/rt/routing-state/control-plane-protocols/igmp-snooping/vlans/vlan", event_data, op)

    def publish_mld_events(self, event_data, op):
        """
        This function publishes/raises MLD CPS Events with the information from event_data
        @param[in] event_data: Input Dictionary which will be used when publishing events
        @returns None

        """

        self.publish_events("igmp-mld-snooping/rt/routing-state/control-plane-protocols/mld-snooping/vlans/vlan", event_data, op)



