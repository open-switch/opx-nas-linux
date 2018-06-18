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

"""
This module provides support for generating or reserving object ID that is
used to uniquely identifiy an object
"""

from dn_base_vrf_tool import log_err
import threading
from StringIO import StringIO

class IdGenerator:
    def __init__(self, min_id = None, max_id = None):
        self.resved_ids = set([])
        if min_id is not None and max_id is not None and min_id >= max_id:
            log_err('Invalid min_id %d or max_id %d' % (min_id, max_id))
            raise ValueError
        if min_id is None:
            self.min_id = 1
        else:
            self.min_id = min_id
        self.max_id = max_id
        self.avail_id = self.min_id
        self.max_resved_id = None
        self.mutex = threading.Lock()

    def __str__(self):
        str_buf = StringIO()
        str_buf.write('\n-----------------------------------')
        str_buf.write('\n   ID Generator')
        str_buf.write('\n-----------------------------------')
        str_buf.write('\n  ID range for allocation : %s - %s' % (str(self.min_id), str(self.max_id) if self.max_id is not None else ''))
        str_buf.write('\n  Next ID to be allocated : %s' % ('-' if self.avail_id is None else str(self.avail_id)))
        str_buf.write('\n  Maximum reserved        : %s' % ('-' if self.max_resved_id is None else str(self.max_resved_id)))
        str_buf.write('\n  List reserved IDs       : ')
        if len(self.resved_ids) == 0:
            str_buf.write('-')
        else:
            id_list = sorted(self.resved_ids)
            start_id = prev_id = id_list[0]

            def add_range(s, min_id, max_id, fst):
                if not fst:
                    s.write(',')
                s.write(('%d-%d' % (min_id, max_id) if max_id > min_id else str(min_id)))

            first = True
            for obj_id in id_list[1:]:
                if obj_id > prev_id + 1:
                    add_range(str_buf, start_id, prev_id, first)
                    start_id = obj_id
                    if first:
                        first = False
                prev_id = obj_id
            add_range(str_buf, start_id, prev_id, first)
        ret_str = str_buf.getvalue()
        str_buf.close()
        return ret_str

    def get_next_avail_id(self):
        self.avail_id += 1
        while self.max_resved_id is None or self.avail_id <= self.max_resved_id:
            if self.avail_id not in self.resved_ids:
                break
            self.avail_id += 1
        if self.max_id is not None and self.avail_id > self.max_id:
            log_err('Unable to get next available ID: min %d max %d buffer_used %d' % (
                        self.min_id, self.max_id, len(self.resved_ids)))
            self.avail_id = None

    def get_new_id(self):
        self.mutex.acquire()
        if self.avail_id is None:
            log_err('No ID could be allocated')
            self.mutex.release()
            return None
        avail_id = self.avail_id
        self.resved_ids.add(avail_id)
        self.get_next_avail_id()
        if self.max_resved_id is None or avail_id > self.max_resved_id:
            self.max_resved_id = avail_id
        self.mutex.release()
        return avail_id

    def release_id(self, obj_id):
        self.mutex.acquire()
        if obj_id not in self.resved_ids:
            log_err('ID %d was not reserved for being released')
            self.mutex.release()
            return False
        self.resved_ids.remove(obj_id)
        if obj_id < self.avail_id:
            self.avail_id = obj_id
        if obj_id == self.max_resved_id:
            while obj_id >= self.min_id:
                if obj_id in self.resved_ids:
                    break
                obj_id -= 1
            if obj_id < self.min_id:
                self.max_resved_id = None
            else:
                self.max_resved_id = obj_id
        self.mutex.release()
        return True

    def is_id_used(self, obj_id):
        return obj_id in self.resved_ids

    def reserve_id(self, obj_id):
        self.mutex.acquire()
        if obj_id < self.min_id or (self.max_id is not None and obj_id > self.max_id):
            log_err('ID %s was not in valid range' % obj_id)
            self.mutex.release()
            return False
        if obj_id in self.resved_ids:
            log_err('ID %d was already reserved and could not be reserved again' % obj_id)
            self.mutex.release()
            return False
        self.resved_ids.add(obj_id)
        if obj_id == self.avail_id:
            self.get_next_avail_id()
        if self.max_resved_id is None or obj_id > self.max_resved_id:
            self.max_resved_id = obj_id
        self.mutex.release()
        return True


