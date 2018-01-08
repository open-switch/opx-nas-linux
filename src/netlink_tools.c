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

/*
 * filename: nl_api.c
 */

/*
 * nl_api.c
 */

#include "netlink_tools.h"
#include "std_socket_tools.h"
#include "std_time_tools.h"
#include "event_log.h"
#include "nas_nlmsg.h"
#include "nas_os_interface.h"
#include "netlink_stats.h"
#include <string.h>
#include <unistd.h>

#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>

typedef struct {
    struct nlattr **tb;
    size_t max_type;
}nl_param_t;

static void netlink_tool_attr(struct nlattr *attr, void *context) {
    nl_param_t * p = (nl_param_t*) context;
    int type = nla_type(attr);
    if (type== 0 || type < p->max_type) {
        p->tb[type] = attr;
    }
}

int nla_parse(struct nlattr *tb[], int max_type, struct nlattr * head, int len)  {
    memset(tb,0,sizeof(struct nlattr*)*max_type);
    nl_param_t param = { tb, max_type };

    nla_for_each_attr((struct nlattr*)head,len,netlink_tool_attr,&param);

    return 0;
}

int nl_sock_create(const char *vrf_name, int ln_groups, int type,bool include_bind, int sock_buf_len) {
    struct sockaddr_nl sa;
    int sock = 0;
    memset(&sa, 0, sizeof(sa));

    sa.nl_family = AF_NETLINK;
    sa.nl_groups = ln_groups;
    if (os_sock_create(vrf_name, e_std_sock_NETLINK, e_std_sock_type_RAW, type, &sock) != STD_ERR_OK)
        return -1;

    std_sock_set_rcvbuf(sock, sock_buf_len);

    if (!include_bind) return sock;

    if (bind(sock, (struct sockaddr *) &sa, sizeof(sa))!=0) {
        close(sock);
        return -1;
    }
    return sock;
}


void netlink_tools_receive_event(int sock, fun_process_nl_message handlers,
        void * context, char * scratch_buff, size_t scratch_buff_len,int *error_code) {
    int len = 0;
    struct nlmsghdr * nh = NULL;
    int _error_code = 0;
    if (error_code==NULL) error_code = &_error_code;
    while (true) {
        struct nlmsghdr *nh = (struct nlmsghdr *)scratch_buff;
        struct iovec iov = { scratch_buff,scratch_buff_len };
        struct sockaddr_nl snl;
        struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

        len = recvmsg(sock, &msg,MSG_TRUNC);
        if ((len==-1) && (errno==EINTR || errno==EAGAIN)) continue;
        if (len==-1) {
            bool _mem = (errno==ENOMEM || errno==ENOBUFS);
            EV_LOGGING(NETLINK,ERR,"READ/ERR","Failed to read from socket %s - %d", _mem ? "due to ENOMEM or ENOBUFS" : "generic error",errno);
        }
        if (len==-1) { *error_code = errno; return ; }
        if (msg.msg_flags & MSG_TRUNC) {
            EV_LOGGING(NETLINK,ERR,"READ/ERR","Truncated message %d (type:%d)",msg.msg_iovlen,
                    nh->nlmsg_type);
            return ;
        }
        break;
    }
    size_t msg_count = 0;
    for(nh = (struct nlmsghdr *) scratch_buff; NLMSG_OK (nh, len);
        nh = NLMSG_NEXT (nh, len)) {

        int nlmsg_type = nh->nlmsg_type;

        EV_LOGGING(NETLINK, DEBUG ,"ACK/ERR","sock %d, msg_type %d", sock, nlmsg_type);

        //not expected during this phase..
        if (nh->nlmsg_flags & NLM_F_DUMP_INTR) {
            *error_code = EINTR;
            return ;    //current messages are incomplete.
        }

        if (nh->nlmsg_type == NLMSG_DONE) {
            EV_LOGGING(NETLINK, INFO ,"ACK/ERR","msg done for sock %d", sock);
            continue;
        }

        if (nh->nlmsg_type == NLMSG_NOOP) {
            EV_LOGGING(NETLINK,INFO,"ACK/ERR","Received a NOOP message");
            continue;
        }

        if (nh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (nh);
            EV_LOGGING(NETLINK,INFO,"ACK/ERR","Received response errid:%d msg:%d",err->error,err->msg);
            if (err->error==0) {
                continue;
            }
            /*
             * Netlink error is returned as a -ve number but all other errorno is +ve.
             * Converting to a positive error code for putting to STD_ERR private space
             */
            *error_code = -(err->error);
            return ;
        }

        msg_count++; //track statistics
        if (!handlers(sock, nh->nlmsg_type,nh,context)) { //assume function will log an error
            return ;
        }
    }
    nas_nl_stats_update (sock, msg_count);
}

bool netlink_tools_process_socket(int sock,
            fun_process_nl_message func,
            void * context, char * scratch_buff, size_t scratch_buff_len,
            const int * seq, int *error_code) {

    struct timeval tv = {0, 1000};
    int error_rc ;//will init below...
    if(error_code==NULL) error_code = &error_rc;
    //zap out existing error code
    *error_code = 0;

    bool rc =false;
    bool cont=true;
    fd_set sel_fds;
    FD_ZERO(&sel_fds);

    EV_LOGGING(NETLINK, DEBUG ,"ACK/ERR","sock %d", sock);

    while (cont) {
        struct nlmsghdr *nh = (struct nlmsghdr *)scratch_buff;
        struct iovec iov = { scratch_buff,sizeof(struct nlmsghdr) };
        struct sockaddr_nl snl;
        struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

        /*Check size of message - new kernels shold return size of new message not size of truncated one - old kernels will return
         * len matching input iov len and then you need to use the message header to determine the size*/
        int len = recvmsg (sock, &msg, MSG_PEEK | MSG_TRUNC);
        if (len<0  && ((errno==EINTR) || (errno==EAGAIN))) {
            EV_LOGGING(NETLINK, DEBUG ,"ACK/ERR","Recvmsg interrupted for sock %d", sock);
            continue;
        }
        if (len==-1) return false;

        EV_LOGGING(NETLINK, DEBUG ,"ACK/ERR","sock %d, msg len %d", sock, len);

        //Check len and update iov.iov_len appropriately (using the conditions above)
        if (msg.msg_flags & MSG_TRUNC) {
            if (iov.iov_len == len) {
                /*
                 * In cases where the input buffer is less then the required space
                 * read just one message - higher overhead but at least no truncated messages
                 *
                 * */
                iov.iov_len = nh->nlmsg_len; //actual size of messasge when the lenght returned is just the header length (old kernel)
            } else {
                iov.iov_len = len; //actual length of message from new kernel
            }
        }
        /*
         * Block possible buffer overwrite - truncate the message if the buffer size is smaller then even a single
         * message - likely only the case when people are querying with less then 1024 bytes
         * */
        if (iov.iov_len > scratch_buff_len) {
            EV_LOGGING(NETLINK, INFO ,"ACK/ERR","iov len %d greater than scratch buff len", iov.iov_len);
            iov.iov_len =  nh->nlmsg_len < scratch_buff_len ?
                    nh->nlmsg_len : scratch_buff_len;
        }

        len = recvmsg (sock, &msg, 0);

        if (len<0) {
            EV_LOGGING(NETLINK, INFO ,"ACK/ERR","Recvmsg len<0, errno %d, sock %d", errno, sock);
            if ((errno==EINTR) || (errno==EAGAIN)) continue;
            *error_code = errno;
            return false;
        }

        int nlmsg_type = nh->nlmsg_type;
        uint32_t msg_count = 0;

        EV_LOGGING(NETLINK, DEBUG ,"ACK/ERR","sock %d, msg len %d, msg type %d", sock, len, nlmsg_type);

        for(nh = (struct nlmsghdr *) scratch_buff; NLMSG_OK (nh, len);
                nh = NLMSG_NEXT (nh, len)) {

            nlmsg_type = nh->nlmsg_type;

            if ((seq!=NULL) && ((*seq)!=nh->nlmsg_seq)) {
                EV_LOGGING(NETLINK,INFO,"ACK/ERR","sock %d, out of sequence, msg_type %d",
                       sock, nlmsg_type);
                continue;
            }

            cont = (nh->nlmsg_flags & NLM_F_MULTI); // continue to wait
                            //for more messages since more on their way

            EV_LOGGING(NETLINK, DEBUG ,"ACK/ERR","sock %d, cont %d, msg_type %d", sock, cont, nlmsg_type);

            if (nh->nlmsg_flags & NLM_F_DUMP_INTR) {
                *error_code = EINTR;
                return false;    //current messages are incomplete.
            }

            if (nh->nlmsg_type == NLMSG_DONE) {
                EV_LOGGING(NETLINK, INFO ,"ACK/ERR","msg done for sock %d, cont %d", sock, cont);
                cont = false;
                rc = true;
                continue;
            }

            if (nh->nlmsg_type == NLMSG_NOOP) {
                EV_LOGGING(NETLINK,INFO,"ACK/ERR","Received a NOOP message");
                continue;
            }

            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (nh);
                EV_LOGGING(NETLINK,INFO,"ACK/ERR","Received response errid:%d msg:%d",err->error,err->msg);
                if (err->error==0) {
                    rc = true;
                    continue;
                }
                /*
                 * Netlink error is returned as a -ve number but all other errorno is +ve.
                 * Converting to a positive error code for putting to STD_ERR private space
                 */
                *error_code = -(err->error);
                return false;
            }

            msg_count++; //track statistics
            if (!func(sock, nh->nlmsg_type,nh,context)) {
                return false;
            } else {
                rc = true;
            }
        }

        EV_LOGGING(NETLINK, DEBUG ,"ACK/ERR","sock %d, rc %d", sock, rc);

        if (msg.msg_flags & MSG_TRUNC) {
            EV_LOGGING(NETLINK,INFO,"ACK/ERR","Truncated message %d (type:%d)",msg.msg_iovlen,
                    nlmsg_type);
            return false;
        }

        FD_SET(sock, &sel_fds);
        if(cont && select((sock+1), &sel_fds, NULL, NULL, &tv) <= 0) {
            EV_LOGGING(NETLINK, INFO ,"ACK/ERR","Select timed-out for %d, errno %d", sock, errno);
            rc = false;
            break;
        }

    }
    return rc;
}

bool nl_send_nlmsg(int sock, struct nlmsghdr *m) {
    struct sockaddr_nl nladdr ;
    memset(&nladdr,0,sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_groups = 0;

    struct iovec iov[1] = {
        { .iov_base = m, .iov_len = m->nlmsg_len }

    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen =     sizeof(nladdr),
        .msg_iov = iov,
        .msg_iovlen = 1,
    };

    return sendmsg(sock,&msg,0)==(m->nlmsg_len);
}

bool nl_send_request(int sock, int type, int flags, int seq, void * req, size_t len ) {
    struct nlmsghdr nlh;

    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };

    struct iovec iov[2] = {
        { .iov_base = &nlh, .iov_len = sizeof(nlh) },
        { .iov_base = req, .iov_len = len }
    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen =     sizeof(nladdr),
        .msg_iov = iov,
        .msg_iovlen = 2,
    };

    nlh.nlmsg_len = NLMSG_LENGTH(len);
    nlh.nlmsg_type = type;
    nlh.nlmsg_flags = flags;
    nlh.nlmsg_pid = 0;
    nlh.nlmsg_seq = seq;

    return sendmsg(sock,&msg,0)==(sizeof(nlh)+len);
}

void * nlmsg_reserve(struct nlmsghdr * m, int maxlen, int len) {
    void * p = nlmsg_tail(m);
    if ((NLMSG_ALIGN(m->nlmsg_len) + RTA_ALIGN(len)) > maxlen) {
        return NULL;
    }
    m->nlmsg_len = NLMSG_ALIGN(m->nlmsg_len) + RTA_ALIGN(len);
    return p;
}

struct nlattr * nlmsg_nested_start(struct nlmsghdr * m, int maxlen) {
    return (struct nlattr *)(nlmsg_reserve(m,maxlen,sizeof(struct rtattr)));
}

void nlmsg_nested_end(struct nlmsghdr * m, struct nlattr *attr) {
    attr->nla_len =  ((char*)nlmsg_tail(m)) - (char*)attr ;
}

int nlmsg_add_attr(struct nlmsghdr * m, int maxlen, int type, const void * data, int attr_len) {
    struct rtattr *rta = (struct rtattr *)nlmsg_reserve(m,maxlen,RTA_LENGTH(attr_len));
    if (rta==NULL) return -1;
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(attr_len);
    memcpy(RTA_DATA(rta), data, attr_len);
    return m->nlmsg_len;
}

bool _process_set_fun(int sock, int rt_msg_type, struct nlmsghdr *hdr, void * context) {
    return true;
}
t_std_error nl_do_set_request(const char *vrf_name, nas_nl_sock_TYPES type,struct nlmsghdr *m, void *buff, size_t bufflen) {
    int error = 0;
    int sock = nas_nl_sock_create(vrf_name, type,false);
    if (sock==-1) return STD_ERR(ROUTE,FAIL,errno);
    do {
        int seq = (int)std_get_uptime(NULL);
        m->nlmsg_seq = seq;
        if (!nl_send_nlmsg(sock,m)) {
            break;
        }
        if (type == nas_nl_sock_T_ROUTE &&
            !netlink_tools_process_socket(sock,_process_set_fun,NULL,buff,bufflen,&seq, &error)) {
            break;
        }
        close(sock);
        return cps_api_ret_code_OK;
    } while(0);

    if (sock!=-1) close(sock);
    return STD_ERR(ROUTE,FAIL,error);
}

static int create_intf_socket(const char *vrf_name, bool include_bind) {
    return nl_sock_create(vrf_name, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
                          NETLINK_ROUTE,include_bind, NL_INTF_SOCKET_BUFFER_LEN);
}

static int create_route_socket(const char *vrf_name, bool include_bind) {
    return nl_sock_create(vrf_name, RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE,
                          NETLINK_ROUTE,include_bind, NL_ROUTE_SOCKET_BUFFER_LEN);
}

static int create_neigh_socket(const char *vrf_name, bool include_bind) {
    return nl_sock_create(vrf_name, RTMGRP_NEIGH,NETLINK_ROUTE,include_bind,
                          NL_NEIGH_SOCKET_BUFFER_LEN);
}

static int create_mcast_snoop_socket(const char *vrf_name, bool include_bind) {
    EV_LOGGING(NETLINK_MCAST_SNOOP, DEBUG,"NETLINK","Create MCAST Snoop Socket");
    int sock = nl_sock_create(vrf_name, 0, NETLINK_ROUTE,include_bind, NL_SCRATCH_BUFFER_LEN);
    if ((sock != -1) && include_bind) {
        int mc_group = RTNLGRP_MDB;
        int err = setsockopt(sock, NL_SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                         &mc_group, sizeof(mc_group));
        if (err) {
            close(sock);
            EV_LOGGING(NETLINK_MCAST_SNOOP, ERR,"NETLINK","MDB Subscription failed!");
            return -1;
        }
    }
    EV_LOGGING(NETLINK_MCAST_SNOOP, DEBUG,"NETLINK","MDB Subscription Success!");
    return sock;

}

static int create_netconf_socket(const char *vrf_name, bool include_bind) {
    int sock = nl_sock_create(vrf_name, 0, NETLINK_ROUTE,include_bind, NL_NETCONF_SOCKET_BUFFER_LEN);
    /* Subscribe for the NETCONF groups to receive the IP forwarding
     * enable/disable from kernel */
    if ((sock != -1) && include_bind) {
        int mc_group = RTNLGRP_IPV4_NETCONF;
        int err = setsockopt(sock, NL_SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                             &mc_group, sizeof(mc_group));
        if (err) {
            EV_LOGGING(NETLINK, ERR,"NETLINK","NETCONF IPv4 subscription failed!");
            return -1;
        }
        mc_group = RTNLGRP_IPV6_NETCONF;
        err = setsockopt(sock, NL_SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                         &mc_group, sizeof(mc_group));
        if (err) {
            close(sock);
            EV_LOGGING(NETLINK, ERR,"NETLINK","NETCONF IPv6 subscription failed!");
            return -1;
        }
    }
    return sock;
}


typedef int (*create_soc_fn)(const char *vrf_name, bool include_bind);
static create_soc_fn sock_create_functions[] = {
    create_route_socket,
    create_intf_socket,
    create_neigh_socket,
    create_netconf_socket,
    create_mcast_snoop_socket
};

int nas_nl_sock_create(const char *vrf_name, nas_nl_sock_TYPES type, bool include_bind)  {
    if (type >= nas_nl_sock_T_MAX) return -1;
    return sock_create_functions[type](vrf_name, include_bind);
}


void nas_os_pack_nl_hdr(struct nlmsghdr *nlh, __u16 msg_type, __u16 nl_flags)
{
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_flags = nl_flags ;
    nlh->nlmsg_type = msg_type;
}

void nas_os_pack_if_hdr(struct ifinfomsg *ifmsg, unsigned char ifi_family,
                        unsigned int flags, int if_index)
{
    ifmsg->ifi_family = ifi_family;
    ifmsg->ifi_flags = flags;
    ifmsg->ifi_index = if_index;
}


void nas_nl_process_nflog_msg (struct nlmsghdr *nl_hdr,
                               nas_nflog_params_t *p_nas_nflog_params)
{
    int    msg_len, rem_len;
    char  *data;
    struct nfattr                *attr;

    msg_len = nl_hdr -> nlmsg_len;

    attr = (struct nfattr *) ((char *) nl_hdr +
                              NLMSG_SPACE(sizeof(struct nfgenmsg)));

    rem_len = msg_len - ((char *) attr - (char *) nl_hdr);

    while (NFA_OK(attr, rem_len)) {
        data = (char *) NFA_DATA(attr);
        if (attr->nfa_type & NFNL_NFA_NEST) {
            EV_LOGGING(NETLINK, INFO,"NK-SOCK-NFLOG","Nested attribute received");
        }
        switch (NFA_TYPE(attr)) {
            case NFULA_PACKET_HDR:
                {
                    struct nfulnl_msg_packet_hdr *pkt_hdr;
                    pkt_hdr = (struct nfulnl_msg_packet_hdr *)data;
                    p_nas_nflog_params->hw_protocol = pkt_hdr->hw_protocol;
                }
                break;

            case NFULA_IFINDEX_OUTDEV:
                p_nas_nflog_params->out_ifindex = ntohl(*(unsigned int *)data);
                break;

            case NFULA_PAYLOAD:
                if (attr->nfa_len > NL_NFLOG_PAYLOAD_LEN)
                {
                    EV_LOGGING(NETLINK, ERR,"NK-SOCK-NFLOG",
                               "ERROR: exceeding input payload buffer len. len = %d",
                               attr->nfa_len);
                    return;
                }
                memcpy (p_nas_nflog_params->payload, (char *) data, attr->nfa_len);
                p_nas_nflog_params->payload_len = attr->nfa_len;
                break;

            default:
                break;
        }
        attr = NFA_NEXT(attr, rem_len);
    }

    return;
}


int nas_os_nl_get_nflog_params (uint8_t *buf, int size,
                                nas_nflog_params_t *p_nas_nflog_params)
{
    struct nlmsghdr *nl_hdr;
    struct nlmsgerr *msg_err;
    int msg_count, msg_len, rem_len;
    int more = 0;

    msg_count = 0;   // Number of NL messages in this buffer
    msg_len = 0;     // Sum of all NL message len from the header
    rem_len = size;   // Running track of how many more bytes to process
    nl_hdr = (struct nlmsghdr *) buf;

    while (NLMSG_OK(nl_hdr, rem_len)) {

        msg_count ++;
        msg_len += nl_hdr -> nlmsg_len;

        if (nl_hdr -> nlmsg_type == NLMSG_ERROR) { // Either ACK or ERR
            msg_err = (struct nlmsgerr *) NLMSG_DATA(nl_hdr);
            if (msg_err -> error != 0) {
                EV_LOGGING(NETLINK, ERR,"NK-SOCK-NFLOG",
                           "Error in processing NFLOG params - %s",
                           strerror(-msg_err -> error));
            } else {
                EV_LOGGING(NETLINK, DEBUG, "NK-SOCK-NFLOG",
                           "Operation was successfully done");
            }
            more = 0;
            break;
        } else if (nl_hdr -> nlmsg_type == NLMSG_DONE) {
            more = 0;
            break;
        }
        nas_nl_process_nflog_msg (nl_hdr, p_nas_nflog_params);

        if (nl_hdr -> nlmsg_flags & NLM_F_MULTI) {
            nl_hdr = NLMSG_NEXT(nl_hdr, rem_len);  // More msg in the buffer.
            more = 1;
        } else {   // Single message and we are automatically done.
            more = 0;
            nl_hdr = NLMSG_NEXT(nl_hdr, rem_len);  // More msg in the buffer.
            break;
        }
    }

    if (size < msg_len) {
        /* @@TODO buffer overflow case log it for now */
        EV_LOGGING(NETLINK, ERR,"NK-SOCK-NFLOG","NFLOG message buffer overlength msg_len:%d", msg_len);
    }
    if (more == 1) {
        /* @@TODO multi part msg case log it for now */
        EV_LOGGING(NETLINK, INFO,"NK-SOCK-NFLOG","Multi part NFLOG msg truncated");
    }

    return 0;
}

int nlmsg_prep_nful_msg(char *buf, int family,
                        int type, int queue_num, int seq_no)
{
    struct nlmsghdr *nl_hdr;
    int len;
    struct nfgenmsg *msg;

    len = NLMSG_SPACE(sizeof (struct nfgenmsg));
    nl_hdr = (struct nlmsghdr *) buf;
    msg = (struct nfgenmsg *) NLMSG_DATA(buf);

    nl_hdr -> nlmsg_type = (type << 8) | NFULNL_MSG_CONFIG;
    nl_hdr -> nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nl_hdr -> nlmsg_seq = seq_no;
    nl_hdr -> nlmsg_pid = 0;

    msg -> nfgen_family = family;
    msg -> version = NFNETLINK_V0;
    msg -> res_id = htons (queue_num);
    return len;

}

// Binds to the specified netfilter subsystem
int nas_os_bind_nf_sub(int fd, int family, int type, int queue_num)
{
    char buf[512];    // Should be sufficient for the type of operations we do
    struct nlmsghdr *nl_hdr;
    int len;
    struct nfattr *nfa;
    struct nfulnl_msg_config_cmd *cmd;
    struct nfulnl_msg_config_mode *mode;
    static int seq_no = 345;
    int error = 0;

    len = nlmsg_prep_nful_msg(buf, family, type, queue_num, seq_no);
    nl_hdr = (struct nlmsghdr *) buf;

    nfa = (struct nfattr *) ((char *)buf + len);
    nfa->nfa_len = NFA_SPACE(sizeof(struct nfulnl_msg_config_cmd));
    len += nfa->nfa_len;
    nfa->nfa_type = NFULA_CFG_CMD;
    cmd = (struct nfulnl_msg_config_cmd *)NFA_DATA(nfa);
    cmd->command = NFULNL_CFG_CMD_BIND;
    nl_hdr -> nlmsg_len = len;

    nl_send_nlmsg (fd, nl_hdr);
    /* read the response */
    netlink_tools_process_socket(fd,_process_set_fun,NULL,buf,512,&seq_no, &error);

    seq_no++;

    len = nlmsg_prep_nful_msg(buf, family, type, queue_num, seq_no);
    nl_hdr = (struct nlmsghdr *) buf;

    nfa = (struct nfattr *) ( (char *) buf + len);
    nfa -> nfa_len = NFA_SPACE(sizeof (struct nfulnl_msg_config_mode));
    len += nfa -> nfa_len;
    nfa -> nfa_type = NFULA_CFG_MODE;
    mode = (struct nfulnl_msg_config_mode *) NFA_DATA(nfa);
    mode -> copy_range = 0xff;
    mode -> copy_mode = NFULNL_COPY_PACKET;
    nl_hdr -> nlmsg_len = len;

    nl_send_nlmsg (fd, nl_hdr);
    /* read the response */
    netlink_tools_process_socket(fd,_process_set_fun,NULL,buf,512,&seq_no, &error);

    seq_no++;
    return 0;
}

int nas_os_nl_nflog_init ()
{
/* NFLOG socket group used. This is the one used in ebtable rule */
#define NL_NFLOG_GROUP        100
/* Netfilter NFLOG protocol family */
#define NL_NFLOG_FAMILY       AF_BRIDGE
/* NFLOG socket buffer. customized this as required. */
#define NL_NFLOG_SOCK_BUFFER  65000
    int fd;
    int netlink_type = NETLINK_NETFILTER;

    fd = nl_sock_create(NL_DEFAULT_VRF_NAME, NL_NFLOG_GROUP, netlink_type,true, NL_NFLOG_SOCK_BUFFER);

    if (fd < 0) {
        EV_LOGGING(NETLINK, ERR, "NK-SOCKCR-NFLOG", "NFLOG initialization failed: %d", errno);
        return -1;
    }

    // For now let us monitor only the ULOG subsystem
    nas_os_bind_nf_sub(fd, NL_NFLOG_FAMILY, NFNL_SUBSYS_ULOG, NL_NFLOG_GROUP);

    // enable NFLOG
    os_nflog_enable ();
    EV_LOGGING(NETLINK, DEBUG,"NK-SOCKCR-NFLOG","NFLOG initialization success");
    return fd;
}
