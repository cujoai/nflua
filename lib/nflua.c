/*
 * Copyright (C) 2017-2019  CUJO LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "nflua.h"

#define MIN(x,y) ((x) < (y) ? (x) : (y))

static int handle_list_response(struct nflua_control *ctrl,
      struct nflua_response *r, struct nlmsghdr *nh, char *buffer)
{
    struct nflua_nl_list *list;
    struct nflua_nl_fragment *frag;
    struct nflua_nl_state *desc;
    size_t offset;
    size_t currentsize;

    if (nh->nlmsg_flags & NFLM_F_INIT) {
        list = NLMSG_DATA(nh);
        frag = &list->frag;
        desc = (struct nflua_nl_state *)(list + 1);
        currentsize = NLMSG_PAYLOAD(nh, sizeof(struct nflua_nl_list));

        r->type = NFLMSG_LIST;
        r->count = list->total;
        r->total_size = list->total * sizeof(struct nflua_nl_state);

        if (r->total_size > NFLUA_LIST_MAXSIZE)
            return -EMSGSIZE;

    } else {
        frag = NLMSG_DATA(nh);
        desc = (struct nflua_nl_state *)(frag + 1);
        currentsize = NLMSG_PAYLOAD(nh, sizeof(struct nflua_nl_fragment));
    }

    offset = frag->offset * sizeof(struct nflua_nl_state);

    if (offset + currentsize > NFLUA_LIST_MAXSIZE)
        return -EMSGSIZE;

    memcpy(buffer + offset, desc, currentsize);

    ctrl->state =
        nh->nlmsg_flags & NFLM_F_DONE ? NFLUA_LINK_READY : NFLUA_RECEIVING_REPLY;

    return 0;
}

int nflua_control_receive(struct nflua_control *ctrl,
        struct nflua_response *nr, char *buffer)
{
    struct iovec iov = { ctrl->buffer, NFLUA_PAYLOAD_MAXSIZE };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    struct nlmsghdr *nh;
    ssize_t len, ret = -1;

    if (nr == NULL || (ctrl->state != NFLUA_PENDING_REPLY
          && ctrl->state != NFLUA_RECEIVING_REPLY))
        return -EPERM;

    if ((len = recvmsg(ctrl->fd, &msg, 0)) < 0)
        return len;

    nh = (struct nlmsghdr *)ctrl->buffer;
    if (NLMSG_OK(nh, len) == 0) {
        ctrl->state = NFLUA_PROTOCOL_OUTOFSYNC;
        return -EBADMSG;
    }

    if (nh->nlmsg_seq != ctrl->seqnum) {
        ctrl->state = NFLUA_PROTOCOL_OUTOFSYNC;
        return -EPROTO;
    }

    for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
        ret = 0;
        switch (nh->nlmsg_type) {
        case NFLMSG_CREATE:
        case NFLMSG_DESTROY:
        case NFLMSG_EXECUTE:
        case NLMSG_ERROR:
            nr->type = nh->nlmsg_type;
            ctrl->state = NFLUA_LINK_READY;
            break;
        case NFLMSG_LIST:
            ret = handle_list_response(ctrl, nr, nh, buffer);
            break;
        default:
            nr->type = -1;
            ctrl->state = NFLUA_LINK_READY;
        }
        if (ret < 0)
            break;
    }

    return ret < 0 ? ret : ctrl->state != NFLUA_LINK_READY;
}

static ssize_t sendcmd(int fd, struct iovec *iov, size_t len)
{
    struct sockaddr_nl dest_addr = {.nl_family = AF_NETLINK};
    struct msghdr msg = {
        .msg_name = &dest_addr,
        .msg_namelen = sizeof(dest_addr),
        .msg_iov = iov,
        .msg_iovlen = len
    };

    return sendmsg(fd, &msg, 0);
}

int nflua_control_create(struct nflua_control *ctrl, struct nflua_nl_state *cmd)
{
    struct nlmsghdr nlh;
    struct iovec iov[2];
    int ret = -1;

    if (ctrl->state != NFLUA_LINK_READY)
        return ret;

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct nflua_nl_state));
    nlh.nlmsg_type = NFLMSG_CREATE;
    nlh.nlmsg_flags = NFLM_F_REQUEST;
    nlh.nlmsg_seq = ++(ctrl->seqnum);
    nlh.nlmsg_pid = ctrl->pid;

    iov[0].iov_base = &nlh;
    iov[0].iov_len = NLMSG_HDRLEN;
    iov[1].iov_base = cmd;
    iov[1].iov_len = sizeof(struct nflua_nl_state);

    if ((ret = sendcmd(ctrl->fd, iov, 2)) < 0)
        return ret;

    ctrl->state = NFLUA_PENDING_REPLY;
    return ret;
}

int nflua_control_destroy(struct nflua_control *ctrl, const char *name)
{
    struct nlmsghdr nlh;
    struct iovec iov[2];
    struct nflua_nl_destroy cmd;
    int namelen = strnlen(name, NFLUA_NAME_MAXSIZE);
    int ret = -EPERM;

    if (ctrl->state != NFLUA_LINK_READY)
        return ret;

    memset(&cmd, 0, sizeof(cmd));
    memcpy(cmd.name, name, namelen);

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct nflua_nl_destroy));
    nlh.nlmsg_type = NFLMSG_DESTROY;
    nlh.nlmsg_flags = NFLM_F_REQUEST;
    nlh.nlmsg_seq = ++(ctrl->seqnum);
    nlh.nlmsg_pid = ctrl->pid;

    iov[0].iov_base = &nlh;
    iov[0].iov_len = NLMSG_HDRLEN;
    iov[1].iov_base = &cmd;
    iov[1].iov_len = sizeof(struct nflua_nl_destroy);

    if ((ret = sendcmd(ctrl->fd, iov, 2)) < 0)
        return ret;

    ctrl->state = NFLUA_PENDING_REPLY;
    return ret;
}

static int send_execute_head(struct nflua_control *ctrl, const char *name,
        const char *script, const char *payload, size_t len, size_t total)
{
    struct nlmsghdr nlh;
    struct nflua_nl_script cmd;
    struct iovec iov[3];

    nlh.nlmsg_len = NLMSG_SPACE(sizeof(struct nflua_nl_script)) + len;
    nlh.nlmsg_type = NFLMSG_EXECUTE;
    nlh.nlmsg_flags = NFLM_F_REQUEST | NFLM_F_INIT |
            (total > len ? NFLM_F_MULTI : NFLM_F_DONE);
    nlh.nlmsg_seq = ++(ctrl->seqnum);
    nlh.nlmsg_pid = ctrl->pid;

    memset(&cmd, 0, sizeof(struct nflua_nl_script));
    memcpy(cmd.name, name, strnlen(name, NFLUA_NAME_MAXSIZE));
    memcpy(cmd.script, script, strnlen(script, NFLUA_SCRIPTNAME_MAXSIZE));
    cmd.total = total;
    cmd.frag.seq = 0;
    cmd.frag.offset = 0;

    iov[0].iov_base = &nlh;
    iov[0].iov_len = NLMSG_HDRLEN;
    iov[1].iov_base = &cmd;
    iov[1].iov_len = NLMSG_ALIGN(sizeof(struct nflua_nl_script));
    iov[2].iov_base = (void *)payload;
    iov[2].iov_len = len;

    return sendcmd(ctrl->fd, iov, 3);
}

static int send_execute_frag(struct nflua_control *ctrl, const char *payload,
        size_t offset, size_t len, int final)
{
    struct nlmsghdr nlh;
    struct nflua_nl_fragment frag;
    struct iovec iov[3];

    nlh.nlmsg_len = NLMSG_SPACE(sizeof(struct nflua_nl_fragment)) + len;
    nlh.nlmsg_type = NFLMSG_EXECUTE;
    nlh.nlmsg_flags = NFLM_F_REQUEST | NFLM_F_MULTI | (final ? NFLM_F_DONE : 0);
    nlh.nlmsg_seq = ctrl->seqnum;
    nlh.nlmsg_pid = ctrl->pid;

    frag.seq = ctrl->currfrag + 1;
    frag.offset = offset;

    iov[0].iov_base = &nlh;
    iov[0].iov_len = NLMSG_HDRLEN;
    iov[1].iov_base = &frag;
    iov[1].iov_len = NLMSG_ALIGN(sizeof(struct nflua_nl_fragment));
    iov[2].iov_base = (void *)(payload + offset);
    iov[2].iov_len = len;

    return sendcmd(ctrl->fd, iov, 3);
}

int nflua_control_execute(struct nflua_control *ctrl, const char *name,
        const char *script, const char *payload, size_t total)
{
    size_t hlen, flen, offset;
    int final, ret;

    if (name == NULL || payload == NULL || script == NULL || total == 0 ||
        total > NFLUA_SCRIPT_MAXSIZE) {
        return -EINVAL;
    }

    hlen = MIN(total, NFLUA_SCRIPT_FRAG_SIZE);

    switch (ctrl->state) {
    case NFLUA_LINK_READY:
        ret = send_execute_head(ctrl, name, script, payload, hlen, total);
        if (ret < 0)
            return ret;
        ctrl->currfrag = 0;
        ctrl->state = total > NFLUA_SCRIPT_FRAG_SIZE ? NFLUA_SENDING_REQUEST :
                NFLUA_PENDING_REPLY;
        break;
    case NFLUA_SENDING_REQUEST:
        offset = hlen + ctrl->currfrag * NFLUA_SCRIPT_FRAG_SIZE;
        flen = MIN(total - offset, NFLUA_SCRIPT_FRAG_SIZE);
        final = offset + flen >= total;
        ret = send_execute_frag(ctrl, payload, offset, flen, final);
        if (ret < 0)
            return ret;
        ctrl->currfrag++;
        if (final)
            ctrl->state = NFLUA_PENDING_REPLY;
        break;
    default:
        return -EPERM;
    }

    return ctrl->state == NFLUA_SENDING_REQUEST;
}

int nflua_control_list(struct nflua_control *ctrl)
{
    struct nlmsghdr nlh;
    struct iovec iov;
    int ret = -EPERM;

    if (ctrl->state != NFLUA_LINK_READY)
        return ret;

    nlh.nlmsg_len = NLMSG_LENGTH(0);
    nlh.nlmsg_type = NFLMSG_LIST;
    nlh.nlmsg_flags = NFLM_F_REQUEST;
    nlh.nlmsg_seq = ++(ctrl->seqnum);
    nlh.nlmsg_pid = ctrl->pid;

    iov.iov_base = &nlh;
    iov.iov_len = NLMSG_HDRLEN;

    if ((ret = sendcmd(ctrl->fd, &iov, 1)) < 0)
        return ret;

    ctrl->state = NFLUA_PENDING_REPLY;
    return ret;
}

static int create_socket(uint32_t pid)
{
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_pid = pid};
    int fd;

    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NFLUA)) < 0)
        return -errno;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -errno;
    }

    return fd;
}

int nflua_control_init(struct nflua_control *ctrl, uint32_t pid)
{
    if (ctrl == NULL)
        return -EINVAL;

    if ((ctrl->fd = create_socket(pid)) < 0)
        return ctrl->fd;

    ctrl->state = NFLUA_LINK_READY;
    ctrl->pid = pid;
    ctrl->seqnum = 0;

    return 0;
}

void nflua_control_close(struct nflua_control *ctrl)
{
    if (ctrl != NULL) {
        close(ctrl->fd);
        ctrl->fd = -1;
        ctrl->state = NFLUA_SOCKET_CLOSED;
    }
}

int nflua_data_send(struct nflua_data *dch, const char *name,
        const char *payload, size_t len)
{
    struct nlmsghdr nlh;
    struct nflua_nl_data cmd;
    struct iovec iov[3];

    if (name == NULL || payload == NULL || len == 0 || len > NFLUA_DATA_MAXSIZE)
        return -EPERM;

    nlh.nlmsg_type = NFLMSG_DATA;
    nlh.nlmsg_seq = ++(dch->seqnum);
    nlh.nlmsg_pid = dch->pid;
    nlh.nlmsg_flags = NFLM_F_REQUEST | NFLM_F_DONE;
    nlh.nlmsg_len = NLMSG_SPACE(sizeof(struct nflua_nl_data)) + len;

    memset(&cmd, 0, sizeof(struct nflua_nl_data));
    memcpy(cmd.name, name, strnlen(name, NFLUA_NAME_MAXSIZE));
    cmd.total = len;

    iov[0].iov_base = &nlh;
    iov[0].iov_len = NLMSG_HDRLEN;
    iov[1].iov_base = &cmd;
    iov[1].iov_len = NLMSG_ALIGN(sizeof(struct nflua_nl_data));
    iov[2].iov_base = (void *)payload;
    iov[2].iov_len = len;

    return sendcmd(dch->fd, iov, 3);
}

static int handle_data_msg(char *state, char *buffer, struct nlmsghdr *nlh)
{
    struct nflua_nl_data *cmd = NLMSG_DATA(nlh);
    size_t datalen = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct nflua_nl_data));
    char *payload = ((char *)nlh) + NLMSG_SPACE(sizeof(struct nflua_nl_data));

    if (nlh->nlmsg_flags != (NFLM_F_REQUEST | NFLM_F_DONE))
            return -EPROTO;

    if (cmd->total > NFLUA_DATA_MAXSIZE || cmd->total != datalen)
        return -EMSGSIZE;

    memcpy(buffer, payload, datalen);

    if (state != NULL)
        strncpy(state, cmd->name, NFLUA_NAME_MAXSIZE);

    return datalen;
}

int nflua_data_receive(struct nflua_data *dch, char *state, char *buffer)
{
    struct iovec iov = {dch->buffer, NFLUA_PAYLOAD_MAXSIZE};
    struct sockaddr_nl sa;
    struct msghdr msg = {&sa, sizeof(sa), &iov, 1, NULL, 0, 0};
    struct nlmsghdr *nh;
    ssize_t len, ret = -EBADMSG;

    if (buffer == NULL)
        return -EINVAL;

    if ((len = recvmsg(dch->fd, &msg, 0)) < 0)
        return len;

    nh = (struct nlmsghdr *)dch->buffer;
    for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_type != NFLMSG_DATA)
            return -EPROTO;
        if ((ret = handle_data_msg(state, buffer, nh)) < 0)
            break;
    }

    return ret;
}

int nflua_data_init(struct nflua_data *dch, uint32_t pid)
{
    if (dch == NULL)
        return -EINVAL;

    if ((dch->fd = create_socket(pid)) < 0)
        return dch->fd;

    dch->pid = pid;
    dch->seqnum = 0;

    return 0;
}

void nflua_data_close(struct nflua_data *dch)
{
    if (dch != NULL) {
        close(dch->fd);
        dch->fd = -1;
    }
}
