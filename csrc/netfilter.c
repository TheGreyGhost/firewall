#include <libnetfilter_log/libnetfilter_log.h>

const int GROUP_NUMBER =

int main(int argc, char **argv) {
    struct nflog_handle *h;
    struct nflog_g_handle *qh;
    ssize_t rv;
    char buf[4096];

    h = nflog_open();
    if (!h) {
            fprintf(stderr, "error during nflog_open()\n");
            return 1;
    }
    if (nflog_unbind_pf(h, PF_INET) < 0) {
            fprintf(stderr, "error nflog_unbind_pf()\n");
            return 1;
    }
    if (nflog_bind_pf(h, PF_INET) < 0) {  //bind a nflog handler to a given protocol family
            fprintf(stderr, "error during nflog_bind_pf()\n");
            return 1;
    }
    qh = nflog_bind_group(h, GROUP_NUMBER);
    if (!qh) {
            fprintf(stderr, "no handle for group %i\n", GROUP_NUMBER);
            return 1;
    }


//qh	Netfilter log handle obtained by call to nflog_bind_group().
//mode	the part of the packet that we are interested in
//range	size of the packet that we want to get
//Sets the amount of data to be copied to userspace for each packet logged to the given group.
//
//NFULNL_COPY_NONE - do not copy any data
//NFULNL_COPY_META - copy only packet metadata
//NFULNL_COPY_PACKET - copy entire packet
// https://git.netfilter.org/libnetfilter_log/tree/src/libnetfilter_log.c

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
            fprintf(stderr, "can't set packet copy mode\n");
            return 1;
    }

    nflog_callback_register(qh, &callback, NULL);

    fd = nflog_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
            nflog_handle_packet(h, buf, rv);
    }
}

static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *ldata, void *data)
{
    payload_len = nflog_get_payload(ldata, (char **)(&ip));
    ....
    /* now "ip" points to the packet's IP header */
    /* ...do something with it... */
    ....
}