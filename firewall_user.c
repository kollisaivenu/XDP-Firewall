#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "firewall_kern.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static struct firewall_kern *skel = NULL;
static int ifindex = 0;

void sig_handler(int sig) {
    exiting = true;
}

void cleanup_and_exit(int status) {
    if (ifindex > 0) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    }
    if (skel) {
        printf("\nDetaching XDP program and exiting...\n");
        firewall_kern__destroy(skel);
    }
    exit(status);
}

int main(int argc, char **argv) {
    int err;
    const char *ifname;
    const char *ip_to_block;
    __u32 map_key;
    __u32 map_val = 1;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <IP_to_block>\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    ip_to_block = argv[2];

    if (inet_pton(AF_INET, ip_to_block, &map_key) != 1) {
        perror("inet_pton failed");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);

    skel = firewall_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = firewall_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        cleanup_and_exit(1);
    }

    int map_fd = bpf_map__fd(skel->maps.ip_blacklist);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd: %s\n", strerror(errno));
        cleanup_and_exit(1);
    }

    err = bpf_map_update_elem(map_fd, &map_key, &map_val, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update map (IP: %s): %s\n", ip_to_block, strerror(errno));
        cleanup_and_exit(1);
    }
    printf("Successfully added IP %s to the blacklist map.\n", ip_to_block);

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Interface %s not found\n", ifname);
        cleanup_and_exit(1);
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_firewall),
                          XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP to %s: %s\n", ifname, strerror(-err));
        cleanup_and_exit(1);
    }

    printf("Successfully attached XDP program to %s. Blocking traffic from %s.\n", ifname, ip_to_block);
    printf("Press Ctrl+C to detach and exit.\n");

    while (!exiting) {
        sleep(1);
    }

    cleanup_and_exit(0);
    return 0;
}
