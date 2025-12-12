#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "firewall_kern.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct xdp_firewall_bpf *skel;
    int err;
    const char *ifname;
    const char *ip_to_block;
    __u32 map_key;
    __u32 map_val = 1;

    if(argc < 3) {
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
    if(!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = xdp_firewall_bpf__load(skel);
    if(err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    int map_fd = bpf_map__fd(skel->maps.ip_blacklist);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptor: %s\n", strerror(errno));
        goto cleanup;
    }

    err = bpf_map_update_elem(map_fd, &map_key, &map_val, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update map (IP: %s): %s\n", ip_to_block, strerror(errno));
        goto cleanup;
    }
    printf("Successfully added IP %s to the blacklist map.\n", ip_to_block);

    err = xdp_program__attach(skel->progs.xdp_firewall, if_nametoindex(ifname), XDP_FLAGS_SKB_MODE, 0);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to interface %s: %s\n", ifname, strerror(-err));
        goto cleanup;
    }
    printf("Successfully attached XDP program to interface %s. Blocking traffic from %s.\n", ifname, ip_to_block);
    printf("Press Ctrl+C to detach and exit.\n");

    while(!exiting) {
        sleep(1);
    }

cleanup:
    if(skel) {
        printf("\nDetaching XDP program and exiting...\n");
        xdp_firewall_bpf__destroy(skel);
    }

    return err ?: 0;
}