BPF_SRC = firewall_kern.c
BPF_OBJ = $(BPF_SRC:.c=.o)

USER_SRC = firewall_user.c
USER_EXEC = xdp_firewall

CLANG_FLAGS = -g -target bpf -D__TARGET_ARCH_aarch64 -I.
USER_CFLAGS = -Wall -g -I/usr/include/libbpf
USER_LDFLAGS = -lbpf -lelf -lz

all: $(BPF_OBJ) $(USER_EXEC)

$(BPF_OBJ): $(BPF_SRC)
	clang $(CLANG_FLAGS) -c $< -o $@

$(USER_EXEC): $(USER_SRC) $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > firewall_kern.skel.h
	gcc $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USER_EXEC) xdp_firewall.skel.h