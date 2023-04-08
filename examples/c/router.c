
#include "router.skel.h"
#include <bits/resource.h>
#include <signal.h>
#include <unistd.h>

bool should_wait = true;

void handle_sigint(int sig)
{
    should_wait = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memloc_rlimit(void)
{
    struct rlimit rlimit_new = {
            .rlim_cur = RLIM_INFINITY,
            .rlim_max = RLIM_INFINITY,
    };
}

int main(int argc, char **argv)
{
    struct router_bpf *skel;
    int err;

    signal(SIGINT, handle_sigint);

    libbpf_set_print(libbpf_print_fn);

    skel = router_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = router_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = router_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully Started! please run 'sudo cat /sys/kernel/debug/tracing/trace_pipe'"
           "to see output of the BPF programs.\n");

    printf("Waiting for SIGINT signal...\n");
    while (should_wait) {
        sleep(1);
    }

cleanup:
    router_bpf__destroy(skel);
    return -err;
}