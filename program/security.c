#include <bpf/libbpf.h>
#include <unistd.h>
#include "security.skel.h"

int main(int argc, char *argv[])
{
    struct security_bpf *skel;
    int err;
    skel = security_bpf__open_and_load();
    if (!skel) { 
        fprintf(stderr, "Ошибка генерации BPF каркаса.\n");
        goto cleanup;
    }
    err = security_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Ошибка внедрения BPF инструкций.\n");
        goto cleanup;
    }
    printf("BPF программа успешно загружена.\n");
    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }
cleanup:
    security_bpf__destroy(skel);
    return err;
}