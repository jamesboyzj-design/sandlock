#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/openat2.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>

static atomic_int done;
static void *replace(void *arg) {
    (void)arg;
    while (!atomic_load(&done)) {
        assert(symlink("safe/file", "data/next") == 0);
        assert(rename("data/next", "data/link") == 0);
        assert(symlink("/outside/missing/file", "data/next") == 0);
        assert(rename("data/next", "data/link") == 0);
    }
    return NULL;
}
int main(void) {
    char dir[] = "/tmp/openat2-race-XXXXXX";
    assert(mkdtemp(dir));
    assert(chdir(dir) == 0);
    assert(mkdir("data", 0755) == 0);
    assert(mkdir("data/safe", 0755) == 0);
    int file = open("data/safe/file", O_CREAT|O_WRONLY, 0000);
    assert(file >= 0); close(file);
    assert(symlink("safe/file", "data/link") == 0);
    int root = open(".", O_PATH|O_DIRECTORY);
    assert(root >= 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, replace, NULL) == 0);
    unsigned files=0, dirs=0, errors=0;
    struct open_how how = {.flags=O_PATH|O_CLOEXEC, .resolve=RESOLVE_IN_ROOT};
    for (unsigned i=0; i<1000000; i++) {
        int fd = syscall(SYS_openat2, root, "data/link", &how, sizeof(how));
        if (fd < 0) { errors++; continue; }
        struct stat st; assert(fstat(fd, &st) == 0);
        if (S_ISDIR(st.st_mode)) dirs++; else files++;
        close(fd);
    }
    atomic_store(&done, 1);
    pthread_join(thread, NULL);
    close(root);
    printf("KERNEL_ONLY_OPENAT2 files=%u directories=%u errors=%u\n", files, dirs, errors);
    return 0;
}
