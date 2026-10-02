/*
 * Runs a chroot script's interpreter. The kernel opens a #! interpreter
 * against the host root, so for a script the supervisor execs a launcher
 * instead:
 *
 *   "#!/proc/self/fd/<us>\n" interp "\0" arg "\0" script "\0"
 *
 * and the kernel starts us with argv = { self, launcher, args... }. We exec
 * <interp> by path, which the supervisor resolves inside the image, with the
 * argv the kernel would have built for the script: { interp, [arg,] script,
 * args... }. An empty arg means the #! line had none.
 *
 * Freestanding, no libc: it is embedded in sandlock and must run in any image.
 */

typedef unsigned long u64;

#if defined(__x86_64__)
#define SYS_pread64    17
#define SYS_write      1
#define SYS_close      3
#define SYS_execve     59
#define SYS_exit_group 231
static long sc4(long n, u64 a, u64 b, u64 c, u64 d) {
    long r;
    register u64 r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return r;
}
#elif defined(__aarch64__)
#define SYS_pread64    67
#define SYS_write      64
#define SYS_close      57
#define SYS_execve     221
#define SYS_exit_group 94
static long sc4(long n, u64 a, u64 b, u64 c, u64 d) {
    register long x8 __asm__("x8") = n;
    register u64 x0 __asm__("x0") = a;
    register u64 x1 __asm__("x1") = b;
    register u64 x2 __asm__("x2") = c;
    register u64 x3 __asm__("x3") = d;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return (long)x0;
}
#elif defined(__riscv) && __riscv_xlen == 64
#define SYS_pread64    67
#define SYS_write      64
#define SYS_close      57
#define SYS_execve     221
#define SYS_exit_group 94
static long sc4(long n, u64 a, u64 b, u64 c, u64 d) {
    register long a7 __asm__("a7") = n;
    register u64 a0 __asm__("a0") = a;
    register u64 a1 __asm__("a1") = b;
    register u64 a2 __asm__("a2") = c;
    register u64 a3 __asm__("a3") = d;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a7) : "memory");
    return (long)a0;
}
#else
#error "unsupported architecture"
#endif

/* #! line, interpreter and argument (BINPRM_BUF_SIZE each at most), PATH_MAX. */
static char buf[3 * 256 + 4096 + 1];

__attribute__((noreturn)) static void fail(const char *msg) {
    u64 n = 0;
    while (msg[n])
        n++;
    sc4(SYS_write, 2, (u64)msg, n, 0);
    sc4(SYS_exit_group, 127, 0, 0, 0);
    __builtin_unreachable();
}

/* The next NUL-terminated field in buf[*at..end), or 0. */
static char *field(long *at, long end) {
    char *s = buf + *at;
    while (*at < end && buf[*at])
        (*at)++;
    if (*at >= end)
        return 0;
    (*at)++;
    return s;
}

/* `used`: the only reference is the module-level asm below. */
__attribute__((used, noreturn)) static void trampoline(u64 *sp) {
    long argc = (long)sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;

    if (argc < 2)
        fail("sandlock: shebang trampoline run directly\n");
    /* argv[1] is /proc/self/fd/<launcher>, a path the supervisor wrote. */
    char *p = argv[1];
    for (char *q = p; *q; q++)
        if (*q == '/')
            p = q + 1;
    long fd = 0;
    for (; *p >= '0' && *p <= '9'; p++)
        fd = fd * 10 + (*p - '0');
    long n = sc4(SYS_pread64, fd, (u64)buf, sizeof(buf) - 1, 0);
    sc4(SYS_close, fd, 0, 0, 0);
    if (n <= 0)
        fail("sandlock: cannot read shebang launcher\n");

    long at = 0;
    while (at < n && buf[at] != '\n')
        at++;
    at++;
    char *interp = field(&at, n);
    char *arg = field(&at, n);
    char *script = field(&at, n);
    if (!script)
        fail("sandlock: malformed shebang launcher\n");

    char *nargv[argc + 2];
    long k = 0;
    nargv[k++] = interp;
    if (*arg)
        nargv[k++] = arg;
    nargv[k++] = script;
    for (long i = 2; i < argc; i++)
        nargv[k++] = argv[i];
    nargv[k] = 0;
    sc4(SYS_execve, (u64)interp, (u64)nargv, (u64)envp, 0);
    fail("sandlock: cannot exec #! interpreter\n");
}

#if defined(__x86_64__)
__asm__(
    ".global _start\n"
    "_start:\n"
    "   xor %rbp, %rbp\n"
    "   mov %rsp, %rdi\n"
    "   and $-16, %rsp\n"
    "   call trampoline\n"
    "   hlt\n"
);
#elif defined(__aarch64__)
__asm__(
    ".global _start\n"
    "_start:\n"
    "   mov x0, sp\n"
    "   bl trampoline\n"
    "   brk #0\n"
);
#elif defined(__riscv) && __riscv_xlen == 64
__asm__(
    ".global _start\n"
    "_start:\n"
    "   mv a0, sp\n"
    "   call trampoline\n"
    "   unimp\n"
);
#endif
