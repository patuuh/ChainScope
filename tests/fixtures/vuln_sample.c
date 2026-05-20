// Test fixture with deliberate vulnerability patterns for security scoring tests

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

// buffer_overflow_risk: strcpy with variable source
void copy_name(char *dest, const char *src) {
    strcpy(dest, src);
}

// buffer_overflow_risk: sprintf with no bounds
void format_message(char *buf, const char *user) {
    sprintf(buf, "Hello, %s!", user);
}

// format_string_risk: printf with variable format
void log_input(const char *fmt) {
    printf(fmt);
}

// format_string_risk: fprintf with variable format
void log_to_file(FILE *fp, const char *msg) {
    fprintf(fp, msg);
}

// command_injection_risk: system with variable arg
void run_command(const char *cmd) {
    system(cmd);
}

// command_injection_risk: popen with variable arg
FILE *run_pipe(const char *cmd) {
    return popen(cmd, "r");
}

// use_after_free_risk: free then use
void process_data(int *data) {
    free(data);
    int x = data[0];
}

// NOT use_after_free: free then reassign then use
void safe_realloc(int *p) {
    free(p);
    p = malloc(sizeof(int) * 10);
    p[0] = 42;
}

// double_free_risk: free called twice on same pointer
void cleanup_twice(char *buf) {
    free(buf);
    free(buf);
}

// null_deref_risk: malloc without NULL check
void alloc_no_check(int n) {
    int *p = malloc(n * sizeof(int));
    p[0] = 1;
}

// null_deref_risk: calloc without NULL check
void alloc_calloc(int n) {
    int *p = calloc(n, sizeof(int));
    p[0] = 1;
}

// NOT null_deref: malloc with NULL check
void alloc_safe(int n) {
    int *p = malloc(n * sizeof(int));
    if (p == NULL) return;
    p[0] = 1;
}

// toctou_risk: access then open
int check_and_open(const char *path) {
    if (access(path, R_OK) == 0) {
        return open(path, 0);
    }
    return -1;
}

// path_traversal_risk: fopen with parameter-derived path
FILE *open_user_file(const char *filename) {
    return fopen(filename, "r");
}

// integer_overflow_risk: arithmetic on param used in malloc
void alloc_computed(int count) {
    int *p = malloc(count * sizeof(int));
    if (p) free(p);
}

// uninitialized_use: variable used before assignment
int use_uninit(void) {
    int x;
    return x + 1;
}

// NOT command_injection: system with string literal
void run_literal(void) {
    system("ls -la");
}

// NOT path_traversal: fopen with string literal
FILE *open_config(void) {
    return fopen("/etc/config.txt", "r");
}

// clean function: no vulnerabilities
int add(int a, int b) {
    return a + b;
}

// Multiple risks: buffer overflow + format string
void dangerous_combo(char *buf, const char *user_fmt) {
    sprintf(buf, user_fmt);
    printf(user_fmt);
}
