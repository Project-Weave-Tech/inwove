// Security 12519 (e): the kernel-keyring probe, run as the service user inside the service image. It tries one
// add_key("user", …) into the session keyring and one into the user keyring, with a throwaway random value, and
// prints one JSON line saying which were refused (and the errno's name). If an add lands (the host's syscall filter
// allows it), the key is invalidated at once. It never prints the value, the description or the key id.
// Refused both = green; landed = amber in L8 (the filter is the host's), never red; a probe that can't run = red.
// Built static in the job (gcc -static -O2), so the image needs no keyutils library.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KEY_SPEC_SESSION_KEYRING -3
#define KEY_SPEC_USER_KEYRING -4
#define KEYCTL_INVALIDATE 21
#define KEYCTL_UNLINK 9

static const char *errname(int e) {
  switch (e) {
    case EPERM: return "EPERM"; case EACCES: return "EACCES"; case ENOSYS: return "ENOSYS";
    case EDQUOT: return "EDQUOT"; case ENOKEY: return "ENOKEY"; case EKEYREVOKED: return "EKEYREVOKED";
    case EINVAL: return "EINVAL"; case ENOMEM: return "ENOMEM"; default: return "other";
  }
}

static void try_one(const char *label, long ring, int last) {
  unsigned char value[32];
  char desc[40];
  if (getrandom(value, sizeof value, 0) != (ssize_t)sizeof value) { printf("\"%s\":\"probe_failed\"%s", label, last ? "" : ","); return; }
  snprintf(desc, sizeof desc, "wpi-probe-%s-%ld", label, (long)getpid());
  long id = syscall(SYS_add_key, "user", desc, value, sizeof value, ring);
  int e = errno;
  memset(value, 0, sizeof value);
  if (id >= 0) {
    // Gone either way: invalidated, or at least unlinked from the ring it landed in.
    long inv = syscall(SYS_keyctl, KEYCTL_INVALIDATE, id);
    long unl = inv == 0 ? 0 : syscall(SYS_keyctl, KEYCTL_UNLINK, id, ring);
    printf("\"%s\":\"landed\",\"%s_removed\":%s%s", label, label, (inv == 0 || unl == 0) ? "true" : "false", last ? "" : ",");
  } else {
    printf("\"%s\":\"refused\",\"%s_errno\":\"%s\"%s", label, label, errname(e), last ? "" : ",");
  }
}

int main(void) {
  printf("{\"uid\":%d,", (int)getuid());
  try_one("session", KEY_SPEC_SESSION_KEYRING, 0);
  try_one("user", KEY_SPEC_USER_KEYRING, 1);
  printf("}\n");
  return 0;
}
