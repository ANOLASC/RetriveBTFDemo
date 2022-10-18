#include <stdint.h>
#include <stdio.h>
// /#include <linux/bpf.h>
//#include <linux/btf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>

struct btf_enum64 {
  uint32_t name_off;
  uint32_t val_lo32;
  uint32_t val_hi32;
};

#include <bpf/bpf.h>
#include <bpf/btf.h>

int main() {
  int id = 97;

  int fd = bpf_btf_get_fd_by_id(id);
  printf("fd: %d\n", fd);

  // int ret = bpf_obj_pin(fd, "/sys/fs/bpf/m");

  // printf("ret: %d\n", ret);
  struct btf *b = btf__parse_split("/home/asss/projects/btfdemo/map", NULL);

  int ret = btf__load_into_kernel(b);
    printf("ret: %d\n", ret);

  struct bpf_object* bo = bpf_object__open("/home/asss/projects/btfdemo/map");

  printf("bpf_object: %p\n", bo);

  ret = bpf_object__load(bo);
  printf("bpf_object__load ret: %d\n", ret);

  if (b) {
    printf("btf: %p\n", b);
    // printf("raw_data: %p\n", b->raw_data);
  } else {
    printf("btf: %p\n", b);
  }
}