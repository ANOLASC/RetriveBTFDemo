// #include <stdio.h>

#include <linux/types.h>
typedef __u32 __wsum;
#include <linux/bpf.h>
//#include "libbpf/src/bpf.h"
//#include "libbpf/src/bpf_helpers.h"
//#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, long);
	__uint(max_entries, 256);
} my_map SEC(".maps");

// int main()
// {
//     int fd;
//     const char* map_name = "my_map";
//     struct bpf_map_create_opts opts = {};

    

//     fd = bpf_map_create(
//         BPF_MAP_TYPE_HASH,
//         map_name,
//         8,
//         8,
//         100,
//         NULL
//     );

//     printf("fd: %d\n", fd);
//     if (fd <= 0) {
//         printf("fd is invalid\n");
//         return 1;
//     }

//     struct bpf_map_info info = {};
//     uint32_t sz = sizeof(info);

//     bpf_obj_get_info_by_fd(fd, &info, &sz);

//     printf("map id: %d\n", info.id);
//     printf("map btf_id: %d\n", info.btf_id);
// }