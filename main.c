#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdbool.h>

#include "/home/asss/projects/btfdemo/libbpf/src/btf.h"
#include "/home/asss/projects/btfdemo/libbpf/src/bpf.h"

struct btf {
	void *raw_data;
	void *raw_data_swapped;
	__u32 raw_size;
	bool swapped_endian;
	struct btf_header *hdr;

	void *types_data;
	size_t types_data_cap; /* used size stored in hdr->type_len */
	__u32 *type_offs;
	size_t type_offs_cap;
	__u32 nr_types;
	struct btf *base_btf;
	int start_id;
	int start_str_off;
	void *strs_data;
	struct strset *strs_set;
	bool strs_deduped;
	int fd;
	int ptr_sz;
};

	static inline __u64
ptr_to_u64 (const void* ptr)
{
	return (__u64)(unsigned long)ptr;
}

	static inline int
sys_bpf (enum bpf_cmd cmd, union bpf_attr* attr, unsigned int size)
{
	return syscall (__NR_bpf, cmd, attr, size);
}

	static inline int
sys_bpf_fd (enum bpf_cmd cmd, union bpf_attr* attr, unsigned int size)
{
	int fd;

	fd = sys_bpf (cmd, attr, size);
	return fd;
}

// BPF_{PROG,MAP}_GET_NEXT_ID (get prog/map id's)
// BPF_{PROG,MAP}_GET_FD_BY_ID (get a prog/map fd)
// BPF_OBJ_GET_INFO_BY_FD (get bpf_prog_info/bpf_map_info with btf_id)
// BPF_BTF_GET_FD_BY_ID (get btf_fd) 
// BPF_OBJ_GET_INFO_BY_FD (get btf)          

void
print_bpf_btf_info(struct bpf_btf_info *info)
{
	printf("btf: %lld\n", info->btf);
	printf("btf_size: %d\n", info->btf_size);
	printf("id: %d\n", info->id);
	//printf("name: %s\n", (char*)info->name);
	printf("name_len: %d\n", info->name_len);
	printf("kernel_btf: %d\n", info->kernel_btf);
}

struct btf*
get_bpf_btf_info(__u32 id)
{
	return btf__load_from_kernel_by_id(id);
}

int
main() 
{
	int err = 0;
	__u32 id = 0;
	int fd = 0;
	int iter = 2;
	while (iter--) {
		err = bpf_prog_get_next_id(id, &id);

		struct btf* btf = get_bpf_btf_info(id);
		printf("id: %d ", id);
		fd = bpf_prog_get_fd_by_id(id);
		printf("fd: %d ", fd);

		struct bpf_btf_info btf_info = {};
		__u32 len = sizeof(btf_info);
		err = bpf_obj_get_info_by_fd(fd, &btf_info, &len);
		// printf("err: %d", err);

		print_bpf_btf_info(&btf_info);

		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			//p_err("can't get next program: %s%s", strerror(errno),
			//		errno == EINVAL ? " -- kernel too old?" : "");
			err = -1;
			break;
		}
		printf("\n");
	}
}
