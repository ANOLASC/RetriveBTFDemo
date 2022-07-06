#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdbool.h>

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

static inline int
bpf_btf_get_fd_by_id(__u32 id)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.btf_id = 0;
	int btf_fd = sys_bpf_fd(BPF_BTF_GET_FD_BY_ID, &attr, sizeof(attr));

	return btf_fd;
}

int 
bpf_obj_get_next_id(__u32 start_id, __u32 *next_id, enum bpf_cmd cmd)
{
	union bpf_attr attr;
	int err;

	memset(&attr, 0, sizeof(attr));
	attr.start_id = start_id;

	err = sys_bpf(cmd, &attr, sizeof(attr));
	if (!err)
		*next_id = attr.next_id;

	return err;
}

int
bpf_btf_get_next_id(__u32 start_id, __u32 *next_id)
{
	return bpf_obj_get_next_id(start_id, next_id, BPF_BTF_GET_NEXT_ID);
}

int 
bpf_prog_get_next_id(__u32 start_id, __u32 *next_id)
{
	return bpf_obj_get_next_id(start_id, next_id, BPF_PROG_GET_NEXT_ID);
}

int 
bpf_prog_get_fd_by_id(__u32 id)
{
	union bpf_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));
	attr.prog_id = id;

	fd = sys_bpf_fd(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
	return fd;
}

int 
bpf_obj_get_info_by_fd(int bpf_fd, void *info, __u32 *info_len)
{
	union bpf_attr attr;
	int err;

	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = bpf_fd;
	attr.info.info_len = *info_len;
	attr.info.info = ptr_to_u64(info);

	err = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));

	if (!err)
		*info_len = attr.info.info_len;

	return err;
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
	// printf("name: %d\n", info->name);
	// printf("name_len: %d\n", info->name_len);
	// printf("kernel_btf: %d\n", info->kernel_btf);
}

int
main() 
{
	int err = 0;
	__u32 id = 0;
	int fd = 0;
	while (true) {
		err = bpf_prog_get_next_id(id, &id);
		printf("id: %d ", id);
		fd = bpf_prog_get_fd_by_id(id);
		printf("fd: %d ", fd);

		struct bpf_btf_info btf_info = {};
		__u32 len = sizeof(btf_info);
		err = bpf_obj_get_info_by_fd(fd, &btf_info, &len);
		// printf("err: %d", err);

		print_bpf_btf_info(&btf_info);

		// struct bpf_btf_info {
		// 	__aligned_u64 btf;
		// 	__u32 btf_size;
		// 	__u32 id;
		// 	__aligned_u64 name;
		// 	__u32 name_len;
		// 	__u32 kernel_btf;
		// } __attribute__((aligned(8)));

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
