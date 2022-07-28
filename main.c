#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdbool.h>

#include "libbpf/src/btf.h"
#include "libbpf/src/bpf.h"

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

// BPF_{PROG,MAP}_GET_NEXT_ID (get map/map id's)
// BPF_{PROG,MAP}_GET_FD_BY_ID (get a map/map fd)
// BPF_OBJ_GET_INFO_BY_FD (get bpf_map_info/bpf_map_info with btf_id)
// BPF_BTF_GET_FD_BY_ID (get btf_fd) 
// BPF_OBJ_GET_INFO_BY_FD (get btf)          

void
print_bpf_btf_info(struct bpf_btf_info *info)
{
	if (info->name_len == 0) {
		printf("name len is 0\n");
		return ;
	}
	printf("btf: %p\n", (struct btf*)info->btf);
	printf("btf_size: %d\n", info->btf_size);
	printf("id: %d\n", info->id);
	printf("name: %s\n", (char*)info->name);
	printf("name_len: %d\n", info->name_len);
	printf("kernel_btf: %d\n", info->kernel_btf);
}

void
print_bpf_prog_info(struct bpf_prog_info *info)
{
	printf("bpf_prog_info\n");
	printf("----------\n");
	printf("name: %s\n", info->name);
	printf("jited_prog_len: %d\n", info->jited_prog_len);
	printf("xlated_prog_len: %d\n",	info->xlated_prog_len);
	printf("----------\n");
}

void
print_bpf_map_info(struct bpf_map_info *info)
{
  printf("bpf_map_info\n");
	printf("----------\n");
	printf("name: %s\n", info->name);
	printf("id: %d\n", info->id);
	printf("key_size: %d\n", info->key_size);
	printf("value_size: %d\n", info->value_size);
	printf("max_entries: %d\n", info->max_entries);
	printf("----------\n");
}

struct btf*
get_bpf_btf_info(__u32 id)
{
	return btf__load_from_kernel_by_id(id);
}

void
do_prog(int id)
{
	int fd = bpf_prog_get_fd_by_id(id);
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	bpf_obj_get_info_by_fd(fd, &info, &len);
	printf("info len: %d\n", len);
	print_bpf_prog_info(&info);

	int btf_id = info.btf_id;
	int btf_fd = bpf_btf_get_fd_by_id(btf_id);

	struct bpf_btf_info btf_info = {};
	__u32 btf_info_len = sizeof(btf_info);
	bpf_obj_get_info_by_fd(btf_fd, &btf_info, &btf_info_len);
	print_bpf_btf_info(&btf_info);
	return ;
}

void
do_map(int id)
{
	int fd = bpf_map_get_fd_by_id(id);
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	bpf_obj_get_info_by_fd(fd, &info, &len);
	printf("info len: %d\n", len);
	print_bpf_map_info(&info);

	int btf_id = info.btf_id;
	int btf_fd = bpf_btf_get_fd_by_id(btf_id);

	struct bpf_btf_info btf_info = {};
	__u32 btf_info_len = sizeof(btf_info);
	bpf_obj_get_info_by_fd(btf_fd, &btf_info, &btf_info_len);
	print_bpf_btf_info(&btf_info);
	return ;
}

int
main(int argc, char** argv) 
{
	// int id = 45;
	// int id = 9;
	if (argc < 3) {
		return -1;
	}
		
	int id = atoi(argv[2]);
	struct btf* btf = btf__load_from_kernel_by_id(id);
	printf("btf: %p\n", btf);
	printf("id: %d\n", id);
	
	if (!strcmp(argv[1], "map")) {
		do_map(id);
	} else if (!strcmp(argv[1], "prog")) {
		do_prog(id);
	} else
		;

	return 0;
}
