#include <errno.h>
//#include <linux/bpf.h>
#include "/usr/src/linux-hwe-5.13-headers-5.13.0-52/include/uapi/linux/bpf.h"
#include "/usr/src/linux-hwe-5.13-headers-5.13.0-52/include/uapi/linux/btf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <byteswap.h>
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
	//printf("name: %s\n", (char*)info->name);
	printf("name_len: %d\n", info->name_len);
	printf("kernel_btf: %d\n", info->kernel_btf);
}

__u32 btf__type_cnt(const struct btf *btf)
{
		return btf->start_id + btf->nr_types;
}

static int btf_parse_hdr(struct btf *btf)
{
	struct btf_header *hdr = btf->hdr;
	__u32 meta_left;

	if (btf->raw_size < sizeof(struct btf_header)) {
		pr_debug("BTF header not found\n");
		return -EINVAL;
	}

	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		btf->swapped_endian = true;
		if (bswap_32(hdr->hdr_len) != sizeof(struct btf_header)) {
			pr_warn("Can't load BTF with non-native endianness due to unsupported header length %u\n",
					bswap_32(hdr->hdr_len));
			return -ENOTSUP;
		}
		btf_bswap_hdr(hdr);
	} else if (hdr->magic != BTF_MAGIC) {
		pr_debug("Invalid BTF magic: %x\n", hdr->magic);
		return -EINVAL;
	}

	if (btf->raw_size < hdr->hdr_len) {
		pr_debug("BTF header len %u larger than data size %u\n",
				hdr->hdr_len, btf->raw_size);
		return -EINVAL;
	}

	meta_left = btf->raw_size - hdr->hdr_len;
	if (meta_left < (long long)hdr->str_off + hdr->str_len) {
		pr_debug("Invalid BTF total size: %u\n", btf->raw_size);
		return -EINVAL;
	}

	if ((long long)hdr->type_off + hdr->type_len > hdr->str_off) {
		pr_debug("Invalid BTF data sections layout: type data at %u + %u, strings data at %u + %u\n",
				hdr->type_off, hdr->type_len, hdr->str_off, hdr->str_len);
		return -EINVAL;
	}

	if (hdr->type_off % 4) {
		pr_debug("BTF type section is not aligned to 4 bytes\n");
		return -EINVAL;
	}

	return 0;
}

static struct btf *btf_new(const void *data, __u32 size, struct btf *base_btf)
{
	struct btf *btf;
	int err;

	btf = calloc(1, sizeof(struct btf));
	if (!btf)
		return NULL; 

	btf->nr_types = 0;
	btf->start_id = 1;
	btf->start_str_off = 0;
	btf->fd = -1;

	if (base_btf) {
		btf->base_btf = base_btf;
		btf->start_id = btf__type_cnt(base_btf);
		btf->start_str_off = base_btf->hdr->str_len;
	}

	btf->raw_data = malloc(size);
	if (!btf->raw_data) {
		err = -ENOMEM;
		goto done;
	}
	memcpy(btf->raw_data, data, size);
	btf->raw_size = size;

	btf->hdr = btf->raw_data;
	err = btf_parse_hdr(btf);
	if (err)
		goto done;

	btf->strs_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->str_off;
	btf->types_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->type_off;

	err = btf_parse_str_sec(btf);
	err = err ?: btf_parse_type_sec(btf);
	if (err)
		goto done;

done:
	if (err) {
		btf__free(btf);
		return ERR_PTR(err);
	}

	return btf;
}

struct btf *btf_get_from_fd(int btf_fd, struct btf *base_btf)
{
	struct bpf_btf_info btf_info;
	__u32 len = sizeof(btf_info);
	__u32 last_size;
	struct btf *btf;
	void *ptr;
	int err;

	/* we won't know btf_size until we call bpf_obj_get_info_by_fd(). so
	 * let's start with a sane default - 4KiB here - and resize it only if
	 * bpf_obj_get_info_by_fd() needs a bigger buffer.
	 */
	last_size = 4096;
	ptr = malloc(last_size);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	memset(&btf_info, 0, sizeof(btf_info));
	btf_info.btf = ptr_to_u64(ptr);
	btf_info.btf_size = last_size;
	err = bpf_obj_get_info_by_fd(btf_fd, &btf_info, &len);

	if (!err && btf_info.btf_size > last_size) {
		void *temp_ptr;

		last_size = btf_info.btf_size;
		temp_ptr = realloc(ptr, last_size);
		if (!temp_ptr) {
			btf = NULL;
			goto exit_free;
		}
		ptr = temp_ptr;

		len = sizeof(btf_info);
		memset(&btf_info, 0, sizeof(btf_info));
		btf_info.btf = ptr_to_u64(ptr);
		btf_info.btf_size = last_size;

		err = bpf_obj_get_info_by_fd(btf_fd, &btf_info, &len);
	}

	if (err || btf_info.btf_size > last_size) {
		//btf = err ? ERR_PTR(-errno) : ERR_PTR(-E2BIG);
		btf = NULL;
		goto exit_free;
	}

	btf = btf_new(ptr, btf_info.btf_size, base_btf);

exit_free:
	free(ptr);
	return btf;
}

struct btf *
btf__load_from_kernel_by_id_split(__u32 id, struct btf *base_btf)
{
	struct btf *btf;
	int btf_fd;

	btf_fd = bpf_btf_get_fd_by_id(id);
	if (btf_fd < 0)
	//	return (struct btf *)-errno;
			return NULL;

	btf = btf_get_from_fd(btf_fd, base_btf);
	close(btf_fd);

	return btf;
}

struct btf *
btf__load_from_kernel_by_id(__u32 id)
{
	return btf__load_from_kernel_by_id_split(id, NULL);
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
