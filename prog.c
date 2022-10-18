struct fwd_struct;

enum my_enum {
	VAL1 = 3,
	VAL2 = 7,
};

typedef struct my_struct my_struct_t;

struct my_struct {
	const unsigned int const_int_field;
	int bitfield_field: 4;
	char arr_field[16];
	const struct fwd_struct *restrict fwd_field;
	enum my_enum enum_field;
	volatile my_struct_t *typedef_ptr_field;
};

union my_union {
	int a;
	struct my_struct b;
};

struct my_struct struct_global_var __attribute__((section("data_sec"))) = {
	.bitfield_field = 3,
	.enum_field = VAL1,
};

int global_var __attribute__((section("data_sec"))) = 7;

__attribute__((noinline))
int my_func(union my_union *arg1, int arg2)
{
	static int static_var __attribute__((section("data_sec"))) = 123;
	static_var++;
	return static_var;
}
