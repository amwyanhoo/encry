#include "3Des.h"

int main() {

	int i;

	uint64_t input = 0x9474b8e8c73bca7d;
	uint64_t key1 = 0x839ab3b8c73b7ae6;
	uint64_t key2 = 0x839ab3b8c73b7ae7;
	uint64_t result1, result2, result3;

	printf("以下是加密过程\n");
	result1 = des(input, key1, 'e');
	result2 = des(result1, key2, 'd');
	result3 = des(result2, key1, 'e');
	printf("\n加密结果是" "%" PRIx64, result3);

	printf("\n******************************************************\n");

	uint64_t deinput1 = result3;
	uint64_t deinput2, deinput3;
	uint64_t exdata;
	printf("\n以下是解密过程\n");
	deinput2 = des(deinput1, key1, 'd');
	deinput3 = des(deinput2, key2, 'e');
	exdata = des(deinput3, key1, 'd');
	printf("\n解密结果是" "%" PRIx64, exdata);
	printf("\n");
	return 0;

}