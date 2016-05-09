/*
* Data Encryption Standard
* An approach to DES algorithm
*
* By: Daniel Huertas Gonzalez
* Email: huertas.dani@gmail.com
* Version: 0.1
*
* Based on the document FIPS PUB 46-3
*/
#include "3Des.h"

/*
* The DES function
* input: 64 bit message
* key: 64 bit key for encryption/decryption
* mode: 'e' = encryption; 'd' = decryption
*/
uint64_t des(uint64_t input, uint64_t key, char mode) {

	int i, j;

	/* 8 bits */
	char row, column;

	/* 28 bits */
	uint32_t C = 0;
	uint32_t D = 0;  

	/* 32 bits */
	uint32_t L = 0;
	uint32_t R = 0;
	uint32_t s_output = 0;
	uint32_t f_function_res = 0;
	uint32_t temp = 0;

	/* 48 bits */
	uint64_t sub_key[16] = { 0 };
	uint64_t s_input = 0;

	/* 56 bits */
	uint64_t permuted_choice_1 = 0;
	uint64_t permuted_choice_2 = 0;

	/* 64 bits */
	uint64_t init_perm_res = 0;
	uint64_t inv_init_perm_res = 0;
	uint64_t pre_output = 0;

	/* initial key schedule calculation �Ա�PC1[i]������Կ���б任*/
	for (i = 0; i < 56; i++) {

		permuted_choice_1 <<= 1;
		permuted_choice_1 |= (key >> (64 - PC1[i])) & LB64_MASK;

	}
	//printf("permuted_choice_1=  " "%" PRIx64, permuted_choice_1);
	//���任������ݷֳ������֣���28λ
	C = (uint32_t)((permuted_choice_1 >> 28) & 0x000000000fffffff);
	D = (uint32_t)(permuted_choice_1 & 0x000000000fffffff);
	/*printf("\nC[0]= " "%" PRIx64, C);
	printf("\nD[0]= " "%" PRIx64, D);
	printf("\n");*/
	
	/* Calculation of the 16 keys����16������Կ */
	for (i = 0; i< 16; i++) {

		/* key schedule */
		// shifting Ci and Di
		for (j = 0; j < iteration_shift[i]; j++) {
			//����1λ��2λ����
			C = 0x0fffffff & (C << 1) | 0x00000001 & (C >> 27);	
			D = 0x0fffffff & (D << 1) | 0x00000001 & (D >> 27);

		}
		/*printf("\nC[%d]= " "%" PRIx64,i+1, C);
		printf("\nD[%d]= " "%" PRIx64, i + 1, D);*/
		
		//�������������Ci��Di���õ�permuted_choice_2��Ϊ28*2=56λ
		permuted_choice_2 = 0;
		permuted_choice_2 = (((uint64_t)C) << 28) | (uint64_t)D;
		//printf("\npermuted_choice_2= " "%" PRIx64, permuted_choice_2);
		//����56λpermuted_choice_2�Ա任��PC2�任��48λ��sub_key[i]��Ϊһ������Կ
		sub_key[i] = 0;		
		for (j = 0; j < 48; j++) {

			sub_key[i] <<= 1;
			sub_key[i] |= (permuted_choice_2 >> (56 - PC2[j])) & LB64_MASK;

		}
		//printf("\nsub_key[%d]= " "%" PRIx64, i+1, sub_key[i]);
	}

	/* initial permutation���ĵĳ�ʼ��ת�� */
	for (i = 0; i < 64; i++) {

		init_perm_res <<= 1;
		init_perm_res |= (input >> (64 - IP[i])) & LB64_MASK;

	}
	//printf("\n\ninit_perm_res= " "%" PRIx64, init_perm_res);
	//�ѱ任�������init_perm_res�ֳ����飬��32λ
	L = (uint32_t)(init_perm_res >> 32) & L64_MASK;
	R = (uint32_t)init_perm_res & L64_MASK;

	/*printf("\nL[0]= " "%" PRIx32, L);
	printf("\nR[0]= " "%" PRIx32, R);*/
	
	for (i = 0; i < 16; i++) {

		/* f(R,k) function */
		s_input = 0;

		//��32λ�ı任�����ĺ�벿��R��E�任����չ��48λ��s_input
		for (j = 0; j< 48; j++) {

			s_input <<= 1;
			s_input |= (uint64_t)((R >> (32 - E[j])) & LB32_MASK);

		}
		//printf("\nE(R[%d])= " "%" PRIx64, i + 1, s_input);

		/*
		* Encryption/Decryption
		* XORing expanded Ri with Ki
		*/
		if (mode == 'd') {
			// decryption
			s_input = s_input ^ sub_key[15 - i];
			//printf("\n��չ�������%d������Կ������= " "%" PRIx64, 16 - i, L);
		}
		else {
			// encryption
			//ÿ����չ��ĺ�벿��R����һ������Կ����������
			s_input = s_input ^ sub_key[i];
			//printf("\n��չ�������%d������Կ������= " "%" PRIx64, i+1, L);

		}

		/* S-Box Tables S�б任*/
		for (j = 0; j < 8; j++) {
			// 00 00 RCCC CR00 00 00 00 00 00 s_input
			// 00 00 1000 0100 00 00 00 00 00 row mask
			// 00 00 0111 1000 00 00 00 00 00 column mask

			row = (char)((s_input & (0x0000840000000000 >> 6 * j)) >> 42 - 6 * j);
			row = (row >> 4) | row & 0x01;

			column = (char)((s_input & (0x0000780000000000 >> 6 * j)) >> 43 - 6 * j);
			//����S�б任�õ���8��4λ���������õ�32λ��
			s_output <<= 4;
			s_output |= (uint32_t)(S[j][16 * row + column] & 0x0f);
		}
		//printf("\n����S�б任�����������= " "%" PRIx32, s_output);

		f_function_res = 0;

		//�Ա�P��s_output���б任
		for (j = 0; j < 32; j++) {
			f_function_res <<= 1;
			f_function_res |= (s_output >> (32 - P[j])) & LB32_MASK;

		}
		//printf("\nf_function_res= " "%" PRIx32, f_function_res);

		temp = R;
		R = L ^ f_function_res;
		L = temp;
		/*printf("\nL[%d]= " "%" PRIx32, i+1, L);
		printf("\nR[%d]= " "%" PRIx32, i+1, R);*/
	}

	//������L,R�ϲ���64λpre_output
	pre_output = (((uint64_t)R) << 32) | (uint64_t)L;
	//printf("\nf_function_res= " "%" PRIx64, pre_output);
	/* inverse initial permutation 
	��PI��pre_output���б任*/
	for (i = 0; i < 64; i++) {

		inv_init_perm_res <<= 1;
		inv_init_perm_res |= (pre_output >> (64 - PI[i])) & LB64_MASK;

	}

	//�������Ľ��inv_init_perm_res
	return inv_init_perm_res;

}

//int main(int argc, const char * argv[]) {
//
//	int i;
//
//	uint64_t input = 0x9474B8E8C73BCA7D;
//	uint64_t key = 0x0000000000000000;
//	uint64_t result = input;
//
//	/*
//	* TESTING IMPLEMENTATION OF DES
//	* Ronald L. Rivest
//	* X0:  9474B8E8C73BCA7D
//	* X16: 1B1A2DDB4C642438
//	*
//	* OUTPUT:
//	* E: 8da744e0c94e5e17
//	* D: 0cdb25e3ba3c6d79
//	* E: 4784c4ba5006081f
//	* D: 1cf1fc126f2ef842
//	* E: e4be250042098d13
//	* D: 7bfc5dc6adb5797c
//	* E: 1ab3b4d82082fb28
//	* D: c1576a14de707097
//	* E: 739b68cd2e26782a
//	* D: 2a59f0c464506edb
//	* E: a5c39d4251f0a81e
//	* D: 7239ac9a6107ddb1
//	* E: 070cac8590241233
//	* D: 78f87b6e3dfecf61
//	* E: 95ec2578c2c433f0
//	* D: 1b1a2ddb4c642438  <-- X16
//	*/
//	for (i = 0; i < 16; i++) {
//
//		if (i % 2 == 0) {
//
//			result = des(result, result, 'e');
//			printf("E: %016llx\n", result);
//
//		}
//		else {
//
//			result = des(result, result, 'd');
//			printf("D: %016llx\n", result);
//
//		}
//	}
//
//	//result = des(input, key, 'e');
//	//printf ("E: %016llx\n", result);
//
//	//result = des(result, key, 'd');
//	//printf ("D: %016llx\n", result);
//
//	exit(0);
//
//}
