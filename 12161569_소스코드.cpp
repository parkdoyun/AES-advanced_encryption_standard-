#include <iostream>
#include <fstream>
#include <string>

using namespace std;

// 컴퓨터보안 AES 과제
// 12161569 컴퓨터공학과 박도윤

const unsigned int gf_poly = 0x01E7; // x^8 + x^7 + x^6 + x^5 + x^2 + x + 1

void KeyExpansion(unsigned int [], unsigned int []); // key 확장 함수
unsigned int g(unsigned int, int); // g 함수
int deg(unsigned int); // degree 계산 함수
void bin_ext_euclid(unsigned int, unsigned int, unsigned int &, unsigned int &, unsigned int &); // extended euclid 함수
unsigned int bin_inv(unsigned int, unsigned int); // 역원 구하는 함수
unsigned int sBox(unsigned int, const unsigned int); // s-box 연산 함수
unsigned int sBox_inv(unsigned int, const unsigned int); // 역 s-box 연산 함수
void SubBytes(unsigned int []); // substitution bytes 함수
void SubBytes_inv(unsigned int[]); // 역 substitution bytes 함수
void ShiftRow(unsigned int []); // shift row 함수
void ShiftRow_inv(unsigned int[]); // 역 shift row 함수
unsigned int bin_mul(unsigned int, unsigned int); // 곱셈 연산 함수
void MixColumn(unsigned int[]); // mix column 함수
void MixColumn_inv(unsigned int[]); // 역 mix column 함수

#define KEYFILE "key.bin"
#define PLAINTEXT "plain.bin"
#define CIPHERTEXT "cipher.bin"
#define PLAIN2FILE "plain2.bin"

int main(int argc, char *argv[])
{	
	// key.bin 열기 
	ifstream is_k(KEYFILE, ios::binary);
	if (!is_k) // error
	{
		cerr << "File could not be opened." << endl;
		exit(EXIT_FAILURE);
	}
	is_k.seekg(0, ios::end);
	int file_len = is_k.tellg(); // key.bin 파일 크기
	is_k.seekg(0, ios::beg);	
	int n;
	
	unsigned int input_key[4] = { 0 }; // key.bin data 저장용 배열
	unsigned int key[44] = { 0 }; // 확장된 key용 배열

	for (int i = 0; i < (file_len / 4); i++)
	{		
		for (int j = 0; j < 4; j++)
		{
			n = 0;
			is_k.read((char *)&n, sizeof(char)); // key.bin 읽기	
			unsigned int tmp = n;
			tmp = tmp << (8 * (4 - j - 1));
			input_key[i] |= tmp; // 읽은 값 배열에 넣기
		}
		
	}
	is_k.close();	
	
	KeyExpansion(input_key, key); // key 확장

	unsigned int temp[4] = { 0 };

	// output 열기 => e 입력 시 cipher.bin / d 입력 시 plain2.bin 열기
	ofstream os;
	if (strncmp(argv[1], "e", 1) == 0) os.open(CIPHERTEXT, ios::binary);
	else if (strncmp(argv[1], "d", 1) == 0) os.open(PLAIN2FILE, ios::binary);
	if (!os) // error
	{
		cerr << "File could not be created." << endl;
		exit(EXIT_FAILURE);
	}

	
	if (strncmp(argv[1], "e", 1) == 0) // encryption
	{
		ifstream is_p(PLAINTEXT, ios::binary); // plain.bin 열기
		if (!is_p) // error
		{
			cerr << "File could not be opened." << endl;
			exit(EXIT_FAILURE);
		}
		
		is_p.seekg(0, ios::end); 
		file_len = is_p.tellg(); // input 크기 확인
		is_p.seekg(0, ios::beg);
		int n;

		for (int cnt = 0; cnt < (file_len / 16); cnt++) // input이 16 byte의 배수일수도 있으므로 for문 사용
		{
			unsigned int plain[4] = { 0 }; // plain.bin data 저장용 배열

			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					n = 0;
					is_p.read((char *)&n, sizeof(char)); // plain.bin 읽기
					unsigned int tmp = n;
					tmp = tmp << (8 * (4 - j - 1));
					plain[i] |= tmp; // 배열에 넣기
				}

			}


			// add round key
			for (int i = 0; i < 4; i++)
			{
				temp[i] = key[i] ^ plain[i]; // XOR
			}

			// 10 round
			for (int i = 1; i <= 10; i++)
			{
				SubBytes(temp); // substitution bytes
				ShiftRow(temp); // shift row
				if (i != 10) MixColumn(temp); // 10 round에서 mix column 연산 제외
				for (int j = 0; j < 4; j++) // add round key
				{
					temp[j] = key[i * 4 + j] ^ temp[j]; // XOR
				}
				cout << endl << "-------- round [" << i << "] --------" << endl; // round마다 값 출력
				for (int i = 0; i < 4; i++)
				{
					cout.width(8); // 8자리로 출력
					cout.fill('0'); // 빈 자리 0으로 채우기
					cout << std::hex << temp[i] << ' ';
				}
				cout << endl;

			}
			for (int i = 0; i < 4; i++) // output 파일에 값 쓰기
			{
				for (int j = 0; j < 4; j++)
				{
					unsigned int tmp = 0xFF;
					tmp = tmp << (8 * (4 - j - 1));
					tmp = tmp & temp[i];
					tmp = tmp >> (8 * (4 - j - 1));					
					os.write((char *)&tmp, sizeof(char)); // 쓰기
				}

			}			
		}
		is_p.close();
	}
	else if (strncmp(argv[1], "d", 1) == 0) // decryption
	{		
		ifstream is_c(CIPHERTEXT, ios::binary); // cipher.bin 열기
		if (!is_c) // error
		{
			cerr << "File could not be opened." << endl;
			exit(EXIT_FAILURE);
		}

		is_c.seekg(0, ios::end); 
		file_len = is_c.tellg(); // input 크기 확인
		is_c.seekg(0, ios::beg);
		int n;

		for (int cnt = 0; cnt < (file_len / 16); cnt++) // input이 16 byte의 배수일수도 있으므로 for문 사용
		{

			unsigned int cipher[4] = { 0 }; // cipher.bin data 저장용 배열

			for (int i = 0; i < 4; i++)
			{
				for (int j = 0; j < 4; j++)
				{
					n = 0;
					is_c.read((char *)&n, sizeof(char)); // cipher.bin 읽기
					unsigned int tmp = n;
					tmp = tmp << (8 * (4 - j - 1));
					cipher[i] |= tmp; // 배열에 넣기
				}

			}


			// add round key
			for (int i = 0; i < 4; i++)
			{
				temp[i] = key[40 + i] ^ cipher[i]; // XOR
			}

			// 10 round
			for (int i = 1; i <= 10; i++) 
			{
				ShiftRow_inv(temp); // shift row (inverse)
				SubBytes_inv(temp); // substitution bytes (inverse)
				for (int j = 0; j < 4; j++) // add round key
				{
					temp[j] = key[40 - (i * 4) + j] ^ temp[j]; // XOR
				}
				if (i != 10) MixColumn_inv(temp); // 10 round 에서 mix column 제외

				cout << endl << "-------- round [" << i << "] --------" << endl; // round마다 출력
				for (int i = 0; i < 4; i++)
				{
					cout.width(8); // 8자리로 출력
					cout.fill('0'); // 빈 자리 0으로 채우기
					cout << std::hex << temp[i] << ' ';
				}
				cout << endl;
			}

			for (int i = 0; i < 4; i++) // output 파일에 값 쓰기
			{
				for (int j = 0; j < 4; j++)
				{
					unsigned int tmp = 0xFF;
					tmp = tmp << (8 * (4 - j - 1));
					tmp = tmp & temp[i];
					tmp = tmp >> (8 * (4 - j - 1));					
					os.write((char *)&tmp, sizeof(char)); // 쓰기
				}

			}			
		}
		is_c.close();
	}
	else // e나 d 외에 다른 명령어 입력 시
	{
		cout << "invalid instruction." << endl;
		return 0;
	}

	os.close();

	return 0;
}

void KeyExpansion(unsigned int key[], unsigned int w[]) // key 확장 함수
{	
	unsigned int temp = 0;

	for (int i = 0; i < 4; i++) // 처음 0~3번째에 원래 key 값 저장
	{
		w[i] = key[i];
	}	
	
	for (int i = 4; i < 44; i++)
	{
		if (i % 4 == 0)
		{
			//g function
			temp = g(w[i - 1], i / 4);
			w[i] = w[i - 4] ^ temp;
			continue;
		}
		w[i] = w[i - 4] ^ w[i - 1];
	}
		
}

unsigned int g(unsigned int w, int round) // g 함수
{
	unsigned int b = w;
	unsigned int temp = 0xFF000000;
	temp = temp & b; // B0 위치 이동
	b = (b << 8);
	temp = temp >> 24;
	b = b | temp; // B1, B2, B3, B0 순서로 이동
	
	// s-box
	unsigned int temp1;
	unsigned int res = 0;
	for (int i = 0; i < 4; i++) // B1, B2, B3, B0 각각 s-box 연산
	{
		temp = 0xFF;
		temp = temp << (8 * i);
		temp = temp & b;
		temp = temp >> (8 * i);
		temp1 = sBox(temp, gf_poly);
		temp1 = temp1 << (8 * i);
		res = res | temp1;
	}
	
	// XOR with RC
	if (round <= 8)
	{
		temp = 0x1;
		temp = temp << (round - 1);
	}
	else if (round == 9) // 9
	{
		temp = 0x0FF;
		temp = temp & gf_poly;
	}
	else // 10, round constant가 left shift해서 다시 carry 발생할 경우 고려
	{
		temp = 0x0FF;
		temp = temp & gf_poly; // rc9
		if ((temp & 0x080) != 0) // rc9의 MSB가 1일 경우 (carry 발생)
		{
			unsigned int rc9 = temp;
			temp = (temp << 1) ^ rc9; // rc10 = (rc9 << 1) XOR rc9
		}
		else // carry 발생 안 할 경우
		{
			temp = temp << 1; // shift
		}
	}
	temp = temp << 24;
	res = res ^ temp; // XOR

	return res;
}

unsigned int sBox(unsigned int b, const unsigned int gf) // s-box 함수
{
	unsigned int b_inv = bin_inv(b, gf); // 역원 구하는 연산
	int c[8] = { 1, 1, 0, 0, 0, 1, 1, 0 }; // 0x63
	int b_arr[8] = { 0 }; 
	for (int i = 0; i < 8; i++) // b_inv 값 이진수 형태로 만들어서 배열에 넣기 
	{
		b_arr[i] = b_inv % 2;
		b_inv /= 2;
	}
	int b_prime[8] = { 0 };
	for (int i = 0; i < 8; i++)
	{ // 각 바이트의 비트들에 대하여 변환 수행
		b_prime[i] = b_arr[i] ^ b_arr[(i + 4) % 8] ^ b_arr[(i + 5) % 8] ^ b_arr[(i + 6) % 8] ^ b_arr[(i + 7) % 8] ^ c[i];
	}
	unsigned int res = 0;
	for (int i = 0; i < 8; i++)
	{
		if (b_prime[i] == 1) res += pow(2, i); // 이진수 형태의 배열을 다시 값으로 변환
	}
	return res;
}

unsigned int sBox_inv(unsigned int b, const unsigned int gf) // 역 s-box 함수
{
	int d[8] = { 1, 0, 1, 0, 0, 0, 0, 0 }; // 0x05
	int b_arr[8] = { 0 };
	unsigned int b_tmp = b;
	for (int i = 0; i < 8; i++) // 이진수 형태로 만들어서 배열에 넣기 
	{
		b_arr[i] = b_tmp % 2;
		b_tmp /= 2;
	}
	int b_prime[8] = { 0 };
	for (int i = 0; i < 8; i++)
	{ // 각 바이트의 비트들에 대하여 변환 수행
		b_prime[i] = b_arr[(i + 2) % 8] ^ b_arr[(i + 5) % 8] ^ b_arr[(i + 7) % 8] ^ d[i];
	}
	unsigned int res = 0;
	for (int i = 0; i < 8; i++)
	{
		if (b_prime[i] == 1) res += pow(2, i); // 이진수 형태의 배열을 다시 값으로 변환
	}
	res = bin_inv(res, gf); // 역원 구하는 연산
	return res;
}

int deg(unsigned int poly) // degree 계산 함수
{
	unsigned int cmp = 0x8000;
	unsigned int temp = 0;
	// 하나씩 cmp 오른쪽으로 shift하면서 AND 연산
	for (int i = 15; i > 0; i--)
	{
		temp = poly & cmp;
		if (temp != 0)
		{
			return i;
		}
		cmp = cmp >> 1;
	}
	return 0;
}

void bin_ext_euclid(unsigned int a, unsigned int b, unsigned int &d, unsigned int &g, unsigned int &h) // extended euclid 함수
{
	unsigned int u = a; // 1
	unsigned int v = b;
	unsigned int g1 = 1; // 2
	unsigned int g2 = 0;
	unsigned int h1 = 0;
	unsigned int h2 = 1;
	int j = 0;
	unsigned int tmp = 0;
	while (u != 0) // 3
	{
		j = deg(u) - deg(v); // 3.1
		if (j < 0) // 3.2
		{
			tmp = u;
			u = v;
			v = tmp;
			tmp = g1;
			g1 = g2;
			g2 = tmp;
			tmp = h1;
			h1 = h2;
			h2 = tmp;
			j = -1 * j;
		}
		u ^= (v << j); // 3.3
		g1 ^= (g2 << j); // 3.4
		h1 ^= (h2 << j);
	}
	d = v;
	g = g2;
	h = h2;
}

unsigned int bin_inv(unsigned int a, unsigned int b) // 역원 구하는 함수, ag + bh = d
{
	unsigned int d;
	unsigned int g;
	unsigned int h;
	bin_ext_euclid(a, b, d, g, h);
	return g;
}

void SubBytes(unsigned int w[]) // substitution bytes 함수
{
	for (int i = 0; i < 4; i++)
	{
		unsigned int temp = w[i]; // 한번에 한 word씩 연산
		unsigned int res = 0;

		for (int j = 0; j < 4; j++) // 8 bit씩 분리해서 각각 s-box 연산
		{
			unsigned int a = 0xFF; 
			a = a << (8 * j);
			a = temp & a; // 해당 8bit 값 a에 복사
			a = a >> (8 * j); // s-box 연산 위해 shift
			a = sBox(a, gf_poly); // s-box 연산
			a = a << (8 * j); // 원래 위치로 다시 shift
			res = res | a; // 변환한 8 bit값 넣기
		}
		w[i] = res; // s-box 변환한 word 넣기
	}
}

void SubBytes_inv(unsigned int w[]) // 역 substitution bytes 함수
{
	for (int i = 0; i < 4; i++)
	{
		unsigned int temp = w[i]; // 한번에 한 word씩 연산
		unsigned int res = 0;

		for (int j = 0; j < 4; j++) // 8 bit씩 분리해서 각각 s-box 연산
		{
			unsigned int a = 0xFF;
			a = a << (8 * j);
			a = temp & a;
			a = a >> (8 * j);
			a = sBox_inv(a, gf_poly); // 역 s-box 연산
			a = a << (8 * j);
			res = res | a;
		}
		w[i] = res;
	}
}

void ShiftRow(unsigned int w[]) // shift row 함수
{
	unsigned int tmp[16] = { 0 };
	unsigned int a, b;
	for (int i = 0; i < 4; i++) // 값을 배열에 담기
	{
		for (int j = 0; j < 4; j++)
		{
			a = 0xFF;
			a = a << (8 * (3 - j));
			a &= w[i];
			a = a >> (8 * (3 - j));
			tmp[i * 4 + j] = a;
		}
	}
	// row 2
	a = tmp[1];
	for (int i = 0; i < 3; i++) tmp[1 + i * 4] = tmp[5 + i * 4];
	tmp[13] = a;
	// row 3
	a = tmp[2];
	b = tmp[6];
	tmp[2] = tmp[10];
	tmp[6] = tmp[14];
	tmp[10] = a;
	tmp[14] = b;
	// row 4
	a = tmp[15];
	for (int i = 0; i < 3; i++) tmp[15 - (i * 4)] = tmp[11 - (i * 4)];
	tmp[3] = a;

	// 배열 다시 값으로 옮기기
	for (int i = 0; i < 4; i++)
	{
		unsigned int res = 0;
		for (int j = 0; j < 4; j++)
		{
			a = tmp[i * 4 + j];
			a = a << (8 * (3 - j));
			res |= a;
		}
		w[i] = res;
	}
}

void ShiftRow_inv(unsigned int w[]) // 역 shift row 함수
{
	unsigned int tmp[16] = { 0 };
	unsigned int a, b;
	for (int i = 0; i < 4; i++) // 값을 배열에 담기
	{
		for (int j = 0; j < 4; j++)
		{
			a = 0xFF;
			a = a << (8 * (3 - j));
			a &= w[i];
			a = a >> (8 * (3 - j));
			tmp[i * 4 + j] = a;
		}
	}
	// row 2
	a = tmp[13];
	for (int i = 2; i >= 0; i--) tmp[5 + i * 4] = tmp[1 + i * 4];
	tmp[1] = a;
	// row 3
	a = tmp[2];
	b = tmp[6];
	tmp[2] = tmp[10];
	tmp[6] = tmp[14];
	tmp[10] = a;
	tmp[14] = b;
	// row 4
	a = tmp[3];
	for (int i = 0; i < 3; i++) tmp[3 + (i * 4)] = tmp[7 + (i * 4)];
	tmp[15] = a;

	// 배열 다시 값으로 옮기기
	for (int i = 0; i < 4; i++)
	{
		unsigned int res = 0;
		for (int j = 0; j < 4; j++)
		{
			a = tmp[i * 4 + j];
			a = a << (8 * (3 - j));
			res |= a;
		}
		w[i] = res;
	}
}

unsigned int bin_mul(unsigned int a, unsigned int b) // 곱셈 연산 함수
{
	if (a == 1) return b;
	else if (b == 1) return a;

	unsigned int gf = gf_poly;

	unsigned int buf = gf & 0xFF;

	unsigned int f[8] = { 0 };
	f[0] = a;
	for (int i = 1; i < 8; i++)
	{
		f[i] = f[i - 1];
		if ((f[i] & 0x80) == 0x80) // carry 발생 시
		{
			f[i] = f[i] << 1;
			f[i] &= 0xFF; // carry 삭제
			f[i] ^= buf;
		}
		else
		{
			f[i] = f[i] << 1; // shift
		}
	}
	unsigned int res = 0;
	for (int i = 0; i < 8; i++)
	{
		int mask = 1 << i;
		if ((b & mask) != 0)
		{
			res ^= f[i];
		}
	}
	return res;
}

void MixColumn(unsigned int w[]) // mix column 함수
{
	unsigned int s[4][4];
	unsigned int mix_arr[4][4] = { {2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2} }; // 순 변환 행렬
	for (int i = 0; i < 4; i++) // 값을 4 * 4 배열로 옮기기
	{
		for (int j = 0; j < 4; j++)
		{
			unsigned int temp = 0xFF000000 >> (8 * j);
			temp = temp & w[i];
			temp = temp >> (8 * (4 - j - 1));
			s[j][i] = temp;
		}
	}
	unsigned int res[4][4];
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{ // 행렬 곱셈
			res[i][j] = bin_mul(s[0][j], mix_arr[i][0]) ^ bin_mul(s[1][j], mix_arr[i][1]) ^ bin_mul(s[2][j], mix_arr[i][2]) ^ bin_mul(s[3][j], mix_arr[i][3]);
		}
	}
	for (int i = 0; i < 4; i++) // 4 * 4 배열 값으로 옮기기
	{
		w[i] = 0;
		for (int j = 0; j < 4; j++)
		{
			unsigned int temp = 0xFF;
			temp &= res[j][i];
			temp = temp << (8 * (4 - j - 1));
			w[i] |= temp;
		}
	}
}

void MixColumn_inv(unsigned int w[]) // 역 mix column 함수
{
	unsigned int s[4][4];
	// 역 변환 행렬
	unsigned int mix_arr[4][4] = { {0x0E, 0x0B, 0x0D, 0x09}, {0x09, 0x0E, 0x0B, 0x0D}, {0x0D, 0x09, 0x0E, 0x0B}, {0x0B, 0x0D, 0x09, 0x0E} };
	for (int i = 0; i < 4; i++) // 값을 4 * 4 배열로 옮기기
	{
		for (int j = 0; j < 4; j++)
		{
			unsigned int temp = 0xFF000000 >> (8 * j);
			temp = temp & w[i];
			temp = temp >> (8 * (4 - j - 1));
			s[j][i] = temp;
		}
	}
	unsigned int res[4][4];
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{ // 행렬 곱셈
			res[i][j] = bin_mul(s[0][j], mix_arr[i][0]) ^ bin_mul(s[1][j], mix_arr[i][1]) ^ bin_mul(s[2][j], mix_arr[i][2]) ^ bin_mul(s[3][j], mix_arr[i][3]);
		}
	}
	for (int i = 0; i < 4; i++) // 4 * 4 배열 값으로 옮기기
	{
		w[i] = 0;
		for (int j = 0; j < 4; j++)
		{
			unsigned int temp = 0xFF;
			temp &= res[j][i];
			temp = temp << (8 * (4 - j - 1));
			w[i] |= temp;
		}
	}
}