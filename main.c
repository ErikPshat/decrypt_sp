#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <kirk_engine.h>

unsigned char buffer[10000000] __attribute__((aligned(64)));

int ReadFile(char *file, void *buf, int size)
{
	int fd = open(file, O_RDONLY, 0);
	if (fd < 0)
		return fd;

	int read2 = read(fd, buf, size);
	close(fd);

	return read2;
}

int WriteFile(char *file, void *buf, int size)
{
	int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (fd < 0)
		return fd;

	int written = write(fd, buf, size);
	close(fd);

	return written;
}

unsigned char header_p1[0xb0];
unsigned char header_p2[0x80];

//file_head len 0x4
char file_head[] = {0,0,0,0};
 
//msp_id len 0x10
 
unsigned char ms_id[] = {
    0x20, 0x4D, 0x53, 0x50, 0x53, 0x4E, 0x59, 0x30, 
	0x00, 0x78, 0x54, 0x80, 0x5A, 0xB2, 0x00, 0x00
};
 
unsigned char key0[112] = 
{
	0x39, 0x81, 0xE2, 0x63, 0x96, 0xF5, 0x0D, 0x48, 0xDB, 0xCF, 0x76, 0xCF, 0x91, 0x9F, 0xF6, 0xF1, 
	0x13, 0x11, 0xF9, 0x0A, 0xB7, 0x87, 0x2E, 0x4C, 0xC9, 0x14, 0x03, 0xC4, 0x11, 0x4E, 0x38, 0xF8, 
	0x96, 0xD4, 0x56, 0x68, 0x9D, 0xB0, 0x61, 0x9C, 0x81, 0xCF, 0xB3, 0x4B, 0x7D, 0xDC, 0xF1, 0x75, 
	0xDF, 0x4D, 0x5A, 0x9F, 0x00, 0x76, 0xAD, 0x54, 0x5E, 0x5E, 0x40, 0x28, 0xDF, 0x36, 0x38, 0x17, 
	0x23, 0x28, 0x80, 0x08, 0x00, 0x82, 0xDD, 0xF2, 0x5F, 0xCC, 0x45, 0x9A, 0x9B, 0x9D, 0x83, 0x07, 
	0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 
	0x47, 0xA3, 0x62, 0xA8, 0x5B, 0xBD, 0xA1, 0x8D, 0xFB, 0xCA, 0xF4, 0xD2, 0xFC, 0xE6, 0xC8, 0x31
};

unsigned char rawData[16] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x56, 0x01, 0x00, 0x10, 0x81, 0xFF, 0xFF, 0x01, 0x28, 
} ;



unsigned char dummy[0x80]; 

void hexDump(const void *data, size_t size) {
  size_t i;
  for (i = 0; i < size; i++) {
    printf("%02hhX%c", ((char *)data)[i], (i + 1) % 16 ? ' ' : '\n');
  }
  printf("\n");
}

int Decrypt(unsigned char* buf, int size, unsigned char* msp_id, int* unk2, int* out_size)
{
	int enc_size, ret, i, delta;
	unsigned char *start_ptr;
	unsigned int *buf32 = (unsigned int *)buf;
	
	enc_size = buf[0xb3]<<24 | buf[0xb2]<<16 | buf[0xb1]<<8 | buf[0xb0];
	*out_size = enc_size;
 
	if ((size-0x150) < enc_size) return -0xCD;

	//===================================================================================
	//stage 1
	//===================================================================================
	memcpy(header_p1, buf, 0xb0);
 
	ret = kirk_init();
	if (ret != 0) return ret;
 
	//===================================================================================
	//stage 2
	//===================================================================================
 
	buf32[0] = 4; // 0 mode
	buf32[1] = 0; // 4 unk4
	buf32[2] = 0; // 8 unk8 
	buf32[3] = 1; // C keyseed
	buf32[4] = 0x80; // 0x10 size
	start_ptr = buf;
	
	memcpy(buf,buf32,0x14);
	memcpy(buf+0x14, msp_id, 0x10);
	memcpy(buf+0x24, key0, 0x70);
	
	//hexDump(buf,0x94);
 
	ret = kirk_CMD4(buf, buf, 0x80);
	if (ret != 0) return ret;

	//===================================================================================
	//stage 3
	//===================================================================================
 
	memcpy(header_p2, buf+0x14, 0x80);
 
	unsigned int *addr = (unsigned int *)start_ptr;
	*(addr) = 0xAC;
 
	memcpy(buf+0x4, header_p2+0x6c, 0x14);
	memcpy(buf+0x18, header_p1+0x18, 0x80);
	
	//hexDump(buf,0x98);
 
	ret = kirk_CMD11(buf, buf, 0xAC);
	if (ret != 0) return ret;
 
	//===================================================================================
	//stage 4
	//===================================================================================
	unsigned char *hdr_p1_offset = header_p1+0x4;
	//WriteFile("hdr_p1_offset.bin", hdr_p1_offset, 0x14);
	//WriteFile("buf.bin", buf, 0x40);
	for(i = 0; i < 0x14; i++)
	{
		if (hdr_p1_offset[i] != buf[i])
		{	
			delta = hdr_p1_offset[i] - buf[i]; 
			return -0x12e;
		}
	}
 
	buf32[6] = 5; // 0x18
	buf32[7] = 0; // 0x1C
	buf32[8] = 0; // 0x20
	buf32[9] = 0x41; // 0x24
	buf32[10] = 0x80; // 0x28
	start_ptr = buf+0x18;
 
	memcpy(buf+0x2c, header_p1+0x30, 0x80);
 
	//hexDump(buf,0x98);
	ret = kirk_CMD7(buf+0x18, buf+0x18, 0x80);
	if (ret != 0) return ret;
 
	//===================================================================================
	//stage 5
	//===================================================================================
	unsigned char *tmp_ptr = buf+0x18;
	for(i = 0; i < 0x80; i++)
	{
		tmp_ptr[i] = tmp_ptr[i] ^ header_p2[i];
	}
 
	buf32[1] = 5; // 4
	buf32[2] = 0; // 8
	buf32[3] = 0; // C
	buf32[4] = 0x41; // 0x10
	buf32[5] = 0x80; // 0x14
	start_ptr = buf+0x4;
 
	//hexDump(buf,0x98);
	ret = kirk_CMD7(buf+0x4, buf+0x4, 0x80);
	if (ret != 0) return ret;
 
	//===================================================================================
	//stage 6
	//===================================================================================
	tmp_ptr = buf+0x14;
//	WriteFile("tmp_ptr.bin", tmp_ptr, 0x40);
//	WriteFile("msp_id.bin", msp_id, 0x10);
	for (i = 0; i < 0x10; i++)
	{
		if (tmp_ptr[i] != msp_id[i])
		{
			delta = tmp_ptr[i] - msp_id[i];
			return -0x12f;
		}
	} 
	
//	WriteFile("buf_pre_memcpy.bin", buf, 0x300);
 
	//memcpy(buf+0x30, buf+0x4, 0x80);
	for (i = 0x7F; i >= 0; i--)
	{
		buf[0x30+i] = buf[0x4+i];
	}

	memcpy(buf+0x40, buf+0x30, 0x10);
	memcpy(unk2, buf+0xd0, 0x80);

//	WriteFile("buf_pre_kirk.bin", buf, 0x300);
	//hexDump(buf,0x300);
	unsigned char * size_buf = buf+0xb0;
	unsigned int size_ = size_buf[0] | (size_buf[1] << 8) | (size_buf[2] << 16) | (size_buf[3] << 24);
	ret = kirk_CMD1(buf, buf+0x40, size_); // ??? should not be r16?
	if (ret != 0) return ret;
 
	return 0;
}

int DecryptFile(char *input, char *output)
{
	printf("Decrypting %s to %s.\n", input, output);
	
	int outsize;
	int size = ReadFile(input, buffer, sizeof(buffer));

	if (size < 0)
	{
		printf("Error: cannot read %s.\n", input);
		return -1;
	}

	int res = Decrypt(buffer, size, ms_id, dummy, &outsize);

	if (res != 0)
	{
		printf("Error decrypting %s.\n", input);
		printf("%08X\n",res);
		return -1;
	}

	if (WriteFile(output, buffer, outsize) != outsize)
	{
		printf("Error writing/creating %s.\n", output);
		return -1;
	}

	return 0;
}



char input[128], output[128];

void DecryptDir(char *indir, char *outdir)
{
	
	printf("opening dir\n");
	DIR * dfd;
	dfd = opendir(indir);	

	if (dfd != NULL)
	{
		struct dirent de, *dep;

		memset(&de, 0, sizeof(struct dirent));
		
		while (readdir_r(dfd, &de, &dep) == 0 && dep != NULL)
		{
			sprintf(input, "%s/%s", indir, de.d_name);
			sprintf(output, "%s/%s", outdir, de.d_name);

			output[strlen(output)-4] = 0; // remove enc extension

			if (de.d_name[0] != '.')
			{
				
				
				if (DecryptFile(input, output) != 0)
				{
					
				}
				else
				{
					
				}
			}
		}

		closedir(dfd);
	}
}


int main()
{	
	int outsize;

	mkdir("dec", 0777);
	DecryptDir("prx", "dec");

	printf("Done!\n");

	return 0;
}
