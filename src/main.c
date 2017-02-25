/*
 * Copyright (C) 2016-2017 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdio.h>
#include <fat.h>
#include <sys/stat.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <iosuhax.h>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/sys_functions.h"
#include "dynamic_libs/vpad_functions.h"
#include "system/memory.h"
#include "common/common.h"
#include "main.h"
#include "exploit.h"
#include "../payload/wupserver_bin.h"

//just to be able to call async
void someFunc(void *arg)
{
	(void)arg;
}

static int mcp_hook_fd = -1;
int MCPHookOpen()
{
	//take over mcp thread
	mcp_hook_fd = MCP_Open();
	if(mcp_hook_fd < 0)
		return -1;
	IOS_IoctlAsync(mcp_hook_fd, 0x62, (void*)0, 0, (void*)0, 0, (void*)someFunc, (void*)0);
	//let wupserver start up
	sleep(1);
	if(IOSUHAX_Open("/dev/mcp") < 0)
		return -1;
	return 0;
}

void MCPHookClose()
{
	if(mcp_hook_fd < 0)
		return;
	//close down wupserver, return control to mcp
	IOSUHAX_Close();
	//wait for mcp to return
	sleep(1);
	MCP_Close(mcp_hook_fd);
	mcp_hook_fd = -1;
}

void println_noflip(int line, const char *msg)
{
	OSScreenPutFontEx(0,0,line,msg);
	OSScreenPutFontEx(1,0,line,msg);
}

void println(int line, const char *msg)
{
	int i;
	for(i = 0; i < 2; i++)
	{	//double-buffered font write
		println_noflip(line,msg);
		OSScreenFlipBuffersEx(0);
		OSScreenFlipBuffersEx(1);
	}
}

#define SECTOR_SIZE 0x8000
#define SECTORS_COUNT 0xBA740
#define NUM_SECTORS 64

int fsa_odd_read(int fsa_fd, int fd, void *buf, int offset)
{
	return IOSUHAX_FSA_RawRead(fsa_fd, buf, SECTOR_SIZE, NUM_SECTORS, offset, fd);
}

int fsa_write(int fsa_fd, int fd, void *buf, int len)
{
	int done = 0;
	uint8_t *buf_u8 = (uint8_t*)buf;
	while(done < len)
	{
		size_t write_size = len - done;
		int result = IOSUHAX_FSA_WriteFile(fsa_fd, buf_u8 + done, 0x01, write_size, fd, 0);
		if(result < 0)
			return result;
		else
			done += result;
	}
	return done;
}

static const char *hdrStr = "wudump v1.5 by FIX94 (wux mode)";
void printhdr_noflip()
{
	println_noflip(0,hdrStr);
}

void write_hash_file(char *fName, char *dir, unsigned int crc32, 
	md5_context *md5ctx, sha1_context *sha1ctx)
{
	unsigned int md5[4];
	md5_finish(md5ctx, (unsigned char*)md5);
	unsigned int sha1[5];
	sha1_finish(sha1ctx, (unsigned char*)sha1);

	char wudPath[64];
	sprintf(wudPath, "%s/%s.txt", dir, fName);
	FILE *f = fopen(wudPath, "w");
	if(f)
	{
		fprintf(f, "%s\n\n", hdrStr);
		fprintf(f, "Hashes for %s.wud:\n", fName);
		fprintf(f, "CRC32: %08X\n"
			"MD5: %08X%08X%08X%08X\n"
			"SHA1: %08X%08X%08X%08X%08X\n",
			crc32, md5[0],md5[1],md5[2],md5[3],
			sha1[0],sha1[1],sha1[2],sha1[3],sha1[4]);
		fclose(f);
		f = NULL;
	}
}

//imported OS zlib crc32 function pointer
static unsigned int (*zlib_crc32)(unsigned int crc32, const void *buf, int bufsize) = (void*)0;

static const int bufSize = SECTOR_SIZE*NUM_SECTORS;
static void *sectorBuf = NULL;
//static bool threadRunning = true;
static unsigned int crc32Val = 0;
static md5_context md5ctx;
static sha1_context sha1ctx;
//static unsigned int crc32PartVal = 0;
//static md5_context md5PartCtx;
//static sha1_context sha1PartCtx;

/*static int hashThread(s32 argc, void *args)
{
	(void)argc;
	(void)args;
	while(threadRunning)
	{
		//update global hashes
		crc32Val = zlib_crc32(crc32Val, sectorBuf, bufSize);
		md5_update(&md5ctx, sectorBuf, bufSize);
		sha1_update(&sha1ctx, sectorBuf, bufSize);
		//update hashes for part file
		crc32PartVal = zlib_crc32(crc32PartVal, sectorBuf, bufSize);
		md5_update(&md5PartCtx, sectorBuf, bufSize);
		sha1_update(&sha1PartCtx, sectorBuf, bufSize);
		//go back to sleep
		OSSuspendThread(OSGetCurrentThread());
	}
	return 0;
}*/

unsigned int swap_uint32( unsigned int val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

unsigned long long swap_uint64( unsigned long long val )
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

typedef struct 
{
	unsigned int		magic0;
	unsigned int		magic1;
	unsigned int		sectorSize;
	unsigned long long	uncompressedSize;
	unsigned int		flags;
}wuxHeader_t;

#define WUX_MAGIC_0	'WUX0'
#define WUX_MAGIC_1	swap_uint32(0x1099d02e)

unsigned int simple_hash( unsigned char * data, unsigned int length )
{
	unsigned int hash = 0x7f231;
	for (unsigned int i=0; i < length; ++i) {
		hash += 0x58af3 * data[i] + 0x31643;
		hash *= 0xe9177;
	}
	return hash & 0xfffff;
}

int Menu_Main(void)
{
	InitOSFunctionPointers();
	InitSysFunctionPointers();
	InitVPadFunctionPointers();
	unsigned int zlib_handle = 0;
	OSDynLoad_Acquire("zlib125.rpl", &zlib_handle);
	OSDynLoad_FindExport(zlib_handle, 0, "crc32", &zlib_crc32);
	VPADInit();
	memoryInitialize();

	// Init screen
	OSScreenInit();
	int screen_buf0_size = OSScreenGetBufferSizeEx(0);
	int screen_buf1_size = OSScreenGetBufferSizeEx(1);
	uint8_t *screenBuffer = (uint8_t*)MEMBucket_alloc(screen_buf0_size+screen_buf1_size, 0x100);
	OSScreenSetBufferEx(0, screenBuffer);
	OSScreenSetBufferEx(1, (screenBuffer + screen_buf0_size));
	OSScreenEnableEx(0, 1);
	OSScreenEnableEx(1, 1);
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);

	printhdr_noflip();
	println_noflip(2,"Please make sure to take out any currently inserted disc.");
	println_noflip(3,"Also make sure you have at least 23.3GB free on your device.");
	println_noflip(4,"Press A to continue with a FAT32 SD Card as destination.");
	println_noflip(5,"Press B to continue with a FAT32 USB Device as destination.");
	println_noflip(6,"Press HOME to return to the Homebrew Launcher.");
	OSScreenFlipBuffersEx(0);
	OSScreenFlipBuffersEx(1);

	int vpadError = -1;
	VPADData vpad;
	int action = 0;
	while(1)
	{
		VPADRead(0, &vpad, 1, &vpadError);
		if(vpadError == 0)
		{
			if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
			{
				MEMBucket_free(screenBuffer);
				memoryRelease();
				return EXIT_SUCCESS;
			}
			else if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_A)
				break;
			else if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_B)
			{
				action = 1;
				break;
			}
		}
		usleep(50000);
	}
	int j;
	for(j = 0; j < 2; j++)
	{
		OSScreenClearBufferEx(0, 0);
		OSScreenClearBufferEx(1, 0);
		printhdr_noflip();
		OSScreenFlipBuffersEx(0);
		OSScreenFlipBuffersEx(1);
		usleep(25000);
	}
	int line = 2;
	//will inject our custom mcp code
	println(line++,"Doing IOSU Exploit...");
	*(volatile unsigned int*)0xF5E70000 = wupserver_bin_len;
	memcpy((void*)0xF5E70020, &wupserver_bin, wupserver_bin_len);
	DCStoreRange((void*)0xF5E70000, wupserver_bin_len + 0x40);
	IOSUExploit();
	int fsaFd = -1;
	int oddFd = -1;
	int ret;
	char wudumpPath[64];
	char wudPath[64];
	char keyPath[64];
	FILE *f = NULL;

	//done with iosu exploit, take over mcp
	if(MCPHookOpen() < 0)
	{
		println(line++,"MCP hook could not be opened!");
		goto prgEnd;
	}
	memset((void*)0xF5E10C00, 0, 0x20);
	DCFlushRange((void*)0xF5E10C00, 0x20);
	println(line++,"Done!");

	//mount with full permissions
	fsaFd = IOSUHAX_FSA_Open();
	if(fsaFd < 0)
	{
		println(line++,"FSA could not be opened!");
		goto prgEnd;
	}
	fatInitDefault();

	println(line++,"Please insert the disc you want to dump now to begin.");
	//wait for disc key to be written
	while(1)
	{
		DCInvalidateRange((void*)0xF5E10C00, 0x20);
		if(*(volatile unsigned int*)0xF5E10C00 != 0)
			break;
		VPADRead(0, &vpad, 1, &vpadError);
		if(vpadError == 0)
		{
			if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
				goto prgEnd;
		}
		usleep(50000);
	}

	//opening raw odd might take a bit
	int retry = 10;
	ret = -1;
	while(ret < 0)
	{
		ret = IOSUHAX_FSA_RawOpen(fsaFd, "/dev/odd01", &oddFd);
		retry--;
		if(retry < 0)
			break;
		sleep(1);
	}
	if(ret < 0)
	{
		println(line++,"Failed to open Raw ODD!");
		goto prgEnd;
	}

	//get our 2MB I/O Buffer and read out first sector
	sectorBuf = MEMBucket_alloc(bufSize, 0x100);
	if(sectorBuf == NULL || fsa_odd_read(fsaFd, oddFd, sectorBuf, 0) < 0)
	{
		println(line++,"Failed to read first disc sector!");
		goto prgEnd;
	}

	//get disc name for folder
	char discId[11];
	discId[10] = '\0';
	memcpy(discId, sectorBuf, 10);
	char discStr[64];
	sprintf(discStr, "Inserted %s", discId);
	println(line++, discStr);

	// make wudump dir we will write to
	char *device = (action == 0) ? "sd:" : "usb:";
	sprintf(wudumpPath, "%s/wudump", device);
	mkdir(wudumpPath, 0x600);
	sprintf(wudumpPath, "%s/wudump/%s", device, discId);
	mkdir(wudumpPath, 0x600);

	u8 cKey[0x10];
	memcpy(cKey, (void*)0xF5E104E0, 0x10);

	sprintf(keyPath, "%s/common.key", wudumpPath);
	f = fopen(keyPath, "wb");
	if(f == NULL)
	{
		println(line++,"Failed to write Common Key!");
		goto prgEnd;
	}
	fwrite(cKey, 1, 0x10, f);
	fclose(f);
	f = NULL;
	println(line++,"Common Key dumped!");

	u8 discKey[0x10];
	memcpy(discKey, (void*)0xF5E10C00, 0x10);

	sprintf(keyPath, "%s/game.key", wudumpPath);
	f = fopen(keyPath, "wb");
	if(f == NULL)
	{
		println(line++,"Failed to write Disc Key!");
		goto prgEnd;
	}
	fwrite(discKey, 1, 0x10, f);
	fclose(f);
	f = NULL;
	println(line++, "Disc Key dumped!");

	int apd_enabled = 0;
	IMIsAPDEnabled(&apd_enabled);
	if(apd_enabled)
	{
		if(IMDisableAPD() == 0)
			println(line++, "Disabled Auto Power-Down.");
	}

	sprintf(discStr, "Dumping %s...", discId);
	char progress[64];
	char progress2[64];
	bool newF = true;
	int part = 1;
	unsigned int readSectors = 0;

	//full hashes
	crc32Val = 0;
	md5_starts(&md5ctx);
	sha1_starts(&sha1ctx);

	//part hashes
	//crc32PartVal = 0;
	//md5_starts(&md5PartCtx);
	//sha1_starts(&sha1PartCtx);

	unsigned int* sectorIndexTable = (unsigned int*)MEMBucket_alloc(sizeof(unsigned int) * SECTORS_COUNT, 0x100);
	unsigned char* sectorHashArray = (unsigned char*)MEMBucket_alloc((sizeof(unsigned int) + (sizeof(unsigned char) * 0x10)) * SECTORS_COUNT, 0x100);
	unsigned int* sectorHashTable = (unsigned char*)MEMBucket_alloc(sizeof(unsigned int) * 0x100000, 0x100);
	memset(sectorHashTable, 0xff, sizeof(unsigned int) * 0x100000);
	unsigned int uniqueSectorCount = 0;
	long long compressedSize = 0;

	//create hashing thread
	//void *stack = MEMBucket_alloc(0x4000, 0x20);
	//void *thread = memalign(8, 0x1000); //thread cant be in MEMBucket
	//OSCreateThread(thread, hashThread, 0, NULL, (unsigned int)stack+0x4000, 0x4000, 20, (1<<OSGetCoreId()));

	//0xBA7400 = full disc
	while(readSectors < SECTORS_COUNT)
	{
		//read offsets until no error returns
		do {
			ret = fsa_odd_read(fsaFd, oddFd, sectorBuf, readSectors);
		} while(ret < 0);
		//update global hashes
		crc32Val = zlib_crc32(crc32Val, sectorBuf, bufSize);
		md5_update(&md5ctx, sectorBuf, bufSize);
		sha1_update(&sha1ctx, sectorBuf, bufSize);

		//update hashes in thread
		//OSResumeThread(thread);
		for(unsigned int i=0; i<NUM_SECTORS; i++)
		{
			if(newF)
			{
				if(f != NULL)
				{
					//close file
					fclose(f);
					f = NULL;
					//write in file hashes
					//char tmpChar[64];
					//sprintf(tmpChar, "game_part%i", part);
					//write_hash_file(tmpChar, wudumpPath, crc32PartVal, 
					//	&md5PartCtx, &sha1PartCtx);
					//open new hashes
					//crc32PartVal = 0;
					//md5_starts(&md5PartCtx);
					//sha1_starts(&sha1PartCtx);
				}
				//set part int for next file
				part++;
				sprintf(wudPath, "%s/game_part%i.wux", wudumpPath, part);
				f = fopen(wudPath, "wb");
				if(f == NULL)
					break;
				newF = false;
			}
			md5_context md5ctxsec;
			md5_starts(&md5ctxsec);
			md5_update(&md5ctxsec, ((char*)sectorBuf)+i*SECTOR_SIZE, SECTOR_SIZE);
			unsigned int md5[4];
			md5_finish(&md5ctxsec, (unsigned char*)md5);
			//update hashes for part file
			//crc32PartVal = zlib_crc32(crc32PartVal, ((char*)sectorBuf)+i*SECTOR_SIZE, SECTOR_SIZE);
			//md5_update(&md5PartCtx, ((char*)sectorBuf)+i*SECTOR_SIZE, SECTOR_SIZE);
			//sha1_update(&sha1PartCtx, ((char*)sectorBuf)+i*SECTOR_SIZE, SECTOR_SIZE);

			unsigned int* current_pos = &sectorHashTable[simple_hash(md5, sizeof(md5))];
			while (*current_pos != 0xFFFFFFFF) {
				unsigned int * next_pos = sectorHashArray + (*current_pos)*(sizeof(md5) + sizeof(unsigned long));
				if( memcmp(md5, next_pos+1, sizeof(md5)) == 0 )
					break;
				current_pos = next_pos;
			}
			// if we found a sector then just store the index
			if( *current_pos != 0xFFFFFFFF )
			{
				sectorIndexTable[readSectors+i] = swap_uint32(*current_pos);
				continue;
			}
			// else store the sector and append a new index
			fwrite(((char*)sectorBuf)+i*SECTOR_SIZE, SECTOR_SIZE, 1, f);
			memset(sectorHashArray+uniqueSectorCount*(sizeof(md5)+sizeof(unsigned long)), 0xff, sizeof(unsigned long));
			memcpy(sectorHashArray+uniqueSectorCount*(sizeof(md5)+sizeof(unsigned long))+sizeof(unsigned long), md5, sizeof(md5));
			*current_pos = uniqueSectorCount;
			compressedSize += SECTOR_SIZE;
			sectorIndexTable[readSectors+i] = swap_uint32(uniqueSectorCount);
			uniqueSectorCount++;
			if((uniqueSectorCount % 0x10000) == 0)
				newF = true; //new file every 2gb
		}
		
		readSectors += NUM_SECTORS;
		if((readSectors % 0x200) == 0)
		{
			OSScreenClearBufferEx(0, 0);
			OSScreenClearBufferEx(1, 0);
			sprintf(progress,"0x%05X/0x%05X (%i%%)",readSectors,SECTORS_COUNT,(readSectors*100)/SECTORS_COUNT);
			int compressionRatio = (int)(((long long)readSectors * SECTOR_SIZE)*10 / compressedSize);
			sprintf(progress2,"Compression ratio: 1:%d.%d", compressionRatio/10, compressionRatio%10);
			printhdr_noflip();
			println_noflip(2,discStr);
			println_noflip(3,progress);
			println_noflip(4,progress2);
			OSScreenFlipBuffersEx(0);
			OSScreenFlipBuffersEx(1);
		}
		//wait for hashes to get done
		//while(!OSIsThreadSuspended(thread)) ;
	}

	//write last part hash
	if(f != NULL)
	{
		//close file
		fclose(f);
		f = NULL;
		//write in file hashes
		//char tmpChar[64];
		//sprintf(tmpChar, "game_part%i", part);
		//write_hash_file(tmpChar, wudumpPath, crc32PartVal, &md5PartCtx, &sha1PartCtx);
	}

	//open new hashes
	//crc32PartVal = 0;
	//md5_starts(&md5PartCtx);
	//sha1_starts(&sha1PartCtx);

	sprintf(wudPath, "%s/game_part1.wux", wudumpPath);
	f = fopen(wudPath, "wb");

	// write header
	wuxHeader_t wuxHeader = {0};
	wuxHeader.magic0 = WUX_MAGIC_0;
	wuxHeader.magic1 = WUX_MAGIC_1;
	wuxHeader.sectorSize = swap_uint32(SECTOR_SIZE);
	wuxHeader.uncompressedSize = swap_uint64((unsigned long long)SECTORS_COUNT * SECTOR_SIZE);
	wuxHeader.flags = 0;
	fwrite(&wuxHeader, sizeof(wuxHeader_t), 1, f);
	//crc32PartVal = zlib_crc32(crc32PartVal, &wuxHeader, sizeof(wuxHeader_t));
	//md5_update(&md5PartCtx, &wuxHeader, sizeof(wuxHeader_t));
	//sha1_update(&sha1PartCtx, &wuxHeader, sizeof(wuxHeader_t));
	fwrite(sectorIndexTable, SECTORS_COUNT, sizeof(unsigned int), f);
	//crc32PartVal = zlib_crc32(crc32PartVal, sectorIndexTable, SECTORS_COUNT*sizeof(unsigned int));
	//md5_update(&md5PartCtx, sectorIndexTable, SECTORS_COUNT*sizeof(unsigned int));
	//sha1_update(&sha1PartCtx, sectorIndexTable, SECTORS_COUNT*sizeof(unsigned int));
	int offset = ftell(f);
	// align to SECTOR_SIZE
	offset = (offset + SECTOR_SIZE - 1);
	offset = offset - (offset%SECTOR_SIZE);
	fseek(f, offset-1, SEEK_SET);
	fputc('\0', f);
	fclose(f);
	f=NULL;
	//write_hash_file("game_part1", wudumpPath, crc32PartVal, &md5PartCtx, &sha1PartCtx);

	//write global hashes into file
	write_hash_file("game", wudumpPath, crc32Val, &md5ctx, &sha1ctx);

	//close down hash thread
	//threadRunning = false;
	//OSResumeThread(thread);
	//OSJoinThread(thread, &ret);
	//free(thread); //thread cant be in MEMBucket
	//MEMBucket_free(stack);

	//all finished!
	OSScreenClearBufferEx(0, 0);
	OSScreenClearBufferEx(1, 0);
	sprintf(progress,"0x%05X/0x%05X (%i%%)",readSectors,SECTORS_COUNT,(readSectors*100)/SECTORS_COUNT);
	int compressionRatio = (int)(((long long)readSectors * SECTOR_SIZE)*10 / compressedSize);
	sprintf(progress2,"Compression ratio: 1:%d.%d", compressionRatio/10, compressionRatio%10);
	printhdr_noflip();
	println_noflip(2,discStr);
	println_noflip(3,progress);
	println_noflip(4,progress2);
	if(readSectors == SECTORS_COUNT)
		println_noflip(5,"Disc dumped!");
	else //only error we handle while dumping
		println_noflip(5,"Failed to write Disc WUD!");
	if(apd_enabled)
	{
		if(IMEnableAPD() == 0)
			println_noflip(6, "Re-Enabled Auto Power-Down.");
	}
	OSScreenFlipBuffersEx(0);
	OSScreenFlipBuffersEx(1);

prgEnd:
	//close down everything fsa related
	if(fsaFd >= 0)
	{
		if(f != NULL)
			fclose(f);
		fatUnmount("sd:");
		fatUnmount("usb:");
		if(oddFd >= 0)
			IOSUHAX_FSA_RawClose(fsaFd, oddFd);
		IOSUHAX_FSA_Close(fsaFd);
		if(sectorBuf != NULL)
			MEMBucket_free(sectorBuf);
	}
	//close out old mcp instance
	MCPHookClose();
	sleep(5);
	//will do IOSU reboot
	OSForceFullRelaunch();
	SYSLaunchMenu();
	OSScreenEnableEx(0, 0);
	OSScreenEnableEx(1, 0);
	MEMBucket_free(screenBuffer);
	memoryRelease();
	return EXIT_RELAUNCH_ON_LOAD;
}
