#pragma once



#define CONV_STR2DEC_1(str, i)  (str[i]>'0'?str[i]-'0':0)
#define CONV_STR2DEC_2(str, i)  (CONV_STR2DEC_1(str, i)*10 + str[i+1]-'0')
#define CONV_STR2DEC_3(str, i)  (CONV_STR2DEC_2(str, i)*10 + str[i+2]-'0')
#define CONV_STR2DEC_4(str, i)  (CONV_STR2DEC_3(str, i)*10 + str[i+3]-'0')

// Some definitions for calculation
#define SEC_PER_MIN             60UL
#define SEC_PER_HOUR            3600UL
#define SEC_PER_DAY             86400UL
#define SEC_PER_YEAR            (SEC_PER_DAY*365)
#define UNIX_START_YEAR         1970UL

// Custom "glue logic" to convert the month name to a usable number
#define GET_MONTH(str, i)      (str[i]=='J' && str[i+1]=='a' && str[i+2]=='n' ? 1 :     \
                                str[i]=='F' && str[i+1]=='e' && str[i+2]=='b' ? 2 :     \
                                str[i]=='M' && str[i+1]=='a' && str[i+2]=='r' ? 3 :     \
                                str[i]=='A' && str[i+1]=='p' && str[i+2]=='r' ? 4 :     \
                                str[i]=='M' && str[i+1]=='a' && str[i+2]=='y' ? 5 :     \
                                str[i]=='J' && str[i+1]=='u' && str[i+2]=='n' ? 6 :     \
                                str[i]=='J' && str[i+1]=='u' && str[i+2]=='l' ? 7 :     \
                                str[i]=='A' && str[i+1]=='u' && str[i+2]=='g' ? 8 :     \
                                str[i]=='S' && str[i+1]=='e' && str[i+2]=='p' ? 9 :     \
                                str[i]=='O' && str[i+1]=='c' && str[i+2]=='t' ? 10 :    \
                                str[i]=='N' && str[i+1]=='o' && str[i+2]=='v' ? 11 :    \
                                str[i]=='D' && str[i+1]=='e' && str[i+2]=='c' ? 12 : 0)

#define GET_MONTH2DAYS(month)  ((month == 1 ? 0 : 31 +                      \
                                (month == 2 ? 0 : 28 +                      \
                                (month == 3 ? 0 : 31 +                      \
                                (month == 4 ? 0 : 30 +                      \
                                (month == 5 ? 0 : 31 +                      \
                                (month == 6 ? 0 : 30 +                      \
                                (month == 7 ? 0 : 31 +                      \
                                (month == 8 ? 0 : 31 +                      \
                                (month == 9 ? 0 : 30 +                      \
                                (month == 10 ? 0 : 31 +                     \
                                (month == 11 ? 0 : 30))))))))))))           \


#define GET_LEAP_DAYS           ((__TIME_YEARS__-1968)/4 - (__TIME_MONTH__ <=2 ? 1 : 0))



#define __TIME_SECONDS__        CONV_STR2DEC_2(__TIME__, 6)
#define __TIME_MINUTES__        CONV_STR2DEC_2(__TIME__, 3)
#define __TIME_HOURS__          CONV_STR2DEC_2(__TIME__, 0)
#define __TIME_DAYS__           CONV_STR2DEC_2(__DATE__, 4)
#define __TIME_MONTH__          GET_MONTH(__DATE__, 0)
#define __TIME_YEARS__          CONV_STR2DEC_4(__DATE__, 7)

#define __TIME_UNIX__         ((__TIME_YEARS__-UNIX_START_YEAR)*SEC_PER_YEAR+       \
                                GET_LEAP_DAYS*SEC_PER_DAY+                          \
                                GET_MONTH2DAYS(__TIME_MONTH__)*SEC_PER_DAY+         \
                                __TIME_DAYS__*SEC_PER_DAY-SEC_PER_DAY+              \
                                __TIME_HOURS__*SEC_PER_HOUR+                        \
                                __TIME_MINUTES__*SEC_PER_MIN+                       \
                                __TIME_SECONDS__)


///////////////////
#ifdef TIMEDACCESS
#include <chrono> 

//https://timestamp.online/ 
// 86400 - day ; 3600 - hour
time_t compiletime = __TIME_UNIX__ - 3600 * 3; //gmt+3
time_t duration = 86400 * 1;
time_t curtime = 0;
time_t remaining = 1000;
time_t timer; chrono::system_clock::time_point mStartedTime;

#include <WinInet.h>
#pragma comment(lib, "WinInet.lib")
#include <tchar.h>
#include <stdio.h>
#include <string>
 

#include <zlib.h> 
int inf(const char* src, int srcLen, const char* dst, int dstLen) {
	z_stream strm;
	strm.zalloc = NULL;
	strm.zfree = NULL;
	strm.opaque = NULL;

	strm.avail_in = srcLen;
	strm.avail_out = dstLen;
	strm.next_in = (Bytef*)src;
	strm.next_out = (Bytef*)dst;

	int err = -1, ret = -1;
	err = inflateInit2(&strm, MAX_WBITS + 16);
	if (err == Z_OK) {
		err = inflate(&strm, Z_FINISH);
		if (err == Z_STREAM_END) {
			ret = strm.total_out;
		}
		else {
			inflateEnd(&strm);
			return err;
		}
	}
	else {
		inflateEnd(&strm);
		return err;
	}
	inflateEnd(&strm);
	//printfdbg("%s\n", dst);
	return err;
}

int gTime()
{
	printfdbg("gettin' time\n");

	int read = 0;
	char* str = (char*)"*/*", buff[1024] = {};

	//HINTERNET inet = InternetOpen("GRB", INTERNET_OPEN_TYPE_PROXY, "http://192.168.56.1:8888", "<local>", 0); 
	HINTERNET inet = InternetOpen("GRB", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!(inet = InternetConnect(inet, "api.ipgeolocation.io", INTERNET_DEFAULT_HTTPS_PORT, 0, 0, INTERNET_SERVICE_HTTP, 0, 0)))
	{
		std::cout << "conn failed" << std::endl;
		return 0;
	}

	char link[200] = "/timezone?apiKey=8d27e8c544044268867e0170a9ea96df&tz=America/Los_Angeles";

	if (!(inet = HttpOpenRequest(inet, "GET", link, "HTTP/1.1", NULL, 0, INTERNET_FLAG_SECURE, 0)))
	{
		std::cout << "open failed" << std::endl;
		return 0;
	}

	TCHAR* szHeaders = (TCHAR*)"Host: api.ipgeolocation.io\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"DNT: 1\r\n"
		"Connection: keep-alive\r\n"
		"Upgrade-Insecure-Requests: 1\r\n"
		"Sec-Fetch-Dest: document\r\n"
		"Sec-Fetch-Mode: navigate\r\n"
		"Sec-Fetch-Site: none\r\n"
		"Sec-Fetch-User: ?1\r\n"
		;

	TCHAR szReq[1024] = { };

	if (!HttpSendRequest(inet, szHeaders, _tcslen(szHeaders), szReq, strlen(szReq)))// strlen(szReq)
	{
		printfdbg("Send Failed %d\n", GetLastError());
		return 0;
	}

	InternetReadFile(inet, buff, 1023, (DWORD*)&read);

	char buf[2][0x10000];
	long n = 1023;//fread(buff, 1, 0x100000, fp);//readFile(buff, &buf[0][0]);
	memcpy(&buf[0][0], buff, 1023);
	unsigned int* pInt = (unsigned int*)(&buf[0][0]);
	printfdbg("n=%d %08x\n", n, *pInt);
	long m = 0x10000;
	int rc = inf(&buf[0][0], n, &buf[1][0], m);
	printfdbg("rc = %d %s\n", rc, &buf[1][0]);

	memcpy(buff, &buf[1][0], 1023);

	string ret = string(buff);
	ret = ret.substr(ret.find("unix") + 6, 10);
	return stoi(ret);
}


bool CheckTime()
{
	chrono::system_clock::time_point mElapsedTime = chrono::system_clock::now();
	std::chrono::duration<float> diff = mElapsedTime - mStartedTime;
	remaining = timer - (time_t)diff.count();
	 
	/*
	int seconds, hours, minutes;
	seconds = remaining - 2;
	minutes = seconds / 60;
	hours = minutes / 60;
	string timedraw = to_string(hours) + ":" + to_string(minutes % 60) + ":" + to_string(seconds % 60);
	printfdbg("%s remaining\n", timedraw.c_str());
	*/

	if (remaining < 0)
		return 0;
	return 1;
}

#endif