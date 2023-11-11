// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS
#define DEBUG   
#define DISCMSG
//#define TIMEDACCESS 
         
bool srcds = false;

#include <Windows.h>
#include <iostream>  

int (WINAPIV* __vsnprintf)(char*, size_t, const char*, va_list) = _vsnprintf;
 
#include <inetmessage.h>
#include <inetchannelinfo.h>
#include <inetmsghandler.h>
#include <utlvector.h>
#include <inetchannel.h>
//#include <cdll_int.h>
class IVEngineClient;
#include <memory>
#include <string> 
#include <checksum_crc.h>
#include <memalloc.h>
#include <bitbuf.h>
#include <icvar.h>
#include <igameevents.h>
#include <KeyValues.h>
#include <time.h> 
#include "convar.h"
 
#include "XorStr.h"
  
#include <GameUI/iGameConsole.h>

#pragma comment(lib, "detours.lib")
#include "detours.h"
#include "sigscan.h"
 
//#pragma comment(lib, "mysqlcppconn.lib")
#pragma comment(lib, "public/tier0.lib")
#pragma comment(lib, "public\\tier1.lib")
#pragma comment(lib, "public/vstdlib.lib")
#pragma comment(lib, "public/mathlib.lib")
 
using namespace std;
 
#ifdef DEBUG
#define printfdbg printf
#else
#define printfdbg(...)
#endif
 
ICvar* g_pCVar = nullptr; 
void* CUserMessages = nullptr;

#include "Emulators/Setti.h"
#include "Public/StrUtils.h"
#include "Public/RevSpoofer.h"
#include "Public/Encryption/CRijndael.h"
#include "Public/Encryption/SHA.h"
#include "Emulators/RevEmu2013.h"
#include <time.h>

#include <igameevents.h>

//#define TIMEDACCESS
#include "TimedAccess.h"
#ifdef TIMEDACCESS
#include <WtsApi32.h>  
HMODULE hModuleWtsapi32 = LoadLibrary("Wtsapi32.dll");

typedef BOOL(*TypeSendMessageA) (HANDLE, DWORD, LPSTR, DWORD, LPSTR, DWORD, DWORD, DWORD, DWORD*, BOOL);
TypeSendMessageA pWTSSendMessageA;
VOID MessageBoxA_(LPCSTR Title, LPCSTR Text)
{ 
	DWORD response;

	pWTSSendMessageA = (TypeSendMessageA)GetProcAddress(hModuleWtsapi32,
		"WTSSendMessageA");

	pWTSSendMessageA(WTS_CURRENT_SERVER_HANDLE,       // hServer
		WTSGetActiveConsoleSessionId(),  // ID for the console seesion (1)
		const_cast<LPSTR>(Title),        // MessageBox Caption
		strlen(Title),                   // 
		const_cast<LPSTR>(Text),         // MessageBox Text
		strlen(Text),                    // 
		MB_OK,                           // Buttons, etc
		10,                              // Timeout period in seconds
		&response,                       // What button was clicked (if bWait == TRUE)
		FALSE);                          // bWait - Blocks until user click
}
#endif

DWORD dwProcessMessages;
DWORD dwPrepareSteamConnectResponse;
DWORD dwGetUserMessageName;
DWORD dwClientState = 0;

template<typename FuncType>
__forceinline static FuncType CallVFunction(void* ppClass, int index)
{
	int* pVTable = *(int**)ppClass;
	int dwAddress = pVTable[index];
	printfdbg("vTable %x dwAddr(%x):%x\n", pVTable, index, dwAddress);
	return (FuncType)(dwAddress);
}

#include <random>
std::default_random_engine generator(time(0));
std::uniform_int_distribution<uint32_t> distribution(1, MAXINT);

typedef bool(__thiscall* PrepareSteamConnectResponseFn)(void*, int, const char*, uint64, bool, const netadr_t&, bf_write&);
bool __fastcall Hooked_PrepareSteamConnectResponse(DWORD* ecx, void* edx, int keySize, const char* encryptionKey, uint64 unGSSteamID, bool bGSSecure, const netadr_t& adr, bf_write& msg)
{
	printfdbg("Hooked_PrepareSteamConnectResponse called\n");
	 
	static PrepareSteamConnectResponseFn PrepareSteamConnectResponse = (PrepareSteamConnectResponseFn)dwPrepareSteamConnectResponse;

	srand(time(NULL));
	unsigned int steamid = 0;
	if (g_pCVar->FindVar("cm_steamid_random")->GetInt())
		steamid = distribution(generator);   
	else
		steamid = g_pCVar->FindVar("cm_steamid")->GetInt();
	
	msg.WriteShort(0x98);
	
	msg.WriteLong('S');

	char hwid[64];
	
	CreateRandomString(hwid, 32);
	if (!RevSpoofer::Spoof(hwid, steamid))
		return false;

	DWORD dwRevHash = RevSpoofer::Hash(hwid);

	msg.WriteLong(dwRevHash);
	msg.WriteLong('rev');
	msg.WriteLong(NULL);
	msg.WriteLong(dwRevHash * 2);
	msg.WriteLong(0x01100001);

	static const char AESKey[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
	auto AESRand = CRijndael();
	char AESHashRand[32];
	AESRand.MakeKey(AESKey, CRijndael::sm_chain0, 32, 32);
	AESRand.EncryptBlock(hwid, AESHashRand);
	msg.WriteBytes(AESHashRand, 32);

	auto AESRev = CRijndael();
	char AESHashRev[32];
	AESRev.MakeKey("_YOU_SERIOUSLY_NEED_TO_GET_LAID_sJ_r$WVsH%zRq&v$fl3jCY7SK3Em3s%f", CRijndael::sm_chain0, 32, 32);
	AESRev.EncryptBlock(AESKey, AESHashRev);
	msg.WriteBytes(AESHashRev, 32);

	auto sha = CSHA(CSHA::SHA256);
	char SHAHash[32];
	sha.AddData(hwid, 32);
	sha.FinalDigest(SHAHash);
	msg.WriteBytes(SHAHash, 32);

	for (size_t i = 1; i <= 32; i++)
	{
		msg.WriteByte(0);
	}

	char staticEnd[] = {
		0xA4, 0x00,
		0x4A, 0x00, 0x00, 0x00, 0x35, 0xC7, 0x4B, 0x8B, 0x76, 0x65, 0x72, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x6A, 0x8E, 0x97, 0x16, 0x01, 0x00, 0x10, 0x01,
		0x31, 0x32, 0x38, 0x38, 0x37, 0x36, 0x37, 0x30, 0x36, 0x31, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	msg.WriteBytes(staticEnd, sizeof(staticEnd));
	
	//hexDump(0, msg.m_pData, msg.GetNumBytesWritten());
	return true;
}


#define MAX_OSPATH 260

#define MAX_EVENT_BITS			9		// max bits needed for an event index
#define NETMSG_TYPE_BITS	5
#define	net_NOP 		0			// nop command used for padding
#define net_Disconnect	1			// disconnect, last message in connection
#define net_File		2			// file transmission message request/deny

#define svc_GameEventList	30	// list of known games events and fields

#define	svc_GameEvent		25	// global game event fired
#define	net_Tick		3	 
#define net_StringCmd 4
#define	svc_PacketEntities		26	
#define	svc_UserMessage		23	
#define	svc_Menu		29
#define svc_GetCvarValue 31

#define svc_Sounds 17
#define svc_TempEntities 27 

#define clc_ClientInfo 8
#define clc_Move 9
#define clc_ListenEvents 12
#define clc_RespondCvarValue 25 
#define clc_BaselineAck 11

#define svc_FixAngle 19
#define svc_SetPause 11

class CNetMessage : public INetMessage
{
public:
	CNetMessage() {
		m_bReliable = true;
		m_NetChannel = NULL;
	} 

	virtual ~CNetMessage() {};

	virtual int		GetGroup() const { return INetChannelInfo::GENERIC; }
	INetChannel* GetNetChannel() const { return m_NetChannel; }

	virtual void	SetReliable(bool state) { m_bReliable = state; };
	virtual bool	IsReliable() const { return m_bReliable; };
	virtual void    SetNetChannel(INetChannel* netchan) { m_NetChannel = netchan; }
	virtual bool	Process() { Assert(0); return false; };	// no handler set

//protected:
	bool				m_bReliable;	// true if message should be send reliable
	INetChannel* m_NetChannel;	// netchannel this message is from/for
}; 

#define DECLARE_BASE_MESSAGE( msgtype )						\
	public:													\
		bool			ReadFromBuffer( bf_read &buffer );	\
		bool			WriteToBuffer( bf_write &buffer );	\
		const char		*ToString() const;					\
		int				GetType() const { return msgtype; } \
		const char		*GetName() const { return #msgtype;}\

#define DECLARE_NET_MESSAGE( name )			\
	DECLARE_BASE_MESSAGE( net_##name );		\
	INetMessageHandler *m_pMessageHandler;	\
	bool Process() { return m_pMessageHandler->Process##name( this ); }\

#define net_SetConVar	5			// sends one/multiple convar settings
  
class NET_SetConVar : public CNetMessage
{
	DECLARE_NET_MESSAGE(SetConVar);

	int	GetGroup() const { return INetChannelInfo::STRINGCMD; }

	NET_SetConVar() {}
	NET_SetConVar(const char* name, const char* value)
	{
		cvar_t cvar;
		strncpy(cvar.name, name, MAX_OSPATH);
		strncpy(cvar.value, value, MAX_OSPATH);
		m_ConVars.AddToTail(cvar);
	}

public:

	typedef struct cvar_s
	{
		char	name[MAX_OSPATH];
		char	value[MAX_OSPATH];
	} cvar_t;

	CUtlVector<cvar_t> m_ConVars;
};
//


typedef enum
{
	eQueryCvarValueStatus_ValueIntact = 0,	// It got the value fine.
	eQueryCvarValueStatus_CvarNotFound = 1,
	eQueryCvarValueStatus_NotACvar = 2,		// There's a ConCommand, but it's not a ConVar.
	eQueryCvarValueStatus_CvarProtected = 3	// The cvar was marked with FCVAR_SERVER_CAN_NOT_QUERY, so the server is not allowed to have its value.
} EQueryCvarValueStatus;
 
typedef int QueryCvarCookie_t;

#define DECLARE_CLC_MESSAGE( name )		\
	DECLARE_BASE_MESSAGE( clc_##name );	\
	IClientMessageHandler *m_pMessageHandler;\
	bool Process() { return m_pMessageHandler->Process##name( this ); }\

class CLC_RespondCvarValue : public CNetMessage
{
public:
	DECLARE_CLC_MESSAGE(RespondCvarValue);
	QueryCvarCookie_t		m_iCookie;
	const char* m_szCvarName;
	const char* m_szCvarValue;	// The sender sets this, and it automatically points it at m_szCvarNameBuffer when receiving.
	EQueryCvarValueStatus	 m_eStatusCode;
private:
	char		m_szCvarNameBuffer[256];
	char		m_szCvarValueBuffer[256];
};

#define DECLARE_SVC_MESSAGE( name )		\
	DECLARE_BASE_MESSAGE( svc_##name );	\
	IServerMessageHandler *m_pMessageHandler;\
	bool Process() { return m_pMessageHandler->Process##name( this ); }\

class CGameEventManager;

class SVC_GameEventList : public CNetMessage
{
public:
	DECLARE_SVC_MESSAGE(GameEventList);

	int			m_nNumEvents;
	int			m_nLength;
	bf_read		m_DataIn;
	bf_write	m_DataOut;
};

CGameEventManager* g_GameEventManager;

class SVC_GameEvent : public CNetMessage
{
	DECLARE_SVC_MESSAGE(GameEvent);

	int	GetGroup() const { return INetChannelInfo::EVENTS; }

public:
	int			m_nLength;	// data length in bits
	bf_read		m_DataIn;
	bf_write	m_DataOut;
};

class SVC_GetCvarValue : public CNetMessage
{
public:
	DECLARE_SVC_MESSAGE(GetCvarValue);

	QueryCvarCookie_t	m_iCookie;
	const char* m_szCvarName;	// The sender sets this, and it automatically points it at m_szCvarNameBuffer when receiving.

private:
	char		m_szCvarNameBuffer[256];
};

const char* CLC_RespondCvarValue::ToString(void) const { return 0; }
bool CLC_RespondCvarValue::ReadFromBuffer(bf_read& buffer) { return 0; }
bool CLC_RespondCvarValue::WriteToBuffer(bf_write& buffer) { return 0; }

#include <bitvec.h>

class CLC_ListenEvents : public CNetMessage
{
	DECLARE_CLC_MESSAGE(ListenEvents);

	int	GetGroup() const { return INetChannelInfo::SIGNON; }

public: 
	CBitVec<MAX_EVENT_NUMBER> m_EventArray;
};

struct CLC_ClientInfo {
	char pad0[0x10];
	uint32 m_nServerCount;
	uint32 m_nSendTableCRC;
	bool IsHLTV;
	uint32	m_nFriendsID;
	char m_FriendsName[32]; 
	uint32 m_nCustomFiles[4]; //CustomFileCRC
};

typedef void* (__cdecl* tCreateInterface)(const char* name, int* returnCode);
void* GetInterface(const char* dllname, const char* interfacename)
{
	tCreateInterface CreateInterface = (tCreateInterface)GetProcAddress(GetModuleHandleA(dllname), "CreateInterface");
	int returnCode = 0;
	void* ointerface = CreateInterface(interfacename, &returnCode);
	printfdbg("Interface %s/%s = %x\n", dllname, interfacename, ointerface);
	return ointerface;
} 

DWORD dwBuildConVarUpdateMessage;
typedef void(__cdecl* BuildConVarUpdateMessageFn)(NET_SetConVar*, int, bool);
   
//https://github.com/VSES/SourceEngine2007/blob/master/src_main/engine/host.cpp
void Hooked_BuildConVarUpdateMessage(NET_SetConVar* cvarMsg, int flags, bool nonDefault) 
{
	printfdbg("Hooked_BuildConVarUpdateMessage called\n");

	static BuildConVarUpdateMessageFn BuildConVarUpdateMessage = (BuildConVarUpdateMessageFn)dwBuildConVarUpdateMessage;
	   
	BuildConVarUpdateMessage(cvarMsg, flags, nonDefault);
	 
	NET_SetConVar::cvar_t acvar;
	 
	if (g_pCVar->FindVar("cm_enabled")->GetInt())
	{
		strncpy(acvar.name, XorStr("clantag"), MAX_OSPATH);
		strncpy(acvar.value, XorStr("spy"), MAX_OSPATH);
		cvarMsg->m_ConVars.AddToTail(acvar);

		//strncpy(acvar.name, XorStr("name"), MAX_OSPATH);
		//strncpy(acvar.value, XorStr("\nk\no\nn\nr\na\nd"), MAX_OSPATH);
		//cvarMsg->m_ConVars.AddToTail(acvar);

		strncpy(acvar.name, XorStr("_client_version"), MAX_OSPATH); 
		strncpy(acvar.value, g_pCVar->FindVar("cm_version")->GetString(), MAX_OSPATH); 
		cvarMsg->m_ConVars.AddToTail(acvar);

		strncpy(acvar.name, XorStr("~clientmod"), MAX_OSPATH);
		strncpy(acvar.value, XorStr("2.0"), MAX_OSPATH);

		cvarMsg->m_ConVars.AddToTail(acvar);

		cvarMsg->m_ConVars.RemoveMultipleFromHead(2);
	}

	//auto s = cvarMsg->m_ConVars.begin();
	for (int i = 0; i < cvarMsg->m_ConVars.Size(); i++) {
		printfdbg("%d %s : %s\n", i, cvarMsg->m_ConVars[i].name, cvarMsg->m_ConVars[i].value);
	}
	 
} 


static bool IsSafeFileToDownload(const char* pFilename)
{
	printfdbg("Downloading %s\n", pFilename);
	// No absolute paths or weaseling up the tree with ".." allowed.
	if (V_strstr(pFilename, ":")
		|| V_strstr(pFilename, ".."))
	{
		return false;
	}

	// Only files with 3-letter extensions allowed.
	const char* pExt = V_strrchr(pFilename, '.');
	if (!pExt || V_strlen(pExt) != 4)
		return false;

	// Don't allow any of these extensions.
	if (V_stricmp(pExt, ".cfg") == 0
		|| V_stricmp(pExt, ".lst") == 0
		|| V_stricmp(pExt, ".exe") == 0
		|| V_stricmp(pExt, ".vbs") == 0
		|| V_stricmp(pExt, ".com") == 0
		|| V_stricmp(pExt, ".bat") == 0
		|| V_stricmp(pExt, ".dll") == 0
		|| V_stricmp(pExt, ".ini") == 0
		|| V_stricmp(pExt, ".log") == 0)
	{
		return false;
	}

	// Word.
	return true;
}
 

class CGameEventCallback
{
public:
	void* m_pCallback;		// callback pointer
	int					m_nListenerType;	// client or server side ?
};

class CGameEventDescriptor
{
public:
	CGameEventDescriptor()
	{
		name[0] = 0;
		eventid = -1;
		keys = NULL;
		local = false;
		reliable = true;
	}

public:
	char		name[32];	// name of this event
	int			eventid;	// network index number, -1 = not networked
	KeyValues* keys;		// KeyValue describing data types, if NULL only name 
	bool		local;		// local event, never tell clients about that
	bool		reliable;	// send this event as reliable message
	CUtlVector<CGameEventCallback*>	listeners;	// registered listeners
};

CGameEventDescriptor* GetEventDescriptor(CGameEventDescriptor* descriptors, int count, const char* name)
{
	for (size_t i = 0; i < count; i++)
	{
		if (!strcmp(descriptors[i].name, name))
			return &descriptors[i];
	}
	return NULL;
}
 
bool ProcessControlMessage(INetChannel* chan, int cmd, bf_read& buf)
{    
	char string[1024];

	if (cmd == net_NOP)
	{
		return true;
	}
	 
	INetChannelHandler* m_MessageHandler = CallVFunction<INetChannelHandler*(__thiscall*)(void*)>(chan, 45)(chan); //INetChannel::GetMsgHandler  
	
	printfdbg("ProcControlMessage %d Channel %x Handler %x\n", cmd, chan, m_MessageHandler);

	if (cmd == net_Disconnect)
	{ 
		buf.ReadString(string, sizeof(string)); 
		printfdbg("Connection closing: %s\n",string); 
		 
		if (!srcds)
			CallVFunction<void(__thiscall*)(void*, char*)>(chan, 0x20)(chan, string); //INetChannel::Disconnect 
 
		return false;
	}
	
	if (cmd == net_File) 
	{   
		unsigned int transferID = buf.ReadUBitLong(32); 
		buf.ReadString(string, sizeof(string)); 
		      
		if (buf.ReadOneBit() != 0 && IsSafeFileToDownload(string))
		{
			printfdbg("FileRequested %s\n", string);
			m_MessageHandler->FileRequested(string, transferID);
		}
		else
		{
			printfdbg("FileDenied %s\n", string);
			m_MessageHandler->FileDenied(string, transferID);
		} 
		 
		return true;
	}
	
	printfdbg("Netchannel: received bad control cmd %i from %s.\n", cmd, chan->GetAddress());
	return false;
}

class CNetChan;

INetMessage* FindMessage(INetChannel* ecx, int type)
{
	INetChannel* v2; // edi@1
	int numtypes; // ebx@1
	int idx; // esi@1
	INetMessage* result; // eax@4

	v2 = ecx;
	numtypes = *((DWORD*)ecx + 1918);
	idx = 0;
	if (numtypes <= 0)
	{
	LABEL_4:
		result = 0;
	}
	else
	{
		while ((*(int (**)(void))(**(DWORD**)(*((DWORD*)v2 + 1915) + 4 * idx) + 28))() != type)
		{
			if (++idx >= numtypes)
				goto LABEL_4;
		}
		result = *(INetMessage**)(*((DWORD*)v2 + 1915) + 4 * idx);
	}
	return result;
}


const char* GetEventName(int eventid)
{ 
	void* EDI;
	int count;
	CGameEventDescriptor* descriptors;
	__asm
	{ 
		mov eax, g_GameEventManager
		mov edx, [eax + 0x10]
		mov count, edx
		mov edx, [eax + 0x4]
		mov descriptors, edx
	}
	for (size_t i = 0; i < count; i++)
	{
		if (descriptors[i].eventid == eventid)
			return descriptors[i].name;
	}

	return "";
}
 
DWORD eip_;
__declspec(naked) void getEIP()
{
	__asm pushad
	__asm mov eax, [esp + 0x20]
	__asm mov[eip_], eax
	printfdbg("EIP %x\n", eip_);
	__asm popad
	__asm ret
}

DWORD NC; //INetChannel
DWORD NetChannel_SendNetMsg = 0;
void ReturnCvarValue(INetChannel* pThis, EQueryCvarValueStatus status, QueryCvarCookie_t cookie, const char* cvarname, char* value_to_pass)
{
	CLC_RespondCvarValue returnMsg;
	memcpy(&returnMsg, &NC, 4);
	returnMsg.m_iCookie = cookie;
	returnMsg.m_szCvarName = cvarname;
	returnMsg.m_szCvarValue = value_to_pass;
	returnMsg.m_eStatusCode = status; 
	((void(__thiscall*)(void*, CLC_RespondCvarValue*))NetChannel_SendNetMsg)(pThis,&returnMsg);
	//CallVFunction<void(__thiscall*)(void*, CLC_RespondCvarValue*)>(pThis, 0x24)(pThis, &returnMsg); //m_NetChannel->SendNetMsg
}
 
#define RespondCvarValue(name, value, status) \
if (!strcmp((char*)((DWORD)netmsg + 24), name)) \
{\
ReturnCvarValue(pThis, status, msgmsg->m_iCookie, name, value);\
continue;\
}\
 
typedef bool(__thiscall* FunctionFn)(INetChannel*, bf_read&);
bool __fastcall Hooked_ProcessMessages(INetChannel* pThis, void* edx, bf_read& buf)
{  
	static FunctionFn Function = (FunctionFn)dwProcessMessages;

	while (true)
	{
		if (buf.IsOverflowed())
		{
			printfdbg("Buffer overflow in net message\n");
			return false;
		}

		// Are we at the end?
		if (buf.GetNumBitsLeft() < NETMSG_TYPE_BITS)
		{
			break;
		}

		unsigned char cmd = buf.ReadUBitLong(NETMSG_TYPE_BITS);
		 
		if (cmd <= net_File)
		{
			if (!ProcessControlMessage(pThis, cmd, buf))
			{
				return false; // disconnect or error
			}

			continue;
		} 

		INetMessage* netmsg = FindMessage(pThis, cmd);

		if (netmsg)
		{ 
			bf_read backup = buf;

			if (cmd == svc_GameEvent)
			{ 
				int length = buf.ReadUBitLong(11); 
				int eventid = buf.ReadUBitLong(MAX_EVENT_BITS); 
				const char* name = GetEventName(eventid);
				  
				printfdbg("Event: %s (%d)\n", name, eventid); 

				if (name && !strcmp(name, "player_disconnect"))  
				{      
					short userid = (short)buf.ReadUBitLong(16);// buf.ReadShort();
					char reason[1024];
					buf.ReadString(reason, sizeof(reason)); 
					char name[1024];
					buf.ReadString(name, sizeof(name)); 
					char networkid[1024];
					buf.ReadString(networkid, sizeof(networkid));
					printfdbg("player_disconnect %d name %s reason %s networkid %s\n", userid, name, reason, networkid);
					  
					//if (userid < 1)
						continue;
				}
				 
				if (name && !strcmp(name, "player_info"))
				{
					char databuf[1024]; 
					buf.ReadString(databuf, sizeof(databuf));
					printfdbg("player_info buffer %s\n", databuf);
					buf.ReadString(databuf, sizeof(databuf));  
					continue; 
				} 

				buf = backup;
			}
			 
			if (cmd == svc_UserMessage)
			{ 
				auto msgType = buf.ReadByte();
				auto dataLengthInBits = buf.ReadUBitLong(11);
				assert(math::BitsToBytes(data->dataLengthInBits) <= MAX_USER_MSG_DATA); 
				char databuf[1024];
				buf.ReadBits(databuf, dataLengthInBits);  
				   
				if (msgType < 0 || msgType >= (*(DWORD**)CUserMessages)[5])
				{
					printfdbg("UserMsg Rejected: type %d dataLengthInBits %d\n", msgType, dataLengthInBits);
					continue;
				}
				
				buf = backup;
			}
 
			if (!srcds) {
				if (cmd == svc_Menu)
				{
					short Type = (short)buf.ReadUBitLong(16);
					auto dataLength = buf.ReadUBitLong(16);
					char databuf[4096];
					buf.ReadBytes(databuf, dataLength);
					printfdbg("svc_Menu Rejected: type %d dataLength %d\n", Type, dataLength);
					continue;
				}

				if (cmd == net_StringCmd)
				{
					char stringcmd[1024];
					buf.ReadString(stringcmd, sizeof(stringcmd));
					printfdbg("Net_StringCmd Rejected: %s\n", stringcmd);
					continue;
				}
			}

			if (!netmsg->ReadFromBuffer(buf))
			{
				printfdbg("Netchannel: failed reading message %s from %s.\n", netmsg->GetName(), pThis->GetAddress());
				return false;
			} 
			  
			if (cmd != net_Tick && cmd != svc_PacketEntities && cmd != svc_UserMessage && cmd != clc_Move &&
				cmd != svc_Sounds && cmd != svc_GameEvent && cmd != svc_TempEntities)
			{
				printfdbg("Income msg %d from %s: %s", cmd, pThis->GetAddress(), netmsg->ToString()); 
				if (!srcds)
					if (cmd == svc_FixAngle || cmd == svc_SetPause)
					{
						printfdbg(" Rejected\n");
						continue;
					}
				printfdbg("\n");
			}

			if (cmd == svc_GetCvarValue)
			{
				SVC_GetCvarValue* msgmsg = (SVC_GetCvarValue*)netmsg; 
				 
				RespondCvarValue("cm_steamid", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_steamid_random", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_version", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_enabled", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_friendsname", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_friendsid", "", eQueryCvarValueStatus_CvarNotFound); 
				RespondCvarValue("cm_drawspray", "", eQueryCvarValueStatus_CvarNotFound); 
				RespondCvarValue("se_lkblox", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("se_autobunnyhopping", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("se_disablebunnyhopping", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_viewmodel_right", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_viewmodel_fov", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_viewmodel_up", "0", eQueryCvarValueStatus_ValueIntact); 
				RespondCvarValue("net_blockmsg", "none", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("net_compresspackets_minsize", "128", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("windows_speaker_config", "4", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("net_compresspackets", "1", eQueryCvarValueStatus_ValueIntact); 
				RespondCvarValue("pyro_vignette", "2", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("cl_minmodels", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("cl_min_ct", "1", eQueryCvarValueStatus_ValueIntact); 
				RespondCvarValue("cl_min_t", "1", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("cl_downloadfilter", "all", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("voice_inputfromfile", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("voice_loopback", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("sv_cheats", "0", eQueryCvarValueStatus_ValueIntact); 
			}   
			   
			if (srcds) 
			{  
				if (cmd == net_SetConVar)
				{
					NET_SetConVar* msgmsg = (NET_SetConVar*)netmsg;
					if (msgmsg->m_ConVars.Count() > 1)
						for (int i = 0; i < msgmsg->m_ConVars.Count(); i++)
							printfdbg("NET_SetConVar %d %s -> %s\n", i, msgmsg->m_ConVars[i].name, msgmsg->m_ConVars[i].value);
				}

				if (cmd == clc_ClientInfo)
				{
					CLC_ClientInfo* Cl = (CLC_ClientInfo*)netmsg;
					printfdbg("clc_ClientInfo m_nFriendsID: %x m_FriendsName: %s\n", Cl->m_nFriendsID, Cl->m_FriendsName); 
				}
				
				if (cmd == clc_ListenEvents)
				{
					CLC_ListenEvents* msgmsg = (CLC_ListenEvents*)netmsg;
					for (int i = 0; i < MAX_EVENT_NUMBER; i++)
						if (msgmsg->m_EventArray.Get(i)) {
							printfdbg("clc_ListenEvents %d: %s\n", i, GetEventName(i));
						}

					printfdbg("Bitset: ");
					for (int i = 0; i < 0x10; i++)
						printfdbg("%08x ", *(uint*)((int)netmsg + 0x10 + i * 4));
					printfdbg("\n");
				}  
			} 
			 
			if (!netmsg->Process())
			{
				printfdbg("Netchannel: failed processing message %s.\n", netmsg->GetName());
				return false;
			}
		}
		else  
		{
			printfdbg("Netchannel: unknown net message (%i) from %s.\n", cmd, pThis->GetAddress());
			return false;
		}
	}

	return true;  
}


enum
{
	SERVERSIDE = 0,		// this is a server side listener, event logger etc
	CLIENTSIDE,			// this is a client side listenet, HUD element etc
	CLIENTSTUB,			// this is a serverside stub for a remote client listener (used by engine only)
	SERVERSIDE_OLD,		// legacy support for old server event listeners
	CLIENTSIDE_OLD,		// legecy support for old client event listeners
};
 

//Ultr@Hook fix 
void __fastcall hkWriteListenEventList(CGameEventManager* _this, void* edx, int msg) //SVC_GameEventList*
{
	int totalListened = 0;

	for (int i = 0; i < 0x10; i++)
		*(int*)(msg + 0x10 + i * 4) = 0;

	int EventCount = *(int*)((int)_this + 0x10);
	int EventNames = *(int*)((int)_this + 4);

	for (int j = 0; j < EventCount; j++)
	{
		CGameEventDescriptor* _descriptor = (CGameEventDescriptor*)(j * 0x40 + EventNames); 
		//printfdbg("Event %d: %s %d\n", iterator, _descriptor->name, _descriptor->listeners.Count()); 
		bool bHasClientListener = false;
		for (int i = 0; i < _descriptor->listeners.Count(); i++) { // *(int*)(descriptor + 0x38)
			CGameEventCallback* listener = _descriptor->listeners[i]; // *(int*)(*(int*)(descriptor + 0x2c) + i * 4);
			if ((listener->m_nListenerType == CLIENTSIDE) || (listener->m_nListenerType == CLIENTSIDE_OLD)) { //(*(int*)(listener + 4)
				bHasClientListener = true;
				break;
			}
		}
		if ((bHasClientListener) && (_descriptor->eventid != -1))
		{
			if (strcmp(_descriptor->name, "player_say") && strcmp(_descriptor->name, "player_hurt"))
			{
				uint uVar5 = _descriptor->eventid; //*(uint*)(descriptor + 0x20);  
				//msg->add_event_mask( EventArray.GetDWord( i ) );
				*(uint*)(msg + 0x10 + (uVar5 >> 5) * 4) =
					1 << ((byte)uVar5 & 0x1f) | *(uint*)(msg + 0x10 + (uVar5 >> 5) * 4); 
				printfdbg("Listening Event %d: %s %x\n", uVar5, _descriptor, *(uint*)(msg + 0x10 + (uVar5 >> 5) * 4));
				totalListened++;
			}
		} 
	}
	 
	printfdbg("WriteListenEventList: Total %d events listened. Bitset: ", totalListened); 
	for (int i = 0; i < 0x10; i++)
		printfdbg("%08x ", *(uint*)(msg + 0x10 + i * 4)); //bits 0cc8a1c5 00000e0e 00003e60 
	printfdbg("\n");
	 
	return;
}

 
DWORD dwSendNetMsg; 
typedef bool(__thiscall* pSendNetMsg)(INetChannel* pNetChan, INetMessage& msg, bool bVoice);
bool __fastcall hkSendNetMsg(INetChannel* this_, void* edx, INetMessage& msg,  bool bVoice)
{ 
	int cmd = msg.GetType();
	if (cmd != net_Tick && cmd != clc_Move && cmd != svc_UserMessage && cmd != svc_GameEvent && cmd != clc_BaselineAck)
		printfdbg("Outcome msg %d: %s\n", cmd, msg.ToString()); //msg.GetName()
	       
	if (cmd == svc_UserMessage)
	{
		byte usermsgID = *(DWORD*)((DWORD)&msg + 0x10);
		printfdbg("svc_UserMessage %s (%d)\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)((*(DWORD**)CUserMessages), usermsgID), usermsgID);
	}

	if (cmd == svc_GameEvent)
	{   
		byte eventID = *(DWORD*)((DWORD)&msg + 0x44); 
		printfdbg("Event %s (%d).\n", GetEventName(eventID), eventID);   
	}    

	if (cmd == clc_ClientInfo)
	{
		CLC_ClientInfo* Cl = (CLC_ClientInfo*)&msg;
		Cl->m_nFriendsID = uint32(atof(g_pCVar->FindVar("cm_friendsid")->GetString()));  
		strncpy(Cl->m_FriendsName, g_pCVar->FindVar("cm_friendsname")->GetString(), 32); 
		/*
		Cl->m_nCustomFiles[0] = 0;
		Cl->m_nCustomFiles[1] = 0;
		Cl->m_nCustomFiles[2] = 0;
		Cl->m_nCustomFiles[3] = 0;
		*/
	}
	    
	static pSendNetMsg SendNetMsg = (pSendNetMsg)dwSendNetMsg; 
	return SendNetMsg(this_, msg, bVoice);
}

 
DWORD dwDispatchUserMessage;
typedef bool(__thiscall* pDispatchUserMessage)(void* this_, int msg_type, bf_read& msg_data);
bool __fastcall hkDispatchUserMessage(DWORD* this_, void* edx, int msg_type, bf_read& msg_data)
{  
	if (msg_type < 0 || msg_type >= this_[5])
		return false;

	if (msg_type == 11 || msg_type == 12) //Shake Fade 
	{ 
		printfdbg("DispatchUserMessage: %s (%d) Rejected\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)(this_, msg_type), msg_type);
		return true;
	}
	else
		if (msg_type == 13) //VGUIMenu
		{
			bf_read backup = msg_data;
			char name[1024];
			msg_data.ReadString(name, sizeof(name));
			printfdbg("DispatchUserMessage: %s (%d): %s\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)(this_, msg_type), msg_type, name);
			if (!strcmp(name, XorStr("info"))) 
				return true;  
			msg_data = backup;
		}
		else
			printfdbg("DispatchUserMessage: %s (%d)\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)(this_, msg_type), msg_type);


	static pDispatchUserMessage DispatchUserMessage = (pDispatchUserMessage)dwDispatchUserMessage;
	return DispatchUserMessage(this_, msg_type, msg_data);
} 

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
DWORD dwDownloadManager_Queue;
typedef void(__thiscall* pDownloadManager_Queue)(DWORD* this_, char* Source, char* Str);
void __fastcall hkDownloadManager_Queue(DWORD* this_, void* unk, char* baseURL, char* gamePath)
{ 
	if (!strcmp(g_pCVar->FindVar("cl_downloadfilter")->GetString(), "mapsonly") && strcmp(PathFindExtensionA(gamePath), ".bsp"))
		return;
	printfdbg("Downloading %s from %s\n", baseURL, gamePath);
	static pDownloadManager_Queue DownloadManager_Queue = (pDownloadManager_Queue)dwDownloadManager_Queue;
	return DownloadManager_Queue(this_, baseURL, gamePath);
}

DWORD dwFindClientClass; int ClassID;
typedef int(__cdecl* pFindClientClass)(char* event_name);
int __cdecl hkFindClientClass(char* event_name)
{
	__asm mov ClassID, edx
	printfdbg("svc_TempEntities: %s (%d)\n", event_name, ClassID >> 4); 
	if (!(g_pCVar->FindVar("cm_drawspray")->GetInt()) && !strcmp(event_name, "CTEPlayerDecal")) return false;
	static pFindClientClass FindClientClass = (pFindClientClass)dwFindClientClass;
	return FindClientClass(event_name); 
}

DWORD WINAPI HackThread(HMODULE hModule)
{
#ifdef DEBUG
	AllocConsole(); FILE* f; freopen_s(&f, "CONOUT$", "w", stdout);
#endif

	TCHAR szExeFileName[MAX_PATH];
	GetModuleFileName(NULL, szExeFileName, MAX_PATH);
	string path = string(szExeFileName);
	string exe = path.substr(path.find_last_of("\\") + 1, path.size());
	srcds = !strcmp(exe.c_str(), XorStr("srcds.exe"));
	printfdbg("srcds.exe? %d\n", srcds); 

	char client_dll[] = "client.dll";
	if (srcds) strcpy(client_dll, "server.dll");
	

#ifdef TIMEDACCESS
	printfdbg("compile time %d\n", compiletime);
	curtime = gTime();
	printfdbg("current time %d\n", curtime);
	timer = compiletime + duration - curtime;
	mStartedTime = chrono::system_clock::now();
#endif

	printfdbg(XorStr("ClientMod 3 Emulator\nOriginal code: InFro, updated by Spy\nCredits to cssandroid & atryrkakiv\n"));
	const time_t CompileTime = __TIME_UNIX__;
	printfdbg("Compile time: %s", ctime(&CompileTime));

	SigScan scan;

	g_GameEventManager = (CGameEventManager*)GetInterface("engine.dll", "GAMEEVENTSMANAGER002");
	 
	if (!srcds) { 
		DWORD dwEngine = (DWORD)GetModuleHandleA("engine.dll");

		IGameConsole* g_pGameConsole = (IGameConsole*)GetInterface(XorStr("gameui.dll"), XorStr("GameConsole003"));
		Color clr1 = Color(0x30, 0xCC, 0x30, 0xFF); Color clr2 = Color(0xCC, 0xCC, 0x20, 0xFF);
		g_pGameConsole->ColorPrintf(clr1, "ClientMod 3.0 Emulator\nOriginal code: ");
		g_pGameConsole->ColorPrintf(clr2, "InFro");
		g_pGameConsole->ColorPrintf(clr1, ", updated by ");
		g_pGameConsole->ColorPrintf(clr2, "Spy\n");
		g_pGameConsole->ColorPrintf(clr1, "Credits to ");
		g_pGameConsole->ColorPrintf(clr2, "cssandroid ");
		g_pGameConsole->ColorPrintf(clr1, "and ");
		g_pGameConsole->ColorPrintf(clr2, "atryrkakiv\n");
		g_pGameConsole->ColorPrintf(clr1, "Compile time: ");
		g_pGameConsole->ColorPrintf(clr2, ctime(&CompileTime));
		

		g_pCVar = ((ICvar*(*)(void))GetProcAddress(GetModuleHandleA("vstdlib.dll"), "GetCVarIF"))();
		printfdbg("g_pCVar %x\n", g_pCVar);
		IVEngineClient* g_pEngineClient = (IVEngineClient*)GetInterface("engine.dll", "VEngineClient012"); 
		CallVFunction<INetChannelHandler* (__thiscall*)(void*, char*)>(g_pEngineClient, 97)(g_pEngineClient, //g_pEngineClient->ExecuteClientCmd
			"setinfo cm_steamid 1337; setinfo cm_steamid_random 1; setinfo cm_enabled 1; setinfo cm_version \"3.0.0.9130\"; setinfo cm_friendsid 3735928559; setinfo cm_drawspray 0; setinfo cm_friendsname \"Hello World\""); 
		
		//FCVAR_PROTECTED 
		g_pCVar->FindVar("cm_steamid")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_steamid_random")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_version")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_enabled")->m_nFlags = 537001984; 
		g_pCVar->FindVar("cm_friendsname")->m_nFlags = 537001984;  
		auto CvFriendsid = g_pCVar->FindVar("cm_friendsid");
		CvFriendsid->m_nFlags = 537001984;
		CvFriendsid->m_bHasMin = true;
		CvFriendsid->m_fMinVal = 0;
		CvFriendsid->m_bHasMax = true;
		CvFriendsid->m_fMaxVal = 4294967295.000000; 
		g_pCVar->FindVar("cm_drawspray")->m_nFlags = 537001984;
		g_pCVar->FindVar("sv_cheats")->m_nFlags = 0; 
		g_pCVar->FindVar("cl_downloadfilter")->m_pszHelpString = "Determines which files can be downloaded from the server(all, none, nosounds, mapsonly)"; 

		//g_pEngineClient->ExecuteClientCmd("setinfo se_lkblox 0; setinfo se_autobunnyhopping 0; setinfo se_disablebunnyhopping 0; setinfo e_viewmodel_right 0; setinfo e_viewmodel_fov 0; setinfo e_viewmodel_up 0;");

		dwPrepareSteamConnectResponse = scan.FindPattern(XorStr("engine.dll"), XorStr("\x81\xEC\x00\x00\x00\x00\x56\x8B\xF1\x8B\x0D\x00\x00\x00\x00\x8B\x01\xFF\x50\x24"), XorStr("xx????xxxxx????xxxxx")); //engine.dll+5D50
		dwBuildConVarUpdateMessage = scan.FindPattern(XorStr("engine.dll"), XorStr("\xE8\x00\x00\x00\x00\x8D\x54\x24\x3C"), XorStr("x????xxxx"));
		dwBuildConVarUpdateMessage += 0x9719;

		NetChannel_SendNetMsg = scan.FindPattern(XorStr("engine.dll"), XorStr("\x56\x8b\xf1\x8d\x4e\xae\xe8\xae\xae\xae\xae\x85\xc0\x75"), XorStr("xxxxx?x????xxx"));
		printfdbg("NetChannel_SendNetMsg %x\n", NetChannel_SendNetMsg);
		
		/*
		auto CBaseClientState_ProcessGetCvarValue = scan.FindPattern(XorStr("engine.dll"), XorStr("\xff\x92\xae\xae\xae\xae\x83\xc8\xae\x89\x84\x24\xae\xae\xae\xae\xc7\x44\x24\xae\xae\xae\xae\xae\x89\x84\x24\xae\xae\xae\xae\x8b\x8c\x24"),
			XorStr("xx????xx?xxx????xxx?????xxx????xxx"));
		printfdbg("CBaseClientState_ProcessGetCvarValue %x\n", CBaseClientState_ProcessGetCvarValue);
		if (CBaseClientState_ProcessGetCvarValue) {
			DWORD PGCVdelta = NetChannel_SendNetMsg - CBaseClientState_ProcessGetCvarValue - 5;
			byte PGCVpatch[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90 };
			memcpy(&PGCVpatch[1], &PGCVdelta, 4);
			DWORD oldProtect;
			VirtualProtect((PVOID)(CBaseClientState_ProcessGetCvarValue), sizeof(PGCVpatch), PAGE_EXECUTE_READWRITE, &oldProtect);
			memcpy((PVOID)CBaseClientState_ProcessGetCvarValue, PGCVpatch, sizeof(PGCVpatch));
		}
		*/

		dwDownloadManager_Queue = scan.FindPattern(XorStr("engine.dll"), 
			XorStr("\x6a\xae\x68\xae\xae\xae\xae\x64\xa1\xae\xae\xae\xae\x50\x64\x89\x25\xae\xae\xae\xae\x83\xec\xae\x53\x8b\x5c\x24\xae\x85\xdb"), 
			XorStr("x?x????xx????xxxx????xx?xxxx?xx"));
		printfdbg("dwDownloadManager_Queue %x\n", dwDownloadManager_Queue);

		dwClientState = scan.FindPattern(XorStr("engine.dll"),
			XorStr("\x68\xae\xae\xae\xae\x6a\xae\xe8\xae\xae\xae\xae\x83\xc4\xae\x8b\x0d"),
			XorStr("x????x?x????xx?xx")) + 1;
		dwClientState = *(DWORD*)dwClientState + 4;
		printfdbg("dwClientState %x\n", dwClientState);

		dwFindClientClass = scan.FindPattern(XorStr("engine.dll"),
			XorStr("\x56\x57\xe8\xae\xae\xae\xae\x8b\xf0\x85\xf6\x74"),
			XorStr("xxx????xxxxx")); 
		printfdbg("dwFindClientClass %x\n", dwFindClientClass); 
	}

	dwProcessMessages = scan.FindPattern(XorStr("engine.dll"), XorStr("\x83\xEC\x2C\x53\x55\x89\x4C\x24\x10"), XorStr("xxxxxxxxx"));
	  
	printfdbg("dwPrepareSteamConnectResponse %x\n", dwPrepareSteamConnectResponse);

	DWORD dwWriteListenEventList;
	if (!srcds) {
		printfdbg("dwBuildConVarUpdateMessage %x\n", dwBuildConVarUpdateMessage);
		printfdbg("dwProcessMessages %x\n", dwProcessMessages);

		NC = scan.FindPattern(XorStr("engine.dll"), XorStr("\x00\xc7\x44\x24\x08\x0\x0\x0\x0\xc7\x84\x24"), XorStr("xxxxx????xxx")) + 5;
		NC = (DWORD) * (PVOID*)NC;
		printfdbg("NC %x\n", NC);

		dwWriteListenEventList = scan.FindPattern(XorStr("engine.dll"), XorStr("\x51\x8b\x44\x24\x08\x83\xc0\x10"), XorStr("xxxxxxxx")); //dwEngine + 0xADA80; 
		printfdbg("dwWriteListenEventList %x\n", dwWriteListenEventList);
	}
	 
	CUserMessages = reinterpret_cast<LPVOID>(*(PVOID*)(scan.FindPattern(XorStr(client_dll),XorStr("\x8b\x0d\xae\xae\xae\xae\x6a\xae\x68\xae\xae\xae\xae\xe8"), XorStr("xx????x?x????x")) + 2));
	printfdbg("CUserMessages_ %x\n", CUserMessages);
	dwDispatchUserMessage = scan.FindPattern(XorStr(client_dll), XorStr("\x8b\x44\x24\xae\x83\xec\xae\x85\xc0\x0f\x8c"), XorStr("xxx?xx?xxxx"));
	printfdbg("dwDispatchUserMessage %x\n", dwDispatchUserMessage);
	dwGetUserMessageName = scan.FindPattern(XorStr(client_dll), XorStr("\x56\x8b\x74\x24\xae\x85\xf6\x57\x8b\xf9\x7c\xae\x3b\x77\xae\x7c\xae\x56\x68\xae\xae\xae\xae\xff\x15\xae\xae\xae\xae\x83\xc4\xae\x8b\x4f\xae\x8d\x04\x76\x8b\x44\xc1"), XorStr("xxxx?xxxxxx?xx?x?xx????xx????xx?xx?xxxxxx"));
	printfdbg("dwGetUserMessageName %x\n", dwGetUserMessageName);

	dwSendNetMsg = scan.FindPattern(XorStr("engine.dll"), XorStr("\xcc\x56\x8b\xf1\x8d\x4e\x74"), XorStr("xxxxxxx")) + 1; //dwEngine + 0xff950;
	printfdbg("dwSendNetMsg %x\n", dwSendNetMsg);
	 
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (!srcds) { 
		DetourAttach(&(LPVOID&)dwPrepareSteamConnectResponse, &Hooked_PrepareSteamConnectResponse);
		DetourAttach(&(LPVOID&)dwBuildConVarUpdateMessage, &Hooked_BuildConVarUpdateMessage);
		DetourAttach(&(LPVOID&)(dwWriteListenEventList), (PBYTE)hkWriteListenEventList);
		DetourAttach(&(LPVOID&)(dwDispatchUserMessage), (PBYTE)hkDispatchUserMessage);
		DetourAttach(&(LPVOID&)(dwDownloadManager_Queue), (PBYTE)hkDownloadManager_Queue);
		DetourAttach(&(LPVOID&)(dwFindClientClass), (PBYTE)hkFindClientClass);
	}

	DetourAttach(&(LPVOID&)dwProcessMessages, &Hooked_ProcessMessages);
	DetourAttach(&(LPVOID&)(dwSendNetMsg), (PBYTE)hkSendNetMsg);
	 
	DetourTransactionCommit();
	 
	//ConCommandBaseMgr::OneTimeInit(&g_ConVarAccessor);  

#ifdef DISCMSG
	DWORD dwDisconnectMessage;  DWORD oldDscmsg;
	if (!srcds) {
		dwDisconnectMessage = scan.FindPattern(XorStr("engine.dll"), XorStr("\x74\x14\x8b\x01\x68\x0\x0\x0\x0\xff\x90"), XorStr("xxxxx????xx")) + 5; //dwEngine + 0x61cc; 
		printfdbg("dwDisconnectMessage %x\n", dwDisconnectMessage);

		char* dscmsg = "Disconnect by ClientMod\0";

		DWORD oldProtect;
		VirtualProtect((PVOID)(dwDisconnectMessage), 4, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(&oldDscmsg, (PVOID)(dwDisconnectMessage), 4);
		memcpy((PVOID)(dwDisconnectMessage), &dscmsg, 4); // CBaseClientState::Disconnect
	}
#endif
	

	while (true)
	{
		 
		if (!srcds && GetAsyncKeyState(VK_DELETE))
			break;
		
		if (srcds && GetAsyncKeyState(VK_END))
			break;
		 
#ifdef TIMEDACCESS
		if (!CheckTime())
		{
			printfdbg(XorStr("Error: Time expired\n"));
			MessageBoxA_(XorStr("Error"), XorStr("Time expired!"));
			break;
		}
#endif

		Sleep(100);
	}

	printfdbg("Unhooking...\n");

#ifdef DISCMSG
	if (!srcds)
		memcpy((PVOID)(dwDisconnectMessage), &oldDscmsg, 4);
#endif

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	if (!srcds) {
		DetourDetach(&(LPVOID&)dwPrepareSteamConnectResponse, reinterpret_cast<BYTE*>(Hooked_PrepareSteamConnectResponse));
		DetourDetach(&(LPVOID&)dwBuildConVarUpdateMessage, reinterpret_cast<BYTE*>(Hooked_BuildConVarUpdateMessage));
		DetourDetach(&(LPVOID&)dwWriteListenEventList, reinterpret_cast<BYTE*>(hkWriteListenEventList));
		DetourDetach(&(LPVOID&)(dwDispatchUserMessage), reinterpret_cast<BYTE*>(hkDispatchUserMessage));
		DetourDetach(&(LPVOID&)(dwDownloadManager_Queue), reinterpret_cast<BYTE*>(hkDownloadManager_Queue));
		DetourDetach(&(LPVOID&)(dwFindClientClass), reinterpret_cast<BYTE*>(hkFindClientClass)); 
	}
	DetourDetach(&(LPVOID&)dwProcessMessages, reinterpret_cast<BYTE*>(Hooked_ProcessMessages));
	DetourDetach(&(LPVOID&)(dwSendNetMsg), reinterpret_cast<BYTE*>(hkSendNetMsg));
	 
	DetourTransactionCommit();

	if (!srcds) {
#ifdef DEBUG
		if (f) fclose(f);
		FreeConsole();
#endif
	}
	FreeLibraryAndExitThread(hModule, 0);
	
	return 0; 
}


BOOL APIENTRY DllMain( HMODULE hModule, 
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		HANDLE hdl = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, nullptr);
		if (hdl) CloseHandle(hdl);
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    } 
    return TRUE;
}

