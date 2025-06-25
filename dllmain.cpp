// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS
#define DEBUG   
#define DISCMSG
//#define TIMEDACCESS 

#include <Windows.h>
#include <iostream>  

bool srcds = false; bool textmode = false;
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

#include "hash.h"
#include "defs.h"

//#pragma comment(lib, "mysqlcppconn.lib")
#pragma comment(lib, "public/tier0.lib")
#pragma comment(lib, "public\\tier1.lib")
#pragma comment(lib, "public/vstdlib.lib")
#pragma comment(lib, "public/mathlib.lib")

using namespace std;

#include <fstream>
ofstream logfile;
#ifdef DEBUG
#include <iomanip>
//#define printfdbg printf
void printfdbg(const char* format, ...)
{
	va_list arglist;
	auto time = std::time(nullptr);
	std::cout << std::put_time(std::localtime(&time), "[%H:%M:%S] ");
	logfile << std::put_time(std::localtime(&time), "[%H:%M:%S] ");
	va_start(arglist, format);
	//vprintf(format, arglist); 
	char logstring[1024];
	vsprintf(logstring, format, arglist);
	va_end(arglist);
	printf(logstring);
	logfile << logstring;
}
#else
#define printfdbg(...)
#endif

HMODULE hMod = 0;
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
#ifdef TIMEDACCESS
#include "TimedAccess.h"
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
IVEngineClient* g_pEngineClient = 0;
DWORD dwDisconnectMessage = 0;

struct CM
{
	int NumPlayers = 0;
	int UserID = 0;
	char Map[255];
	int Port = 0;
	int MaxPlayers = 0;
	int ServerCount = 0;
	int FriendsID = 0;
	int PlayerSlot = 0;
}; CM* _CM = new CM;


template<typename FuncType>
__forceinline static FuncType CallVFunction(void* ppClass, int index)
{
	int* pVTable = *(int**)ppClass;
	int dwAddress = pVTable[index];
	//printfdbg("vTable %x dwAddr(%x):%x\n", pVTable, index, dwAddress);
	return (FuncType)(dwAddress);
}

#include <random>
std::default_random_engine generator(time(0));
std::uniform_int_distribution<uint32_t> distribution(1, MAXINT);
std::uniform_int_distribution<uint32_t> friendsID(0xD000000, 0xDD00000);

#include "Emulators/Setti.h"

typedef bool(__thiscall* PrepareSteamConnectResponseFn)(void*, int, const char*, uint64, bool, const netadr_t&, bf_write&);
bool __fastcall Hooked_PrepareSteamConnectResponse(DWORD* ecx, void* edx, int keySize, const char* encryptionKey, uint64 unGSSteamID, bool bGSSecure, const netadr_t& adr, bf_write& msg)
{
	printfdbg("PrepareSteamConnectResponse called\n");

	static PrepareSteamConnectResponseFn PrepareSteamConnectResponse = (PrepareSteamConnectResponseFn)dwPrepareSteamConnectResponse;
	if (!g_pCVar->FindVar("cm_steamid_enabled")->GetInt())
		PrepareSteamConnectResponse(ecx, keySize, encryptionKey, unGSSteamID, bGSSecure, adr, msg);

	srand(time(NULL));
	unsigned int steamid = 0;
	if (g_pCVar->FindVar("cm_steamid_random")->GetInt())
		steamid = distribution(generator);
	else
		steamid = g_pCVar->FindVar("cm_steamid")->GetInt();

	msg.WriteShort(0x98);
	msg.WriteLong('S');
	 
	char hwid[64];
	generateRandomHWID(hwid); //CreateRandomString(hwid, 32);

	if (!RevSpoofer::Spoof(hwid, steamid)) {
		printfdbg("RevSpoofer::Spoof ERROR\n");
		CallVFunction<IVEngineClient* (__thiscall*)(void*, char*)>(g_pEngineClient, 97)(g_pEngineClient, "retry");
		return false;
	}

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
	//msg.WriteBytes(staticEnd, sizeof(staticEnd));

	//hexDump(0, msg.m_pData, msg.GetNumBytesWritten()); 
	return true;
}

//https://github.com/VSES/SourceEngine2007/blob/master/src_main/common/protocol.h
#define DELTASIZE_BITS		20	// must be: 2^DELTASIZE_BITS > (NET_MAX_PAYLOAD * 8)
//https://github.com/0TheSpy/hl2sdk/blob/master/public/const.h
#define	MAX_EDICT_BITS				11			// # of bits needed to represent max edicts
// Max # of edicts in a level
#define	MAX_EDICTS					(1<<MAX_EDICT_BITS)
// Used for networking ehandles.
#define NUM_ENT_ENTRY_BITS		(MAX_EDICT_BITS + 1)
#define NUM_ENT_ENTRIES			(1 << NUM_ENT_ENTRY_BITS)
#define ENT_ENTRY_MASK			(NUM_ENT_ENTRIES - 1)
#define INVALID_EHANDLE_INDEX	0xFFFFFFFF

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
#define net_SignonState 6
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
#define svc_ServerInfo 8
#define svc_CreateStringTable 12

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

#define AddtoTailWithVal(cvar, val) strncpy(acvar.name, XorStr(cvar), MAX_OSPATH);\
strncpy(acvar.value, val, MAX_OSPATH);\
cvarMsg->m_ConVars.AddToTail(acvar);

#define AddtoTail(cvar) strncpy(acvar.name, XorStr(cvar), MAX_OSPATH);\
strncpy(acvar.value, g_pCVar->FindVar(cvar)->GetString(), MAX_OSPATH);\
cvarMsg->m_ConVars.AddToTail(acvar);


//https://github.com/VSES/SourceEngine2007/blob/master/src_main/engine/host.cpp
void Hooked_BuildConVarUpdateMessage(NET_SetConVar* cvarMsg, int flags, bool nonDefault)
{
	printfdbg("Hooked_BuildConVarUpdateMessage called\n");

	static BuildConVarUpdateMessageFn BuildConVarUpdateMessage = (BuildConVarUpdateMessageFn)dwBuildConVarUpdateMessage;

	BuildConVarUpdateMessage(cvarMsg, flags, nonDefault);

	NET_SetConVar::cvar_t acvar;

	if (g_pCVar->FindVar("cm_enabled")->GetInt())
	{
		cvarMsg->m_ConVars.RemoveAll();
		AddtoTail("cl_team");
		AddtoTail("cl_updaterate");
		AddtoTailWithVal("_client_version", g_pCVar->FindVar("cm_version")->GetString());
		AddtoTail("cl_interp");
		AddtoTailWithVal("~clientmod", "2.0");
		AddtoTail("cl_lagcompensation");
		AddtoTail("cl_interp_npcs");
		AddtoTail("cl_interpolate");
		AddtoTail("cl_cmdrate");
		AddtoTail("cl_language");
		AddtoTail("english");
		AddtoTail("name");
		AddtoTail("cl_autohelp");
		AddtoTail("cl_predictweapons");
		AddtoTail("cl_rebuy");
		AddtoTail("cl_class");
		AddtoTailWithVal("clantag", "");
		AddtoTail("tv_nochat");
		AddtoTail("hap_HasDevice");
		AddtoTail("cl_predict");
		AddtoTail("cl_spec_mode");
		AddtoTail("rate");
		AddtoTail("cl_autobuy");
		AddtoTail("cl_interp_ratio");
		AddtoTail("closecaption");
		AddtoTailWithVal("voice_loopback", "0");
		AddtoTail("cl_autowepswitch");
	}

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

	INetChannelHandler* m_MessageHandler = CallVFunction<INetChannelHandler * (__thiscall*)(void*)>(chan, 45)(chan); //INetChannel::GetMsgHandler  

	printfdbg("ProcControlMessage %d Channel %x Handler %x\n", cmd, chan, m_MessageHandler);

	if (cmd == net_Disconnect)
	{
		buf.ReadString(string, sizeof(string));
		printfdbg("Connection closing: %s\n", string);

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

enum UpdateType
{
	EnterPVS = 0,	// Entity came back into pvs, create new entity if one doesn't exist
	LeavePVS,		// Entity left pvs
	DeltaEnt,		// There is a delta for this entity.
	PreserveEnt,	// Entity stays alive but no delta ( could be LOD, or just unchanged )
	Finished,		// finished parsing entities successfully
	Failed,			// parsing error occured while reading entities
};

//https://github.com/VSES/SourceEngine2007/blob/master/src_main/common/protocol.h
// Flags for delta encoding header
enum
{
	FHDR_ZERO = 0x0000,
	FHDR_LEAVEPVS = 0x0001,
	FHDR_DELETE = 0x0002,
	FHDR_ENTERPVS = 0x0004,
};

int m_nHeaderBase = -1;
int m_nNewEntity = -1;
int m_nOldEntity = -1;

//https://github.com/ValveSoftware/source-sdk-2013/blob/master/mp/src/public/iclientnetworkable.h
// NOTE: All of these are commented out; NotifyShouldTransmit actually
// has all these in them. Left it as an enum in case we want to go back though
enum DataUpdateType_t
{
	DATA_UPDATE_CREATED = 0,	// indicates it was created +and+ entered the pvs
	//	DATA_UPDATE_ENTERED_PVS,
	DATA_UPDATE_DATATABLE_CHANGED,
	//	DATA_UPDATE_LEFT_PVS,
	//	DATA_UPDATE_DESTROYED,		// FIXME: Could enable this, but it's a little worrying
									// since it changes a bunch of existing code
};

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
	((void(__thiscall*)(void*, CLC_RespondCvarValue*))NetChannel_SendNetMsg)(pThis, &returnMsg);
	//CallVFunction<void(__thiscall*)(void*, CLC_RespondCvarValue*)>(pThis, 0x24)(pThis, &returnMsg); //m_NetChannel->SendNetMsg
}

#define RespondCvarValue(name, value, status) \
if (!stricmp((char*)((DWORD)netmsg + 24), name)) \
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

				printfdbg("svc_GameEvent: %s (%d)\n", name, eventid);

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

				if (cmd == svc_ServerInfo)
				{
					printfdbg("svc_ServerInfo:\n");
					printfdbg("m_nProtocol %d\n", (uint16)buf.ReadUBitLong(16));
					_CM->ServerCount = (uint32)buf.ReadUBitLong(32);
					printfdbg("m_nServerCount %d\n", _CM->ServerCount);
					printfdbg("m_bIsHLTV %d\n", (byte)buf.ReadOneBit() != 0);
					printfdbg("m_bIsDedicated %d\n", (byte)buf.ReadOneBit() != 0);
					printfdbg("m_nClientCRC %x\n", (long)buf.ReadLong());
					printfdbg("m_nMaxClasses %d\n", (WORD)buf.ReadWord());
					printfdbg("m_nMapCRC %x\n", (long)buf.ReadLong());
					_CM->PlayerSlot = (byte)buf.ReadByte();
					printfdbg("m_nPlayerSlot %d\n", _CM->PlayerSlot);
					_CM->MaxPlayers = (byte)buf.ReadByte();
					printfdbg("m_nMaxClients %d\n", _CM->MaxPlayers);
					printfdbg("m_fTickInterval %f\n", (float32)buf.ReadFloat());
					printfdbg("m_cOS %c\n", (byte)buf.ReadChar());
					char GameDir[1024]; buf.ReadString(GameDir, sizeof(GameDir));
					buf.ReadString(_CM->Map, sizeof(_CM->Map));
					char SkyName[1024]; buf.ReadString(SkyName, sizeof(SkyName));
					char HostName[1024]; buf.ReadString(HostName, sizeof(HostName));
					printfdbg("m_szGameDirBuffer %s\n", GameDir);
					printfdbg("m_szMapNameBuffer %s\n", _CM->Map);
					printfdbg("m_szSkyNameBuffer %s\n", SkyName);
					printfdbg("m_szHostNameBuffer %s\n", HostName);
					buf = backup;
				}

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
				printfdbg("Income msg %d from %s: %s\n", cmd, pThis->GetAddress(), netmsg->ToString());
				if (!srcds)
					if (cmd == svc_FixAngle || cmd == svc_SetPause)
					{
						//printf(" Rejected\n");
						continue;
					}
				//printf("\n");
			}

			if (cmd == svc_GetCvarValue)
			{
				SVC_GetCvarValue* msgmsg = (SVC_GetCvarValue*)netmsg;

				RespondCvarValue("cm_steamid", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_steamid_random", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_steamid_enabled", "", eQueryCvarValueStatus_CvarNotFound); 
				RespondCvarValue("cm_version", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_enabled", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_forcemap", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_drawspray", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_fakeconnect", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("cm_log", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("se_lkblox", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("se_autobunnyhopping", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("se_disablebunnyhopping", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_viewmodel_right", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_viewmodel_fov", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_viewmodel_up", "0", eQueryCvarValueStatus_ValueIntact);

				RespondCvarValue("se_respawn_on_death", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_blood_scale", "1", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_bob_lower_amt", "21", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("mat_potato_mode", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("mat_async_tex_maxtime_ms", "0.5", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("mat_colcorrection_disableentities", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("se_doubleduck", "0", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("se_nowinpanel", "1", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("se_newsmoke", "14", eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("e_showserverinfo", "0", eQueryCvarValueStatus_ValueIntact);

				RespondCvarValue("async_toggle_priority", "", eQueryCvarValueStatus_CvarNotFound);
				RespondCvarValue("_client_version", (char*)g_pCVar->FindVar("cm_version")->GetString(), eQueryCvarValueStatus_ValueIntact);
				RespondCvarValue("~clientmod", "2.0", eQueryCvarValueStatus_ValueIntact);

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
		printf("%08x ", *(uint*)(msg + 0x10 + i * 4)); //bits 0cc8a1c5 00000e0e 00003e60 
	printf("\n");

	return;
}

#define SIGNONSTATE_NONE		0	// no state yet, about to connect
#define SIGNONSTATE_CHALLENGE	1	// client challenging server, all OOB packets
#define SIGNONSTATE_CONNECTED	2	// client is connected to server, netchans ready
#define SIGNONSTATE_NEW			3	// just got serverinfo and string tables
#define SIGNONSTATE_PRESPAWN	4	// received signon buffers
#define SIGNONSTATE_SPAWN		5	// ready to receive entity packets
#define SIGNONSTATE_FULL		6	// we are fully connected, first non-delta packet received
#define SIGNONSTATE_CHANGELEVEL	7	// server is changing level, please wait


void MD5UpdateString(MD5Context_t* ctx, std::string str)
{
	MD5Update(ctx, (unsigned char*)(str.c_str()), str.length());
}

void BinaryToReadable(unsigned char* in, size_t inlen, std::string& out)
{
	char buf[4];
	for (size_t i = 0; i < inlen; i++)
	{
		auto c = in[i];
		snprintf(buf, sizeof(buf), (c <= ' ' || c >= 'y') ? "%02x" : "%01c", c);
		out.append(buf);
	}
}

void GenerateFriendsName(char* friendsName, size_t uMaxLength)
{
	MD5Context_t ctx;
	unsigned char digest[16];

	MD5Init(&ctx);

	ctx.buf[0] += 0x20;
	ctx.buf[1] -= 0x12;
	ctx.buf[2] += 0x79;
	ctx.buf[3] -= 0x8B;

	char md5string[255];
	sprintf(md5string, "7LRUT827L05D4GX7AG2LFR5NFI2SOHQ0%d0%d0%s%d%d%d%uDWXU38QN7A0X783WL2585UD753U0D6RE",
		_CM->PlayerSlot + 1, _CM->UserID, _CM->Map, _CM->Port, _CM->MaxPlayers, _CM->ServerCount, _CM->FriendsID);

	printfdbg("Key %s\n", md5string);
	MD5UpdateString(&ctx, md5string);

	MD5Final(digest, &ctx);

	for (size_t i = 0; i < sizeof(digest); i++)
	{
		digest[i] ^= 0x12; // static key
	}

	std::string readableHash;
	BinaryToReadable(digest, sizeof(digest), readableHash);

	CRC32_t checksum = -1;
	CRC32_ProcessBuffer(&checksum, digest, sizeof(digest));

	checksum = ~checksum;

	char szReadableHash[32];
	strncpy(szReadableHash, readableHash.c_str(), sizeof(szReadableHash));

	unsigned __int32 args[2];
	args[1] = *(DWORD*)szReadableHash;
	args[0] = checksum;

	auto finalHash = friends_name_hash((unsigned char*)szReadableHash, sizeof(szReadableHash), *(unsigned __int64*)&args);

	snprintf(friendsName, uMaxLength, "%16llX", finalHash);
}

DWORD dwSendNetMsg;
typedef bool(__thiscall* pSendNetMsg)(INetChannel* pNetChan, INetMessage& msg, bool bVoice);
bool __fastcall hkSendNetMsg(INetChannel* this_, void* edx, INetMessage& msg, bool bVoice)
{
	int cmd = msg.GetType();
	if (cmd != net_Tick && cmd != clc_Move && cmd != svc_UserMessage && cmd != svc_GameEvent && cmd != clc_BaselineAck)
		printfdbg("Outcome msg %d: %s\n", cmd, msg.ToString()); //msg.GetName()

	if (!srcds) {
		if (cmd == net_SignonState)
		{
			byte m_nSignonState = *(DWORD*)((DWORD)&msg + 0x10);

			if (textmode && (m_nSignonState == SIGNONSTATE_FULL))
			{
				CallVFunction<IVEngineClient* (__thiscall*)(void*, char*)>(g_pEngineClient, 97)(g_pEngineClient,
					"jointeam; +voicerecord");
			}

			if (m_nSignonState == g_pCVar->FindVar("cm_fakeconnect")->GetInt() + 1) //2-6
			{
				auto clientport = g_pCVar->FindVar("clientport");
				clientport->SetValue(clientport->GetInt() + 1);
				printfdbg("Set client port to %d\n", clientport->GetInt());
				*(BYTE*)(dwDisconnectMessage - 5) = 0xEB;
				CallVFunction<IVEngineClient* (__thiscall*)(void*, char*)>(g_pEngineClient, 97)(g_pEngineClient,
					"disconnect; net_start; retry");
				*(BYTE*)(dwDisconnectMessage - 5) = 0x74;
				return false;
			}
		}
	}

	if (cmd == svc_UserMessage)
	{
		byte usermsgID = *(DWORD*)((DWORD)&msg + 0x10);
		printfdbg("svc_UserMessage %s (%d)\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)((*(DWORD**)CUserMessages), usermsgID), usermsgID);
	}

	if (cmd == svc_GameEvent)
	{
		byte eventID = *(DWORD*)((DWORD)&msg + 0x44);
		printfdbg("svc_GameEvent: %s (%d).\n", GetEventName(eventID), eventID);
	}

	if (cmd == clc_ClientInfo)
	{
		if (g_pCVar->FindVar("cm_enabled")->GetInt())
		{
			CLC_ClientInfo* Cl = (CLC_ClientInfo*)&msg;
			Cl->m_nFriendsID = friendsID(generator);
			_CM->FriendsID = Cl->m_nFriendsID;

			string addr = string(this_->GetAddress());
			addr = addr.substr(addr.find(":") + 1, addr.size());
			_CM->Port = stoi(addr.c_str());

			GenerateFriendsName(Cl->m_FriendsName, 16);
		}
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
		printfdbg("svc_UserMessage: %s (%d) Rejected\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)(this_, msg_type), msg_type);
		return true;
	}
	else
		if (msg_type == 13) //VGUIMenu
		{
			bf_read backup = msg_data;
			char name[1024];
			msg_data.ReadString(name, sizeof(name));
			printfdbg("svc_UserMessage: %s (%d): %s\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)(this_, msg_type), msg_type, name);
			
			if (!strcmp(name, XorStr("info")))
			{
				msg_data.ReadByte(); msg_data.ReadByte();
				char title[1024]; char content[1024];
				memset(title, 0, sizeof(title)); memset(content, 0, sizeof(content));

				msg_data.ReadString(title, sizeof(title));
				while (title[0])
				{
					msg_data.ReadString(content, sizeof(content));
					printfdbg("%s: %s\n", title, content);
					memset(title, 0, sizeof(title)); memset(content, 0, sizeof(content));
					msg_data.ReadString(title, sizeof(title));
				}
	 
			return true;
			}	
			
			msg_data = backup;
		}
		else
			printfdbg("svc_UserMessage: %s (%d)\n", ((char* (__thiscall*)(void*, int))dwGetUserMessageName)(this_, msg_type), msg_type);


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

DWORD dwSVC_ServerInfo_ReadFromBuffer = 0;
typedef char* (__thiscall* pSVC_ServerInfo_ReadFromBuffer)(int this_, int buf);
bool __fastcall hkSVC_ServerInfo_ReadFromBuffer(int this_, void* unk, int buf)
{
	static pSVC_ServerInfo_ReadFromBuffer SVC_ServerInfo_ReadFromBuffer = (pSVC_ServerInfo_ReadFromBuffer)dwSVC_ServerInfo_ReadFromBuffer;
	auto ret = SVC_ServerInfo_ReadFromBuffer(this_, buf);

	if (*(byte*)g_pCVar->FindVar("cm_forcemap")->GetString() != 0)
	{
		int v11 = this_ + 328;
		strncpy((char*)v11, g_pCVar->FindVar("cm_forcemap")->GetString(), 128);
		//*(DWORD*)(this_ + 28) = 4105947211; //m_nMapCRC
	}
	return ret;
}

DWORD dwSetStringUserData = 0;
typedef char* (__thiscall* pSetStringUserData)(DWORD** this_, const void* userdata, int stringNumber, void* length);
bool __fastcall hkSetStringUserData(DWORD** this_, void* unk, char* userdata, int stringNumber, int* length)
{
	char* TableName = (char*)((int(__thiscall*)(DWORD**))(*this_)[1])(this_);

	if (!stricmp(TableName, "downloadables") || !stricmp(TableName, "modelprecache")) {
		if (*(byte*)g_pCVar->FindVar("cm_forcemap")->GetString() != 0) {
			string usrdata = string(userdata);
			if (usrdata.find("maps/") != string::npos || usrdata.find("maps\\") != string::npos) {
				sprintf(userdata, "maps/%s.bsp", g_pCVar->FindVar("cm_forcemap")->GetString());
			}
		}
	}

	if (length && !stricmp(TableName, "userinfo"))
	{
		_CM->NumPlayers = stoi(userdata);
		if (_CM->NumPlayers == _CM->PlayerSlot)
		{
			_CM->UserID = *(int*)((int)(length)+0x20);
			printf(">> ");
		}
		printfdbg("svc_CreateStringTable %s: %s %s %d %s %x %s\n", TableName, userdata, length, *(int*)((int)(length)+0x20), ((int)(length)+0x24), *(int*)((int)(length)+0x48), ((int)(length)+0x4c));
		_CM->NumPlayers++;
	}
	//else printfdbg("svc_CreateStringTable %s: %d %s\n", TableName, stringNumber, userdata);

	static pSetStringUserData SetStringUserData = (pSetStringUserData)dwSetStringUserData;
	auto ret = SetStringUserData(this_, userdata, stringNumber, length);
	return ret;
}


DWORD dwCvarSetValue = 0;

typedef short(__thiscall* pCvarSetValue)(ConVar* this_, char* String);
short __fastcall hkCvarSetValue(ConVar* this_, void* unk, char* String1)
{
	if (V_stricmp(this_->GetName(), "cm_log") == 0)
	{
		int newlog = -1;
		if (V_stricmp(String1, "0") == 0)
			newlog = 0;
		else if (V_stricmp(String1, "1") == 0)
			newlog = 1;

		if (newlog != -1 && newlog != g_pCVar->FindVar("cm_log")->GetInt())
		{
			//changed
			g_pCVar->FindVar("cm_log")->SetValue(newlog);
			if (newlog == 1)
			{
				//createNewLogFile
				char logname[MAX_PATH];
				auto time = std::time(nullptr);
				std::tm* tm = std::localtime(&time);
				char timebuffer[26];
				std::strftime(timebuffer, sizeof(timebuffer), "%Y-%m-%d_%H-%M-%S", tm);
				sprintf(logname, "SpyLog_%s.txt", timebuffer);
				printfdbg("Log name: %s\n", logname);
				logfile.open(logname, std::ofstream::out | std::ofstream::app);
				if (!logfile) {
					cout << "Failed to open\n";
				}
			}

			if (newlog == 0)
			{
				//saveLogFile ;
				printfdbg("Saved log\n");
				logfile.close();
			}
		}
	}

	static pCvarSetValue CvarSetValue = (pCvarSetValue)dwCvarSetValue;
	auto ret = CvarSetValue(this_, String1);

	return ret;
}


DWORD dwReadSubChannelData = 0;
#define FRAGMENT_BITS		8
#define FRAGMENT_SIZE		(1<<FRAGMENT_BITS)
#define MAX_FILE_SIZE		((1<<MAX_FILE_SIZE_BITS)-1)	// maximum transferable size is	64MB
#define MAX_FILE_SIZE_BITS 26
#define NET_MAX_PALYLOAD_BITS 17
#define MAX_STREAMS 2
typedef char(__thiscall* pReadSubChannelData)(void* this_, bf_read& buf, int stream);
char __fastcall hkReadSubChannelData(void* this_, void* edx, bf_read& buf, int stream)
{
	auto buf_copy = buf;
	bool bSingleBlock = buf.ReadOneBit() == 0; // is single block ? 
	unsigned int startFragment = 0;
	unsigned int numFragments = 0;
	unsigned int offset = 0;
	unsigned int length = 0;
	unsigned int nUncompressedSize = 0;
	unsigned int max_payload_bits = 0;
	unsigned int isFile = 0;
	unsigned int transferID = 0;
	char filename[MAX_OSPATH] = "";
	bool compressed = 0;
	unsigned int bytes = 0;

	if (!bSingleBlock)
	{
		startFragment = buf.ReadUBitLong(MAX_FILE_SIZE_BITS - FRAGMENT_BITS); // 16 MB max
		numFragments = buf.ReadUBitLong(3);  // 8 fragments per packet max
		offset = startFragment * FRAGMENT_SIZE;
		length = numFragments * FRAGMENT_SIZE;
	}

	if (offset == 0) // first fragment, read header info
	{
		auto max_payload_bits = buf.ReadUBitLong(NET_MAX_PALYLOAD_BITS);
		if (bSingleBlock)
		{
			// data compressed ?
			compressed = buf.ReadOneBit();
			if (compressed)
			{
				nUncompressedSize = buf.ReadUBitLong(MAX_FILE_SIZE_BITS);
			}
			max_payload_bits = buf.ReadUBitLong(NET_MAX_PALYLOAD_BITS);
		}
		else
		{
			isFile = buf.ReadOneBit();
			if (isFile) // is it a file ?
			{
				transferID = buf.ReadUBitLong(32);
				buf.ReadString(filename, MAX_OSPATH);
			}
			// data compressed ?
			compressed = buf.ReadOneBit();
			if (compressed)
			{
				nUncompressedSize = buf.ReadUBitLong(MAX_FILE_SIZE_BITS);
			}
			bytes = buf.ReadUBitLong(MAX_FILE_SIZE_BITS);
		}
		char* buffer = new char[length];
		buf.ReadBytes(buffer, length); // read data
		delete buffer;
	}

	printfdbg("ReadSubChannelData stream %d bSingleBlock %d offset %d length %d compressed %d isFile %d nUncompressedSize %d\n",
		stream, bSingleBlock, offset, length, compressed, isFile, nUncompressedSize);

	if (nUncompressedSize) return false;

	buf = buf_copy;
	static pReadSubChannelData ReadSubChannelData = (pReadSubChannelData)dwReadSubChannelData;
	auto ret = ReadSubChannelData(this_, buf, stream);
	return ret;
}


void ConsoleInputThread(HMODULE hModule)
{
	char input[255];
	while (true) {
		cin.getline(input, sizeof(input));
		CallVFunction<IVEngineClient* (__thiscall*)(void*, char*)>(g_pEngineClient, 97)(g_pEngineClient, //g_pEngineClient->ExecuteClientCmd
			input);
	}
}

DWORD WINAPI HackThread(HMODULE hModule)
{
#ifdef DEBUG
	AllocConsole(); FILE* f; freopen_s(&f, "CONOUT$", "w", stdout); //freopen_s(&f, "CONIN$", "r", stdin);
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
	printfdbg("Compile time %s\n", __TIMESTAMP__);
	//auto curtime = time(0);
	//auto gmtm = gmtime(&curtime);
	//printfdbg("Current time: %s\n", asctime(gmtm)); 
	printfdbg("Project is free: https://github.com/0TheSpy/ClientMod3Emulator\n"); 

	SigScan scan;

	g_GameEventManager = (CGameEventManager*)GetInterface("engine.dll", "GAMEEVENTSMANAGER002");

	g_pEngineClient = (IVEngineClient*)GetInterface("engine.dll", "VEngineClient012");

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
		g_pGameConsole->ColorPrintf(clr2, __TIMESTAMP__);
		//g_pGameConsole->ColorPrintf(clr1, "\nCurrent time: ");
		//g_pGameConsole->ColorPrintf(clr2, asctime(gmtm));
		g_pGameConsole->ColorPrintf(clr1, "\nProject is free: ");
		g_pGameConsole->ColorPrintf(clr2, "https://github.com/0TheSpy/ClientMod3Emulator\n");

		g_pCVar = ((ICvar * (*)(void))GetProcAddress(GetModuleHandleA("vstdlib.dll"), "GetCVarIF"))();
		printfdbg("g_pCVar %x\n", g_pCVar);

		CallVFunction<IVEngineClient* (__thiscall*)(void*, char*)>(g_pEngineClient, 97)(g_pEngineClient, //g_pEngineClient->ExecuteClientCmd
			"setinfo cm_steamid 1337; setinfo cm_steamid_random 1; setinfo cm_steamid_enabled 1; setinfo cm_enabled 1; setinfo cm_version \"3.0.0.9135\"; setinfo cm_drawspray 1; setinfo cm_forcemap \"\"; setinfo cm_fakeconnect 0; setinfo cm_log 0");

		//FCVAR_PROTECTED 
		g_pCVar->FindVar("cm_steamid")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_steamid_random")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_steamid_enabled")->m_nFlags = 537001984; 
		g_pCVar->FindVar("cm_version")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_enabled")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_drawspray")->m_nFlags = 537001984;
		g_pCVar->FindVar("sv_cheats")->m_nFlags = 0;
		g_pCVar->FindVar("cl_downloadfilter")->m_pszHelpString = "Determines which files can be downloaded from the server(all, none, nosounds, mapsonly)";
		g_pCVar->FindVar("cm_forcemap")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_fakeconnect")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_log")->m_nFlags = 537001984;
		g_pCVar->FindVar("cm_fakeconnect")->m_pszHelpString = "Drop connection at signon state: (1 = CONNECTED, 2 = NEW, 3 = PRESPAWN, 4 = SPAWN, 5 = FULL).";

		dwCvarSetValue = scan.FindPattern(XorStr("engine.dll"), XorStr("\x83\xec\xae\xa1\xae\xae\xae\xae\x33\xc4\x56\x89\x44\x24"), XorStr("xx?x????xxxxxx"));

		dwPrepareSteamConnectResponse = scan.FindPattern(XorStr("engine.dll"), XorStr("\x81\xEC\x00\x00\x00\x00\x56\x8B\xF1\x8B\x0D\x00\x00\x00\x00\x8B\x01\xFF\x50\x24"), XorStr("xx????xxxxx????xxxxx")); //engine.dll+5D50
		dwBuildConVarUpdateMessage = scan.FindPattern(XorStr("engine.dll"), XorStr("\xE8\x00\x00\x00\x00\x8D\x54\x24\x3C"), XorStr("x????xxxx"));
		dwBuildConVarUpdateMessage += 0x9719;

		NetChannel_SendNetMsg = scan.FindPattern(XorStr("engine.dll"), XorStr("\x56\x8b\xf1\x8d\x4e\xae\xe8\xae\xae\xae\xae\x85\xc0\x75"), XorStr("xxxxx?x????xxx"));
		printfdbg("NetChannel_SendNetMsg %x\n", NetChannel_SendNetMsg);

		///*
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
		//*/

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

		//MapPatch 
		DWORD oldProtect;
		DWORD BadInlineModel = scan.FindPattern(XorStr("engine.dll"), XorStr("\x7c\xae\x83\x7e\xae\xae\x75\xae\x33\xc0"), XorStr("x?xx??x?xx"));
		if (BadInlineModel) {
			VirtualProtect((PVOID)(BadInlineModel), 0x100, PAGE_EXECUTE_READWRITE, &oldProtect);
			*(WORD*)BadInlineModel = 0x9090; *(BYTE*)(BadInlineModel + 0x11) = 0xEB;
		}
		DWORD MapVersionExpecting = scan.FindPattern(XorStr("engine.dll"), XorStr("\x7c\xae\x83\xf8\xae\x7e\xae\x6a"), XorStr("x?xx?x?x"));
		if (MapVersionExpecting) {
			VirtualProtect((PVOID)(MapVersionExpecting), 0x100, PAGE_EXECUTE_READWRITE, &oldProtect);
			*(WORD*)MapVersionExpecting = 0x9090; *(BYTE*)(MapVersionExpecting + 0x5) = 0xEB;
		}
		DWORD MapCheckCRC = scan.FindPattern(XorStr("engine.dll"), XorStr("\x74\xae\x8b\x0d\xae\xae\xae\xae\x8b\x11\xff\x52\xae\x84\xc0\x75\xae\x56"), XorStr("x?xx????xxxx?xxx?x"));
		if (MapCheckCRC) {
			VirtualProtect((PVOID)(MapCheckCRC), 0x100, PAGE_EXECUTE_READWRITE, &oldProtect);
			*(BYTE*)(MapCheckCRC) = 0xEB;
		}
	}

	char* cmdline = GetCommandLineA();
	if (_tcsstr(cmdline, _T("-textmode")) != NULL) {
		textmode = true;
		CallVFunction<IVEngineClient* (__thiscall*)(void*, char*)>(g_pEngineClient, 97)(g_pEngineClient, //g_pEngineClient->ExecuteClientCmd
			"voice_inputfromfile 1");

		freopen_s(&f, "CONIN$", "r", stdin);
		printfdbg("hl2 launched with -textmode\n");
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)ConsoleInputThread, hModule, 0, nullptr);
	}

	dwProcessMessages = scan.FindPattern(XorStr("engine.dll"), XorStr("\x83\xEC\x2C\x53\x55\x89\x4C\x24\x10"), XorStr("xxxxxxxxx"));
	printfdbg("dwPrepareSteamConnectResponse %x\n", dwPrepareSteamConnectResponse);

	dwReadSubChannelData = scan.FindPattern(XorStr("engine.dll"), XorStr("\x83\xec\xae\x8b\x44\x24\xae\x53\x8d\x14\x80"), XorStr("xx?xxx?xxxx"));
	printfdbg("dwReadSubChannelData %x\n", dwReadSubChannelData);

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

	CUserMessages = reinterpret_cast<LPVOID>(*(PVOID*)(scan.FindPattern(XorStr(client_dll), XorStr("\x8b\x0d\xae\xae\xae\xae\x6a\xae\x68\xae\xae\xae\xae\xe8"), XorStr("xx????x?x????x")) + 2));
	printfdbg("CUserMessages_ %x\n", CUserMessages);
	dwDispatchUserMessage = scan.FindPattern(XorStr(client_dll), XorStr("\x8b\x44\x24\xae\x83\xec\xae\x85\xc0\x0f\x8c"), XorStr("xxx?xx?xxxx"));
	printfdbg("dwDispatchUserMessage %x\n", dwDispatchUserMessage);

	dwGetUserMessageName = scan.FindPattern(XorStr(client_dll),
		XorStr("\x56\x8b\x74\x24\xae\x85\xf6\x57\x8b\xf9\x7c\xae\x3b\x77\xae\x7c\xae\x56\x68\xae\xae\xae\xae\xff\x15\xae\xae\xae\xae\x83\xc4\xae\x8b\x4f\xae\x8d\x04\x76\x8b\x44\xc1"),
		XorStr("xxxx?xxxxxx?xx?x?xx????xx????xx?xx?xxxxxx"));
	printfdbg("dwGetUserMessageName %x\n", dwGetUserMessageName);

	dwSendNetMsg = scan.FindPattern(XorStr("engine.dll"), XorStr("\xcc\x56\x8b\xf1\x8d\x4e\x74"), XorStr("xxxxxxx")) + 1; //dwEngine + 0xff950;
	printfdbg("dwSendNetMsg %x\n", dwSendNetMsg);

	dwSVC_ServerInfo_ReadFromBuffer = scan.FindPattern(XorStr("engine.dll"), XorStr("\x83\xec\xae\x53\x55\x56\x8b\x74\x24\xae\x57\x8b\xf9\x8d\x87"),
		XorStr("xx?xxxxxx?xxxxx"));
	printfdbg("dwSVC_ServerInfo_ReadFromBuffer %x\n", dwSVC_ServerInfo_ReadFromBuffer);

	dwSetStringUserData = scan.FindPattern(XorStr("engine.dll"), XorStr("\x56\x57\x8b\x7c\x24\xae\x85\xff\x8b\xf1\x75\xae\x8b\x06"), XorStr("xxxxx?xxxxx?xx"));
	printfdbg("dwSetStringUserData %x\n", dwSetStringUserData);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (!srcds) {
		DetourAttach(&(LPVOID&)dwPrepareSteamConnectResponse, &Hooked_PrepareSteamConnectResponse);
		DetourAttach(&(LPVOID&)dwBuildConVarUpdateMessage, &Hooked_BuildConVarUpdateMessage);
		DetourAttach(&(LPVOID&)(dwWriteListenEventList), (PBYTE)hkWriteListenEventList);
		DetourAttach(&(LPVOID&)(dwDispatchUserMessage), (PBYTE)hkDispatchUserMessage);
		DetourAttach(&(LPVOID&)(dwDownloadManager_Queue), (PBYTE)hkDownloadManager_Queue);
		DetourAttach(&(LPVOID&)(dwFindClientClass), (PBYTE)hkFindClientClass);
		DetourAttach(&(LPVOID&)(dwSVC_ServerInfo_ReadFromBuffer), (PBYTE)hkSVC_ServerInfo_ReadFromBuffer);
		DetourAttach(&(LPVOID&)(dwSetStringUserData), (PBYTE)hkSetStringUserData);

		DetourAttach(&(LPVOID&)(dwCvarSetValue), (PBYTE)hkCvarSetValue);
	}

	DetourAttach(&(LPVOID&)dwProcessMessages, &Hooked_ProcessMessages);
	DetourAttach(&(LPVOID&)(dwSendNetMsg), (PBYTE)hkSendNetMsg);
	//DetourAttach(&(LPVOID&)(dwReadSubChannelData), (PBYTE)hkReadSubChannelData);

	DetourTransactionCommit();

	//ConCommandBaseMgr::OneTimeInit(&g_ConVarAccessor);  

#ifdef DISCMSG
	DWORD oldDscmsg;
	if (!srcds) {
		dwDisconnectMessage = scan.FindPattern(XorStr("engine.dll"), XorStr("\x74\x14\x8b\x01\x68\x0\x0\x0\x0\xff\x90"), XorStr("xxxxx????xx")); //dwEngine + 0x61cc; 
		printfdbg("dwDisconnectMessage %x\n", dwDisconnectMessage);
		if (dwDisconnectMessage) {
			char* dscmsg = "Disconnect by ClientMod\0";

			DWORD oldProtect;
			VirtualProtect((PVOID)(dwDisconnectMessage), 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
			dwDisconnectMessage += 5;
			memcpy(&oldDscmsg, (PVOID)(dwDisconnectMessage), 4);
			memcpy((PVOID)(dwDisconnectMessage), &dscmsg, 4); // CBaseClientState::Disconnect
		}
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
		if (dwDisconnectMessage)
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
		DetourDetach(&(LPVOID&)(dwSVC_ServerInfo_ReadFromBuffer), reinterpret_cast<BYTE*>(hkSVC_ServerInfo_ReadFromBuffer));
		DetourDetach(&(LPVOID&)(dwSetStringUserData), reinterpret_cast<BYTE*>(hkSetStringUserData));

		DetourDetach(&(LPVOID&)(dwCvarSetValue), reinterpret_cast<BYTE*>(hkCvarSetValue));
	}
	DetourDetach(&(LPVOID&)dwProcessMessages, reinterpret_cast<BYTE*>(Hooked_ProcessMessages));
	DetourDetach(&(LPVOID&)(dwSendNetMsg), reinterpret_cast<BYTE*>(hkSendNetMsg));
	//DetourDetach(&(LPVOID&)(dwReadSubChannelData), reinterpret_cast<BYTE*>(hkReadSubChannelData)); 

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


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		hMod = hModule;
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

