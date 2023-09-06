// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS
#define DEBUG
//#define HWID
//#define TIMEDACCESS
 
#ifdef HWID
#define HWIDSTRING if (strcmp(XorStr("{be5a05e9-f9bd-11ea-9a43-806e6f6e6963}"), hwProfileInfo.szHwProfileGuid)) 
#endif 

#include <Windows.h>
#include <iostream> 

#include <dbg.h>
#include <inetmessage.h>
#include <inetchannelinfo.h>
#include <inetmsghandler.h>
#include <utlvector.h>
#include <inetchannel.h>
#include <cdll_int.h>
#include <memory>
#include <string>
#include <type_traits>
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
 
#pragma comment(lib, "mysqlcppconn.lib")
#pragma comment(lib, "public/tier0.lib")
#pragma comment(lib, "public/tier1.lib")
#pragma comment(lib, "public/vstdlib.lib")
#pragma comment(lib, "public/mathlib.lib")

using namespace std;
 
#ifdef DEBUG
#define printfdbg printf
#else
#define printfdbg(...)
#endif
 
ICvar* g_pCVar = nullptr; 

#include "Emulators/Setti.h"
#include "Public/StrUtils.h"
#include "Public/RevSpoofer.h"
#include "Public/Encryption/CRijndael.h"
#include "Public/Encryption/SHA.h"
#include "Emulators/RevEmu2013.h"
#include <time.h>

#ifdef TIMEDACCESS
#include "TimedAccess.h"
#endif
 
DWORD dwPrepareSteamConnectResponse;
typedef bool(__thiscall* PrepareSteamConnectResponseFn)(void*, int, const char*, uint64, bool, const netadr_t&, bf_write&);
bool __fastcall Hooked_PrepareSteamConnectResponse(DWORD* ecx, void* edx, int keySize, const char* encryptionKey, uint64 unGSSteamID, bool bGSSecure, const netadr_t& adr, bf_write& msg)
{
	printfdbg("Hooked_PrepareSteamConnectResponse called\n");

	static PrepareSteamConnectResponseFn PrepareSteamConnectResponse = (PrepareSteamConnectResponseFn)dwPrepareSteamConnectResponse;

	srand(time(NULL));
	int steamid = 0;
	if (g_pCVar->FindVar("cm_steamid_random")->GetInt())
		steamid = std::rand() * std::rand();
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

	strncpy(acvar.name, XorStr("clantag"), MAX_OSPATH);
	strncpy(acvar.value, XorStr("spy"), MAX_OSPATH);
	cvarMsg->m_ConVars.AddToTail(acvar);
	
	//strncpy(acvar.name, XorStr("name"), MAX_OSPATH);
	//strncpy(acvar.value, XorStr("koronavirus"), MAX_OSPATH);
	//cvarMsg->m_ConVars.AddToTail(acvar);
	 
	strncpy(acvar.name, XorStr("_client_version"), MAX_OSPATH);
	 
	strncpy(acvar.value, g_pCVar->FindVar("cm_version")->GetString(), MAX_OSPATH);
	//strncpy(acvar.value, XorStr("3.0.0.9035"), MAX_OSPATH); 
	cvarMsg->m_ConVars.AddToTail(acvar); 

	strncpy(acvar.name, XorStr("~clientmod"), MAX_OSPATH);
	strncpy(acvar.value, XorStr("2.0"), MAX_OSPATH); 

	cvarMsg->m_ConVars.AddToTail(acvar);
	 
	cvarMsg->m_ConVars.RemoveMultipleFromHead(2);
	    
	//auto s = cvarMsg->m_ConVars.begin();
	for (int i = 0; i < cvarMsg->m_ConVars.Size(); i++) {
		printfdbg("%d %s : %s\n", i, cvarMsg->m_ConVars[i].name, cvarMsg->m_ConVars[i].value);
	}
	
} 

DWORD dwProcessMessages;

#define MAX_EVENT_BITS			9		// max bits needed for an event index
#define NETMSG_TYPE_BITS	5
#define	net_NOP 		0			// nop command used for padding
#define net_Disconnect	1			// disconnect, last message in connection
#define net_File		2			// file transmission message request/deny

#define svc_GameEventList	30	// list of known games events and fields

#define	svc_GameEvent		25	// global game event fired
#define	net_Tick		3	 
#define	svc_PacketEntities		26	
#define	svc_UserMessage		23	
#define svc_GetCvarValue 31

#define clc_RespondCvarValue 25 

#define DECLARE_SVC_MESSAGE( name )		\
	DECLARE_BASE_MESSAGE( svc_##name );	\
	IServerMessageHandler *m_pMessageHandler;\
	bool Process() { return m_pMessageHandler->Process##name( this ); }\

class SVC_GameEvent : public CNetMessage
{
	DECLARE_SVC_MESSAGE(GameEvent);

	int	GetGroup() const { return INetChannelInfo::EVENTS; }

public:
	int			m_nLength;	// data length in bits
	bf_read		m_DataIn;
	bf_write	m_DataOut;
}; 

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


#include <igameevents.h>

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


 
 
/*
bool SVC_GameEventList::WriteToBuffer(bf_write& buffer)
{
	Assert(m_nNumEvents > 0);

	m_nLength = m_DataOut.GetNumBitsWritten();

	buffer.WriteUBitLong(GetType(), NETMSG_TYPE_BITS);
	buffer.WriteUBitLong(m_nNumEvents, MAX_EVENT_BITS);
	buffer.WriteUBitLong(m_nLength, 20);
	return buffer.WriteBits(m_DataOut.GetData(), m_nLength);
}

bool SVC_GameEventList::ReadFromBuffer(bf_read& buffer)
{
	m_nNumEvents = buffer.ReadUBitLong(MAX_EVENT_BITS);
	m_nLength = buffer.ReadUBitLong(20);
	m_DataIn = buffer;
	return buffer.SeekRelative(m_nLength); 
}
*/
  

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


#include <KeyValues.h>

bool ProcessControlMessage(INetChannel* chan, int cmd, bf_read& buf)
{    
	char string[1024];

	if (cmd == net_NOP)
	{
		return true;
	}

	printfdbg("ProcControlMessage %d\n", cmd);
	 
	INetChannelHandler* m_MessageHandler = chan->GetMsgHandler();
	  
	if (cmd == net_Disconnect)
	{ 
		buf.ReadString(string, sizeof(string)); 
		printfdbg("Connection closing: %s\n", string); 
		MessageBoxA(NULL, string, XorStr("ConnectionClosing"), 0);
		return false;
	}

	if (cmd == net_File) 
	{  
		unsigned int transferID = buf.ReadUBitLong(32); 
		buf.ReadString(string, sizeof(string)); 
		if (buf.ReadOneBit() != 0 && IsSafeFileToDownload(string))
		{
			m_MessageHandler->FileRequested(string, transferID);
		}
		else
		{
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
	void* eventManager;
	void* EDI;
	int count;
	CGameEventDescriptor* descriptors;
	__asm
	{
		mov     edx, 0x203C2684
		mov     eax, [edx]
		mov eventManager, eax
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

class SVC_GetCvarValue : public CNetMessage
{
public:
	DECLARE_SVC_MESSAGE(GetCvarValue);

	QueryCvarCookie_t	m_iCookie;
	const char* m_szCvarName;	// The sender sets this, and it automatically points it at m_szCvarNameBuffer when receiving.

private:
	char		m_szCvarNameBuffer[256];
};
 
const char* CLC_RespondCvarValue::ToString(void) const {	return 0;}
bool CLC_RespondCvarValue::ReadFromBuffer(bf_read& buffer) {	return 0;}
bool CLC_RespondCvarValue::WriteToBuffer(bf_write& buffer){	return 0;} 
 
DWORD eip_;
__declspec(naked) void getEIP()
{
	__asm
	{
		pushad
		mov eax,[esp+0x20]  
		mov [eip_], eax
	}
	 
	printfdbg("EIP %x\n", eip_);

	__asm
	{ 
		popad
		ret 
	}
}

DWORD NC;

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
				  
				printfdbg("Event %s (%d) length %x buf %x\n", name, eventid, length, &buf); 

				if (name && !strcmp(name, "player_disconnect"))  
				{ 
					char databuf[1024];
					 
					int userid = buf.ReadShort();
					buf.ReadString(databuf, sizeof(databuf));
					buf.ReadString(databuf, sizeof(databuf));
					buf.ReadString(databuf, sizeof(databuf));
					
					if (userid < 1)
					{
						continue;
					} 
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

			if (!netmsg->ReadFromBuffer(buf))
			{
				printfdbg("Netchannel: failed reading message %s from %s.\n", netmsg->GetName(), pThis->GetAddress());
				return false;
			} 
			 
			if (cmd == svc_GetCvarValue)
			{
				SVC_GetCvarValue* msgmsg = (SVC_GetCvarValue*)netmsg;
				//printfdbg("svc_GetCvarValue (%x) %d %s\n", netmsg, msgmsg->m_iCookie, msgmsg->m_szCvarName); 
				 
				if (!strcmp((char*)((DWORD)netmsg + 24) , "cm_steamid") ||
					!strcmp((char*)((DWORD)netmsg + 24), "cm_steamid_random") ||
					!strcmp((char*)((DWORD)netmsg + 24), "cm_version") )
				{  
					CLC_RespondCvarValue returnMsg; 
					  
					memcpy(&returnMsg, &NC, 4);
					returnMsg.m_iCookie = msgmsg->m_iCookie; //+16 
					returnMsg.m_szCvarName = msgmsg->m_szCvarName; 
					char* value_to_pass = "";
					returnMsg.m_szCvarValue = value_to_pass;
					returnMsg.m_eStatusCode = eQueryCvarValueStatus_CvarNotFound;
					 
					//__asm call getEIP  
					pThis->SendNetMsg(returnMsg); 
					  
					return false; 
				}  
				 
				if (!strcmp(msgmsg->m_szCvarName, "se_lkblox") ||
					!strcmp(msgmsg->m_szCvarName, "se_autobunnyhopping") ||
					!strcmp(msgmsg->m_szCvarName, "se_disablebunnyhopping") ||
					!strcmp(msgmsg->m_szCvarName, "e_viewmodel_right") ||
					!strcmp(msgmsg->m_szCvarName, "e_viewmodel_fov") ||
					!strcmp(msgmsg->m_szCvarName, "e_viewmodel_up") )
				{
					CLC_RespondCvarValue returnMsg;

					memcpy(&returnMsg, &NC, 4);
					returnMsg.m_iCookie = msgmsg->m_iCookie; 
					returnMsg.m_szCvarName = msgmsg->m_szCvarName;
					char* value_to_pass = "0";
					returnMsg.m_szCvarValue = value_to_pass;
					returnMsg.m_eStatusCode = eQueryCvarValueStatus_ValueIntact;
					 
					pThis->SendNetMsg(returnMsg);

					return false;
				}  
			}

			if (cmd != net_Tick && cmd != svc_PacketEntities && cmd != svc_UserMessage)
				printfdbg("Msg %d from %s: %s\n", cmd, pThis->GetAddress(), netmsg->ToString());
			 

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
   
DWORD WINAPI HackThread(HMODULE hModule)
{ 
#ifdef DEBUG
    AllocConsole(); FILE* f; freopen_s(&f, "CONOUT$", "w", stdout);
#endif

#ifdef HWID
	HW_PROFILE_INFO hwProfileInfo;
	if (GetCurrentHwProfile(&hwProfileInfo))
	{ 
		printfdbg("HWID: %s\n", hwProfileInfo.szHwProfileGuid);  
		HWIDSTRING
		{ 
			printfdbg("Error: Bad hwid\n"); 
			MessageBoxA(NULL, XorStr("Bad HWID"), XorStr("Error"), 0);
			exit(0);
			_Exit(0);
			memcpy(0, &hwProfileInfo, 0x100);
		}
	}
#endif 

#ifdef TIMEDACCESS
	printfdbg("compile time %d\n", compiletime);
	curtime = gTime();
	printfdbg("current time %d\n", curtime);
	timer = compiletime + duration - curtime;
	mStartedTime = chrono::system_clock::now();
#endif

	printfdbg(XorStr("ClientMod 3.0 Emulator\nOriginal code: InFro, updated by Spy\nCredits to cssandroid & atryrkakiv\n"));
	 
	IGameConsole* g_pGameConsole = (IGameConsole*)GetInterface(XorStr("gameui.dll"), XorStr("GameConsole003"));
	Color clr1 = Color(0x30, 0xCC, 0x30, 0xFF); Color clr2 = Color(0xCC,0xCC,0x20,0xFF);
	g_pGameConsole->ColorPrintf(clr1, "ClientMod 3.0 Emulator\nOriginal code: ");
	g_pGameConsole->ColorPrintf(clr2, "InFro");
	g_pGameConsole->ColorPrintf(clr1, ", updated by ");
	g_pGameConsole->ColorPrintf(clr2, "Spy\n");
	g_pGameConsole->ColorPrintf(clr1, "Credits to ");
	g_pGameConsole->ColorPrintf(clr2, "cssandroid ");
	g_pGameConsole->ColorPrintf(clr1, "and ");
	g_pGameConsole->ColorPrintf(clr2, "atryrkakiv\n");
	 
	g_pCVar = GetCVarIF();
	printfdbg("g_pCVar %x\n", g_pCVar);
	IVEngineClient* g_pEngineClient = (IVEngineClient*)GetInterface("engine.dll", "VEngineClient012");
	g_pEngineClient->ExecuteClientCmd("setinfo cm_steamid 1337; setinfo cm_steamid_random 1; setinfo cm_version \"3.0.0.9035\""); 
	ConVar* var1 = g_pCVar->FindVar("cm_steamid"); ConVar* var2 = g_pCVar->FindVar("cm_steamid_random"); ConVar* var3 = g_pCVar->FindVar("cm_version");
	var1->m_nFlags = 537001984; var2->m_nFlags = 537001984; var3->m_nFlags = 537001984;    //FCVAR_PROTECTED
	   
	//g_pEngineClient->ExecuteClientCmd("setinfo se_lkblox 0; setinfo se_autobunnyhopping 0; setinfo se_disablebunnyhopping 0; setinfo e_viewmodel_right 0; setinfo e_viewmodel_fov 0; setinfo e_viewmodel_up 0;");
	  
    SigScan scan; 
    dwPrepareSteamConnectResponse = scan.FindPattern(XorStr("engine.dll"), XorStr("\x81\xEC\x00\x00\x00\x00\x56\x8B\xF1\x8B\x0D\x00\x00\x00\x00\x8B\x01\xFF\x50\x24"), XorStr("xx????xxxxx????xxxxx")); //engine.dll+5D50
	dwBuildConVarUpdateMessage = scan.FindPattern(XorStr("engine.dll"), XorStr("\xE8\x00\x00\x00\x00\x8D\x54\x24\x3C"), XorStr("x????xxxx"));
	dwBuildConVarUpdateMessage += 0x9719;
	dwProcessMessages = scan.FindPattern(XorStr("engine.dll"), XorStr("\x83\xEC\x2C\x53\x55\x89\x4C\x24\x10"), XorStr("xxxxxxxxx"));

	printfdbg("dwPrepareSteamConnectResponse %x\n", dwPrepareSteamConnectResponse);
	printfdbg("dwBuildConVarUpdateMessage %x\n", dwBuildConVarUpdateMessage);
	printfdbg("dwProcessMessages %x\n", dwProcessMessages);

	NC = scan.FindPattern(XorStr("engine.dll"), XorStr("\x00\xc7\x44\x24\x08\x0\x0\x0\x0\xc7\x84\x24"), XorStr("xxxxx????xxx")) + 5;
	NC = (DWORD) * (PVOID*)NC;
	printfdbg("NC %x\n", NC); 
	
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(LPVOID&)dwPrepareSteamConnectResponse, &Hooked_PrepareSteamConnectResponse);
    DetourAttach(&(LPVOID&)dwProcessMessages, &Hooked_ProcessMessages);
    DetourAttach(&(LPVOID&)dwBuildConVarUpdateMessage, &Hooked_BuildConVarUpdateMessage);
    DetourTransactionCommit();
   
	//ConCommandBaseMgr::OneTimeInit(&g_ConVarAccessor); 

	DWORD dwEngine = (DWORD)GetModuleHandleA("engine.dll");
	 
	char* dscmsg = "Disconnect by ClientMod\0";
	 
	DWORD oldProtect; DWORD oldDscmsg;
	VirtualProtect((PVOID)(dwEngine + 0x61cc ), 4, PAGE_EXECUTE_READWRITE, &oldProtect); 
	memcpy(&oldDscmsg, (PVOID)(dwEngine + 0x61cc), 4);
	memcpy((PVOID)(dwEngine + 0x61cc), &dscmsg, 4); // CBaseClientState::Disconnect
	  
	  
	while (true)
	{ 
		if (GetAsyncKeyState(VK_DELETE))  break;

#ifdef TIMEDACCESS
		if (!CheckTime())
		{
			printfdbg(XorStr("Error: Time expired\n")); 
			MessageBox(0, XorStr("Time expired!"), XorStr("Error"), MB_OK); 
			break;
		}
#endif

		Sleep(100);
	}

	printfdbg("Unhooking...\n");
	 
	memcpy((PVOID)(dwEngine + 0x61cc), &oldDscmsg, 4);

	DetourTransactionBegin(); 
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(LPVOID&)dwPrepareSteamConnectResponse, reinterpret_cast<BYTE*>(Hooked_PrepareSteamConnectResponse));
	DetourDetach(&(LPVOID&)dwProcessMessages, reinterpret_cast<BYTE*>(Hooked_ProcessMessages));
	DetourDetach(&(LPVOID&)dwBuildConVarUpdateMessage, reinterpret_cast<BYTE*>(Hooked_BuildConVarUpdateMessage));
	DetourTransactionCommit(); 
	 

#ifdef DEBUG
	if (f) fclose(f);
	FreeConsole();
#endif
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

