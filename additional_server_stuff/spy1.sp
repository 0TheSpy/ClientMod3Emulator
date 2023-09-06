#pragma semicolon 1

#define DEBUG

#define PLUGIN_AUTHOR ""
#define PLUGIN_VERSION "0.00"

#include <sourcemod>
#include <sdktools>
#include <cstrike> 
 
////////
#include <clients>
#include <keyvalues>
#include <sdkhooks>

#pragma newdecls required
   
public Plugin myinfo = 
{
	name = "",
	author = "SPY",
	description = "",
	version = "0.0",
	url = ""
};

public void OnPluginStart()
{
	RegConsoleCmd("sm_cvarlist", Cmd_CheckCVarList, "Check list of cvar values for a player.");	
}


public bool OnClientConnect(int client, char[] rejectmsg, int maxlen)
{
	char name[64];
	GetClientName(client, name, 64);
	PrintToServer("%d %s connected", client, name);
	return true;
}

public Action OnClientCommand(int client, int args)
{
  char cmd[64];
  char arg[128];
  
  GetCmdArg(0, cmd, sizeof cmd);
  
  if ( args )
  {
  	GetCmdArgString(arg, sizeof arg);
  	
  	Format(cmd, sizeof cmd, "%s %s", cmd, arg);
  }
  
  char name[64];
  GetClientName(client, name, 64);
  
  PrintToChatAll("%d %s: %s", client, name, cmd);
  PrintToServer("%d %s: %s", client, name, cmd);

  return Plugin_Continue;
}

public int CVarQueryCB(QueryCookie hCookie, int target, ConVarQueryResult result, const char[] sCVar, const char[] sCVarValue, int iUserID)
{
	int client = GetClientOfUserId(iUserID);
	char sMsg_[128];
	
	char sMsg[128];
	
	if(hCookie == QUERYCOOKIE_FAILED)
	{
		Format(sMsg, sizeof(sMsg), "Query cookie failed!");
	}
	else if(result == ConVarQuery_NotFound)
	{
		Format(sMsg, sizeof(sMsg), "CVar not found!");
	}
	else if(result == ConVarQuery_NotValid)
	{
		Format(sMsg, sizeof(sMsg), "Argument is not a CVar. Console command found with same name.");
	}
	else if(result == ConVarQuery_Protected)
	{
		Format(sMsg, sizeof(sMsg), "CVar is protected! Value cannot be retrieved.");
	}
	else
	{
		Format(sMsg, sizeof(sMsg), "OK");
	}
	
	Format(sMsg_, sizeof(sMsg_), "%N's CVar value: %s = %s (%s)", target, sCVar, sCVarValue, sMsg);
	
	PrintToServer("[sm_cvarlist]: %s",sMsg_);

	if(IsValidClient(client))
	{
		PrintToConsole(client, sMsg_);
	}
	else
	{
		LogToGame(sMsg_);
	}
}
 
public Action Cmd_CheckCVarList(int client, int iArgs)
{
	if(iArgs != 2)
	{
		ReplyToCommand(client, "Command Usage: sm_cvarlist <target> <cvar>");
		return Plugin_Handled;
	}
	  
	char sTarget[65], sTargetName[MAX_TARGET_LENGTH], sCVar[65];
	GetCmdArg(1, sTarget, sizeof(sTarget));
	GetCmdArg(2, sCVar, sizeof(sCVar));
	
	PrintToServer("sm_cvarlist %s %s", sTarget, sCVar);
	
	int a_iTargets[MAXPLAYERS], iTargetCount;
	bool bTN_ML;
	if((iTargetCount = ProcessTargetString(sTarget, client, a_iTargets, MAXPLAYERS, COMMAND_FILTER_NO_IMMUNITY|COMMAND_FILTER_NO_BOTS, sTargetName, sizeof(sTargetName), bTN_ML)) <= 0)
	{
		ReplyToCommand(client, "Not found or invalid parameter.");
		return Plugin_Handled;
	}
	
	if(IsValidClient(client))
	{
		PrintToServer("~OK: %d", a_iTargets[0]);
	}
	
	for(int i = 0; i < iTargetCount; i++)
	{
		int target = a_iTargets[i]; 
		
		if(IsValidClient(target))
		{
			QueryClientConVar(target, sCVar, view_as<ConVarQueryFinished>(CVarQueryCB), GetClientUserId(client));
		}
	}
	return Plugin_Handled;
}

bool IsValidClient(int client, bool bAllowBots = false, bool bAllowDead = true)
{
	if(!(1 <= client <= MaxClients) || !IsClientInGame(client) || (IsFakeClient(client) && !bAllowBots) || (!IsPlayerAlive(client) && !bAllowDead))
	{
		return false;
	}
	return true;
}

 