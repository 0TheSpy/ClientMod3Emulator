/**
* Copyright (C) 2017, 2010kohtep
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "..\Public\StrUtils.h"
#include <Windows.h>
#include <ctime>

void CreateRandomString(char* pszDest, int nLength)
{
	static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	for (int i = 0; i < nLength; ++i)
		pszDest[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	pszDest[nLength] = '\0';
}

void generateRandomHWID(char hwid[64]) { 
    srand(time(0));
    memset(hwid, ' ', 17);
     
    hwid[17] = 'A' + rand() % 26;  
    hwid[18] = 'A' + rand() % 26;  
    hwid[19] = '-';
    hwid[20] = 'A' + rand() % 26;  
    hwid[21] = 'A' + rand() % 26;  
     
    for (int i = 22; i < 30; i++) {
        hwid[i] = '0' + rand() % 10;
    }
     
    hwid[30] = '\0';
}
