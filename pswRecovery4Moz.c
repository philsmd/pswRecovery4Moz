// pswRecovery4Moz
// Copyright (C) 2011-11-30 by Philipp Schmidt (ph i lipp (AT] 
// ps ch mi dt.it, w/o spaces and (AT] replaced)
//
// This Program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// It is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this source files. If not, see
// <http://www.gnu.org/licenses/>.

// Credits:
// Credits go to Dr Stephen Henson for his research for "Netscape Key Databases"
// (see http://www.drh-consultancy.demon.co.uk/key3.html)
// Hopefully I didn't forget anybody else who reserves credits (but drop a mail
// if that would be the case)
// Of course sources from the OpenSSL libraries were also taken into account
// Thanks for that stuff too,bros

// Instructions:
// compile this file w/ the command:
// g++ pswRecovery4Moz.c -ldl # -o pswRecovery4Moz
//
// more instuctions under: http://www.pschmidt.it/?a=:e%20pswRecovery4Moz.txt

// Contribution/Report bugs:
// Don't hesitate to contribute to this tool. I'm also happy if somebody wants
// to put it on GitHub etc. Please inform me of any such action s.t. I can help
// and contribute afterwards myself (pls. do NOT forget to give credits ;-), also
// to Steve)

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>         /* declare the 'stat' structure */
#include <dlfcn.h>
#include <ctype.h>

#define VERSION "0.1"
#define PROGRAM "pswRecovery4Moz"
#define BUF_MAX_SMALL 256
#define BUF_MAX 500
#define BUF_MAX_LARGE 2000
#define BUF_MAX_HUGE 8192
#define RAW_OUTPUT 0    // Do not show additional status notification,hide unneeded details (iff 1)
#define GS_LENGTH 20
#define PK_DEFAULT_LENGTH 0x93
#define PASSWORD_CHECK_LENGTH 16    // Fixed length of global salt
#define PASSWORD_CHECK_SEARCH "password-check"
#define KEY3_SEARCH "global-salt"
#define KEY_NULL_PREFIX "00 "
#define KEY3_HEADER_SIZE 3
#define CONVERSION_LENGTH 20 // Fixed sized used in SHA1-HMAC etc conversion (e.g. for padding)
#define MOZ_KEY_SIZE 24
#define MOZ_IV_SIZE 8
#define PATH_DELIMITER '/'
#define PATHS_DELIMITER ':'
#define MOZ_LOGIN_TOKEN_NAME "NSS Certificate DB"
#define SQLITE_OPEN_READONLY 0x00000001
#define SHA1CircularShift(bits,word)((((word)<<(bits))&0xFFFFFFFF)|((word)>>(32-(bits))))

// ASN1 CONSTANTS
const char*ASN1_NAMES[]={/*1*/"BOOLEAN","INTEGER","BIT STRING","OCTET STRING","NULL","OBJECT IDENTIFIER",
    "OBJECT DESCRIPTOR","EXTERNAL",/*9*/"REAL","ENUMERATED","EMBEDDED PDV","UTF8String","RELATIVE-OID","",
    "",/*16*/"SEQUENCE","SET","NUMERIC STRING","PRINTABLE STRING","","VIDEOTEXT STRING","IA5String",
    "UTC STRING","GENERALIZED TIME","GRAPHIC STRING",/*26*/"VISIBLE STRING","GENERAL STRING","UNIVERSAL STRING",
    "CHARACTER STRING","BMP STRING",/*omit*/"","","","","","","","","","","","","","","","","",/*48*/"SEQUENCE"};
#define ASN1_INDENTATION 4
#define ASN1_SEQUENCE 48
#define ASN1_BOOLEAN 1
#define ASN1_NULL 9
#define ASN1_DEFAULT_NAME 18 // Character string

#define NSS_LIBRARY_NAME "libnss3.so"
#define SQLITE_LIBRARY_NAME "libsqlite3.so"
#define SQLITE_NAME_ADD_SUFFIX ".0"
#define MOZ_SIGNONS "signons.sqlite"
#define MOZ_SIGNONS_QUERY "SELECT hostname,httpRealm,encryptedUsername,encryptedPassword FROM moz_logins;"
#define MOZ_KEY3DB "key3.db"
#define MOZ_DEFAULT_LIB_PATH "/usr/lib/:/usr/lib/x86_64-linux-gnu/:/usr/lib/x86_64/:/usr/lib/x86_64-linux/: \
    /usr/lib64/:/usr/lib32/"
#define FF_USER_PATH "/.mozilla/firefox/"
#define TB_USER_PATH "/.thunderbird/"
#define TB_PATH_SEARCH "thunderbird"
#define MOZ_INI_NAME "profiles.ini"
#define MOZ_DEFAULT_PASSWORD ""
//Following key is used as entry key to get the private key from key3.db (NOTHING special,nor any secret key whatsoever)
//We do NOT even need to hard-code it since it can be either extracted from signons.sqlite OR we have the private key
//directly specified as command line argument (=> forget it)
//#define MOZ_DEFAULT_KEYID "f8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"

// some global variables (we can somehow omit also those if you really insist,but who cares)
unsigned int cmdline_raw=0;
int isNSSInitialized=0;
// libs
void*libnss=NULL;
void*libsqlite=NULL;
void*libtmp=NULL;

// some typedefs
typedef enum SECItemType {
    Buffer=0,
    ClearDataBuffer=1,
    CipherDataBuffer=2,
    DERCertBuffer=3,
    EncodedCertBuffer=4,
    DERNameBuffer=5,
    EncodedNameBuffer=6,
    AsciiNameString=7,
    AsciiString=8,
    DEROID=9,
    UnsignedInteger=10,
    UTCTime=11,
    GeneralizedTime=12
}SECItemType;
struct SECItem {
    SECItemType type;
    unsigned char*data;
    unsigned int len;
};
typedef enum SECStatus {
    SECWouldBlock=-2,
    SECFailure=-1,
    SECSuccess=0
}SECStatus;
typedef struct rsaEncryption {
    char*keyID;
    char*key;
    struct rsaEncryption*next;
}rsaEncryptionNode;

typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef SECStatus    (*NSS_Init)(const char *configdir);
typedef SECStatus    (*NSS_Shutdown)(void);
typedef PK11SlotInfo*(*PK11_GetInternalKeySlot)(void);
typedef int          (*PK11_NeedLogin)(PK11SlotInfo*slot);
typedef char*        (*PK11_GetTokenName)(PK11SlotInfo*slot);
typedef SECStatus    (*PK11_Authenticate)(PK11SlotInfo*slot,int cert,void*pass);
typedef SECStatus    (*PK11_CheckUserPassword)(PK11SlotInfo*slot,char*pass);
typedef SECStatus    (*PK11SDR_Decrypt)(SECItem*data,SECItem*result,void*cx);
typedef void         (*PK11_FreeSlot)(PK11SlotInfo*slot);

typedef int          (*SQLite_Open)(const char*file,void**db,int,const char*vfs);
typedef int          (*SQLite_Close)(void*db);
typedef int          (*SQLite_Get_Table)(void*db,const char*query,char***res,int*rows,int*columns,char**errorMsg);
typedef int          (*SQLite_Free_Table)(char**table);

NSS_Init                NSSInit=NULL;
NSS_Shutdown            NSSShutdown=NULL;
PK11_GetInternalKeySlot PK11GetInternalKeySlot=NULL;
PK11_CheckUserPassword  PK11CheckUserPassword=NULL;
PK11_NeedLogin          PK11NeedLogin=NULL;
PK11_GetTokenName       PK11GetTokenName=NULL;
PK11_Authenticate       PK11Authenticate=NULL;
PK11SDR_Decrypt         PK11SDRDecrypt=NULL;
PK11_FreeSlot           PK11FreeSlot=NULL;
SQLite_Open             SQLiteOpen=NULL;
SQLite_Close            SQLiteClose=NULL;
SQLite_Get_Table        SQLiteGetTable=NULL;
SQLite_Free_Table       SQLiteFreeTable=NULL;

// helper functions
void str2lower(char*str) {
	int n=strlen(str);
	for(int i=0;i<n;i++) {
		if (str[i]>=65&&str[i]<=90) {
		    str[i]+=32;
        }
	}
}

int testOpenFile(const char*filePath) {
    FILE*tmpFile=fopen(filePath,"r");
    if (tmpFile==NULL) {
        return 1;
	}
    fclose(tmpFile);
    return 0;
}

int fileExists(char*path) {
    struct stat stat_p;
    stat(path,&stat_p);
    return S_ISREG(stat_p.st_mode)&&!testOpenFile(path);
}

int dirExists(char*path) {
    struct stat stat_p;
    stat(path,&stat_p);
    return S_ISDIR(stat_p.st_mode);
}

char*getMozProfilePath(bool print,const char*path) {
	char profilePath[BUF_MAX_SMALL];
	char profileFile[BUF_MAX_SMALL];
	char line[1024];
	unsigned long pathSize=BUF_MAX_SMALL;
	char *finalProfilePath;
	int isDefaultFound=0;
    char userPath[BUF_MAX];
    strcpy(userPath,getenv("HOME"));
    if (userPath==NULL||strlen(userPath)<0) {
        struct passwd*pw=getpwuid(getuid());
        if (pw) {
            strcpy(userPath,pw->pw_dir);
        } else {
            if (print) {
                printf("[-] Failed to get user home path\n"); 
            }
            return NULL;
        }
    }
    strcat(userPath,path);
	strcpy(profilePath,userPath);
	strcpy(profileFile,userPath);
	strcat(profileFile,MOZ_INI_NAME);
	FILE*profile=fopen(profileFile,"r");
	if (!profile) {
        if (print) {
            printf("[-] Failed to open/find profile file: %s\n",profileFile);
        }
		return NULL;
	}
	while(fgets(line,1024,profile)) {
		str2lower(line);
		if (!isDefaultFound&&(strstr(line,"name=default")!=NULL)) {
			isDefaultFound=1;
			continue;
		}

		if (isDefaultFound) {
			if (strstr(line,"path=")!=NULL) {
				char *slash=strstr(line,"/");
				if (slash!=NULL) {
					*slash='\\';
                }
				line[strlen(line)-1]=0;
				char*start=strstr(line,"=");
				int totalLen=strlen(profilePath)+strlen(start)+3;
				finalProfilePath=(char*)malloc(totalLen);
				if (finalProfilePath) {
					strcpy(finalProfilePath,profilePath);
					strcat(finalProfilePath,start+1);
                    if (print&&!cmdline_raw) {
                        printf("[i] Profile path: %s\n",finalProfilePath);
                    }
				}
				break;
			}
		}
	}
	fclose(profile);
	return finalProfilePath;
}

void*loadLibrary(char*mozDir,const char*libName) {
    char loadPath[BUF_MAX_HUGE]="";
    if (mozDir==NULL||libName==NULL||strlen(mozDir)<1) {
        printf("[-] Please specify a library path (-l)\n");
        return 0;
    }
    char*dirPtr=mozDir,*lastPtr=mozDir,*foundPtr=NULL;
    do {
        foundPtr=strchr(dirPtr,PATHS_DELIMITER);
        if (foundPtr&&foundPtr!=lastPtr) {
            if (lastPtr!=mozDir) {
                strncpy(loadPath,dirPtr,foundPtr-lastPtr-1);
                loadPath[foundPtr-lastPtr-1]='\0';
            } else {
                strncpy(loadPath,dirPtr,foundPtr-lastPtr);
                loadPath[foundPtr-lastPtr]='\0';
            }
        } else {
            strcpy(loadPath,dirPtr);
        }
	    strcat(loadPath,"/");
	    strcat(loadPath,libName);
        if (fileExists(loadPath)) {
            // Finally load the library and exit loop
            libtmp=dlopen(loadPath,RTLD_LAZY);
            break;
        }
        // just try to do the same with a default suffix e.g. [libname.so].0
	    strcat(loadPath,SQLITE_NAME_ADD_SUFFIX);
        if (fileExists(loadPath)) {
            // Finally load the library and exit loop
            libtmp=dlopen(loadPath,RTLD_LAZY);
            break;
        }
        if (foundPtr&&foundPtr!=lastPtr) {
            dirPtr+=foundPtr-dirPtr+1;
        } else {
            break; 
        }
        lastPtr=foundPtr;
    } while (foundPtr);
	if (!libtmp) {
		return 0;
	}
	return libtmp;
}

void NSSUnload() {
	if (isNSSInitialized&&NULL!=NSSShutdown) {
	     (*NSSShutdown)();
    }
    if (libnss!=NULL) {
         dlclose(libnss);
    }
}

int initNSSLibrary(char*profilePath) {
	isNSSInitialized=0;
    if ((*NSSInit)(profilePath)!=SECSuccess) {
		NSSUnload();
		return 1;
	} else {
		isNSSInitialized=1;
	}
    return 0;
}

int base64Decode(const char*encoded,char**decoded,int*decodedLen) {
    if (decoded==NULL||encoded==NULL) {
        return 1;
    }
    unsigned char in[4],out[3],v;
    char temp[3],chars[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";
    unsigned int i,j=0,pos,length=strlen(encoded);
    (*decodedLen)=0;
    *decoded=(char*)malloc(sizeof(char)*BUF_MAX_HUGE);
    strcpy((*decoded),"");
    int isNullTerminator=0;
    unsigned int numNullTerminators=0;
    unsigned nullTerminators[length];
    while (j<=length) {
        for (pos=0,i=0;i<4&&j<=length;i++) {
            v=0;
            while (j<=length&&v==0) {
                v=(unsigned char)encoded[j++];
                v=(unsigned char)((v<43||v>122)?0:chars[v-43]);
                if (v) {
                    v=(unsigned char)((v=='$')?0:v-61);
                }
            }
            if (j<=length) {
                pos++;
                if (v) {
                    in[i]=(unsigned char)(v-1);
                }
            } else {
                in[i]=0;
            }
        }
        if (pos) {
            out[0]=(unsigned char)(in[0]<<2|in[1]>>4);
            out[1]=(unsigned char)(in[1]<<4|in[2]>>2);
            out[2]=(unsigned char)(((in[2]<<6)&0xc0)|in[3]);
            for (i=0;i<pos-1;i++) {
                if (out[i]!='\0') {
                    sprintf(temp,"%c",out[i]);
                    strcat(*decoded,temp);
                    while (isNullTerminator) {
                        strcat(*decoded,temp);
                        isNullTerminator--;
                    }
                } else {
                    isNullTerminator++; 
                    nullTerminators[numNullTerminators++]=*decodedLen+i;
                }
            }
            (*decodedLen)+=i;
        }
    }
    for (i=0;i<numNullTerminators;i++) {
        (*decoded)[nullTerminators[i]]='\0';
    }
    int correction=0;
    if (encoded[length-1]=='=') {
        correction++;
        if (encoded[length-2]=='=') {
            correction++;
        }
    }
    (*decodedLen)=(length*3)/4-correction;
    return 0;
}

int PK11Decrypt(char*decodeData,int decodeLen,char**clearData,int*finalLen,const char*master) {
    SECStatus status;
    SECItem request;
    SECItem reply;
    PK11SlotInfo*slot=(*PK11GetInternalKeySlot)(); // Get a token
    if (!slot) {
		return 1;
	}
	// Decrypt the string
    // Can be done similar to what was is explained here https://wiki.mozilla.org/NSS_Shared_DB
    if ((*PK11NeedLogin)(slot)) {
        if (master==NULL||strlen(master)<1) {
            printf("[-] A master password is required (specify one with -m)\n");
            //return 1;     // not so clever if we fail once,don't retry
            (*PK11FreeSlot)(slot);
            exit(1);
        }
        if (!strcmp(((*PK11GetTokenName)(slot)),MOZ_LOGIN_TOKEN_NAME)) {
            status=(*PK11CheckUserPassword)(slot,(char*)master);
            if (status!=SECSuccess) {
                (*PK11FreeSlot)(slot);
                return 1;
            }
        }
    }
    request.data=(unsigned char*)decodeData;
    request.len=decodeLen;
    reply.data=0;
	reply.len=0;
    status=(*PK11SDRDecrypt)(&request,&reply,NULL);
    if (status!=SECSuccess) {
        (*PK11FreeSlot)(slot);
		return 1;
	}
    *clearData=(char*)reply.data;
    *finalLen=reply.len;
	(*PK11FreeSlot)(slot);  // free the slot
	return 0;
}
 
int decryptStr(const char*cryptData,char**clearData,const char*master) {
    int decodeLen=0;
    int finalLen=0;
    char*decodeData=NULL;
    char*finalData=NULL;
	if (cryptData[0]) {
		if (base64Decode(cryptData,&decodeData,&decodeLen)||decodeData==NULL) {
            if (decodeData) {
                free(decodeData);
            }
			return 1;
		}
        if (PK11Decrypt(decodeData,decodeLen,&finalData,&finalLen,master)||finalData==NULL) {
			return 1;
		}
        free(decodeData);
		*clearData=(char*)malloc(finalLen+1);
        if (*clearData==NULL) { // malloc failed
			return 1;
		}
        memcpy(*clearData,finalData,finalLen);
		*(*clearData+finalLen)=0;
        if (finalData) {
            free(finalData);   
        }
		return 0;
	}
	if (base64Decode(cryptData,clearData,&decodeLen)) {
		return 1;
	}
	return 0;
}

char*getMozLibPath() {
    // Logic missing, but needed (if even possible in linux)
    unsigned long pathSize=BUF_MAX_SMALL;
	const char*path=MOZ_DEFAULT_LIB_PATH;
    char*mozDir=(char*)malloc(strlen(path)+1);
	if (mozDir) {
		strcpy(mozDir,path);
    }
	return mozDir;
}

void initLib(const char*name,char*dir,void**libref,const char*lib) {
    if (!(*libref)) {
        if (dir==NULL||strlen(dir)<1) {
            dir=getMozLibPath(); 
        }
        if (!((*libref)=loadLibrary(dir,lib))) {
            printf("[-] Failed to load %s library\n",name);
            exit(1);
        }
    }
}

int initMozLibs(char*mozDir) {
	libnss=NULL;
	if (mozDir!=NULL) {
        if (libsqlite=loadLibrary(mozDir,SQLITE_LIBRARY_NAME)) {
            libnss=loadLibrary(mozDir,NSS_LIBRARY_NAME);
        }
	}
	if (!libnss) {  //  try it w/o full path or fail
		libnss=dlopen(NSS_LIBRARY_NAME,RTLD_LAZY);
		if (!libnss) {
            printf("[-] The library libnss could NOT be initialized\n");
			return 0;
		}
	}
	if (!libsqlite) {
		return 0;
	}
	NSSInit=(NSS_Init)dlsym(libnss,"NSS_Init");
	NSSShutdown=(NSS_Shutdown)dlsym(libnss,"NSS_Shutdown");
	PK11GetInternalKeySlot=(PK11_GetInternalKeySlot)dlsym(libnss,"PK11_GetInternalKeySlot");
	PK11NeedLogin=(PK11_NeedLogin)dlsym(libnss,"PK11_NeedLogin");
	PK11GetTokenName=(PK11_GetTokenName)dlsym(libnss,"PK11_GetTokenName");
	PK11Authenticate=(PK11_Authenticate) dlsym(libnss,"PK11_Authenticate");
	PK11CheckUserPassword=(PK11_CheckUserPassword)dlsym(libnss,"PK11_CheckUserPassword");
	PK11SDRDecrypt=(PK11SDR_Decrypt) dlsym(libnss,"PK11SDR_Decrypt");
	PK11FreeSlot=(PK11_FreeSlot)dlsym(libnss,"PK11_FreeSlot");
	if (!NSSInit||!NSSShutdown||!PK11GetInternalKeySlot||!PK11NeedLogin||!PK11Authenticate||!PK11SDRDecrypt||
            !PK11FreeSlot||!PK11CheckUserPassword) {
        if (!cmdline_raw) {
            printf("[-] Not all library functions could be found\n"); 
        }
		NSSUnload();
        return 0;
    }
	return 1;
}

int decryptCmdLine(const char*user,const char*pass,const char*master) {
	char*clearData;
	if (!decryptStr(user,&clearData,master)==1) {
        if (!cmdline_raw) {
            printf("[i] Username: ");
        }
        printf("%s\n",clearData);
        if (clearData) {
            free(clearData);
        }
	}
	if (!decryptStr(pass,&clearData,master)==1) {
        if (!cmdline_raw) {
            printf("[i] Password: ");
        }
        printf("%s\n",clearData);
        if (clearData) {
            free(clearData);
        }
	}
    return 0;
}

char**getSQLiteContent(char*signonFile,char***dst,unsigned int*retNum,unsigned int*retCols) {
    char**retArray;
    (*retNum)=0;
    (*retCols)=0;
    // you could do similar things w/ -lsqlite instead of -ldl of course (but who really cares?)
	SQLiteOpen=(SQLite_Open)dlsym(libsqlite,"sqlite3_open_v2");
	SQLiteGetTable=(SQLite_Get_Table)dlsym(libsqlite,"sqlite3_get_table");
	SQLiteFreeTable=(SQLite_Free_Table)dlsym(libsqlite,"sqlite3_free_table");
	SQLiteClose=(SQLite_Close)dlsym(libsqlite,"sqlite3_close");
	if (signonFile==NULL||testOpenFile(signonFile)) {
		return 0;
    }
    void*sqliteDB;
    if (!SQLiteOpen(signonFile,&sqliteDB,SQLITE_OPEN_READONLY,NULL)) {
        int rows,columns;
        char**tuples;
        char*errorMsg;
        const char*query=MOZ_SIGNONS_QUERY;
        if (!SQLiteGetTable(sqliteDB,query,&tuples,&rows,&columns,&errorMsg)) {
            (*retCols)=columns;
            retArray=(char**)malloc((rows*columns)*sizeof(char*));
            int i,j;
            for (i=1;i<=rows;i++) {
                for (j=0;j<columns;j++) {
                    retArray[(i-1)*columns+j]=(char*)malloc(sizeof(char)*BUF_MAX);
                    if (tuples[i*columns+j]) {
                        strcpy(retArray[(i-1)*columns+j],tuples[i*columns+j]);
                    } else {
                        strcpy(retArray[(i-1)*columns+j],"");
                    }
                }
                (*retNum)++;
            }
            SQLiteFreeTable(tuples);
        }
        SQLiteClose(sqliteDB);
	}
    *dst=retArray;
	return retArray;
}

int decryptSQLite(const char*signonFile,const char*master) {
	char*clearData;
	SQLiteOpen=(SQLite_Open)dlsym(libsqlite,"sqlite3_open_v2");
	SQLiteGetTable=(SQLite_Get_Table)dlsym(libsqlite,"sqlite3_get_table");
	SQLiteFreeTable=(SQLite_Free_Table)dlsym(libsqlite,"sqlite3_free_table");
	SQLiteClose=(SQLite_Close)dlsym(libsqlite,"sqlite3_close");
	if (signonFile==NULL||testOpenFile(signonFile)) {
		return 1;
    }
    if (!cmdline_raw) {
        printf("[i] Source file: %s\n",signonFile);
    }
    void*sqliteDB;
    int ret=SQLiteOpen(signonFile,&sqliteDB,SQLITE_OPEN_READONLY,NULL);
    if (!ret) {
        int rows,columns;
        char**tuples;
        char*errorMsg;
        const char*query=MOZ_SIGNONS_QUERY;
        ret=SQLiteGetTable(sqliteDB,query,&tuples,&rows,&columns,&errorMsg);
        if (!ret) {
            for (int i=1,ii=0;i<=rows;i++,ii=0) {
                if (!cmdline_raw) {
                    printf("\n");
                    // Those two info are NOT so important,skip in raw output
                    printf("[i] URL: %s\n",tuples[i*columns+(ii++)]);
                    printf("[i] Target: %s\n",tuples[i*columns+(ii++)]);
                } else {
                    ii+=2; // this will be done always (either with 2x ii++ or here)
                }
		        if (!decryptStr(tuples[i*columns+(ii++)],&clearData,master)==1) {
                    if (!cmdline_raw) {
                        printf("[i] Username: ");
                    }
                    printf("%s\n",clearData);
                    if (clearData) {
                        free(clearData);
                    }
		        }
		        if (!decryptStr(tuples[i*columns+ii],&clearData,master)==1) {
                    if (!cmdline_raw) {
                        printf("==> Password: ");
                    }
                    printf("%s\n",clearData);
                    if (clearData) {
                        free(clearData);
                    }
		        }
            }
            ret=SQLiteFreeTable(tuples);
        }
        SQLiteClose(sqliteDB);
	}
	return ret;
}

// HMAC for SHA1

// SHA1 helper functions
typedef struct SHA1Context {
    unsigned Message_Digest[5];      // Message Digest (output)
    unsigned Length_Low;             // Message length in bits
    unsigned Length_High;            // Message length in bits
    unsigned char Message_Block[64]; // 512-bit message blocks
    int Message_Block_Index;         // Index into message block array
    int Computed;                    // Is the digest computed?
    int Corrupted;                   // Is the message digest corruped?
} SHA1Context;

void SHA1Reset(SHA1Context*context) {
    context->Length_Low         =0;
    context->Length_High        =0;
    context->Message_Block_Index=0;
    context->Message_Digest[0]  =0x67452301;
    context->Message_Digest[1]  =0xEFCDAB89;
    context->Message_Digest[2]  =0x98BADCFE;
    context->Message_Digest[3]  =0x10325476;
    context->Message_Digest[4]  =0xC3D2E1F0;
    context->Computed=0;
    context->Corrupted=0;
}

void SHA1ProcessMessageBlock(SHA1Context*context) {
    const unsigned K[]={0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6};
    unsigned temp;
    unsigned W[80];
    unsigned A,B,C,D,E;
    int t;
    // Initialize the first 16 words in the array W
    for (t=0;t<16;t++) {
        W[t]=((unsigned)context->Message_Block[t*4])<<24;
        W[t]|=((unsigned)context->Message_Block[t*4+1])<<16;
        W[t]|=((unsigned)context->Message_Block[t*4+2])<<8;
        W[t]|=((unsigned)context->Message_Block[t*4+3]);
    }
    for (t=16;t<80;t++) {
       W[t]=SHA1CircularShift(1,W[t-3]^W[t-8]^W[t-14]^W[t-16]);
    }
    A=context->Message_Digest[0];
    B=context->Message_Digest[1];
    C=context->Message_Digest[2];
    D=context->Message_Digest[3];
    E=context->Message_Digest[4];
    for (t=0;t<20;t++) {
        temp=SHA1CircularShift(5,A)+((B&C)|((~B)&D))+E+W[t]+K[0];
        temp&=0xFFFFFFFF;
        E=D;
        D=C;
        C=SHA1CircularShift(30,B);
        B=A;
        A=temp;
    }
    for (t=20;t<40;t++) {
        temp=SHA1CircularShift(5,A)+(B^C^D)+E+W[t]+K[1];
        temp&=0xFFFFFFFF;
        E=D;
        D=C;
        C=SHA1CircularShift(30,B);
        B=A;
        A=temp;
    }
    for (t=40;t<60;t++) {
        temp=SHA1CircularShift(5,A)+((B&C)|(B&D)|(C&D))+E+W[t]+K[2];
        temp&=0xFFFFFFFF;
        E=D;
        D=C;
        C=SHA1CircularShift(30,B);
        B=A;
        A=temp;
    }
    for (t=60;t<80;t++) {
        temp=SHA1CircularShift(5,A)+(B^C^D)+E+W[t]+K[3];
        temp&=0xFFFFFFFF;
        E=D;
        D=C;
        C=SHA1CircularShift(30,B);
        B=A;
        A=temp;
    }
    context->Message_Digest[0]=(context->Message_Digest[0]+A)&0xFFFFFFFF;
    context->Message_Digest[1]=(context->Message_Digest[1]+B)&0xFFFFFFFF;
    context->Message_Digest[2]=(context->Message_Digest[2]+C)&0xFFFFFFFF;
    context->Message_Digest[3]=(context->Message_Digest[3]+D)&0xFFFFFFFF;
    context->Message_Digest[4]=(context->Message_Digest[4]+E)&0xFFFFFFFF;
    context->Message_Block_Index=0;
}

void SHA1PadMessage(SHA1Context*context) {
    if (context->Message_Block_Index>55) {
        context->Message_Block[context->Message_Block_Index++]=0x80;
        while (context->Message_Block_Index<64) {
            context->Message_Block[context->Message_Block_Index++]=0;
        }
        SHA1ProcessMessageBlock(context);
        while (context->Message_Block_Index<56) {
            context->Message_Block[context->Message_Block_Index++]=0;
        }
    } else {
        context->Message_Block[context->Message_Block_Index++]=0x80;
        while (context->Message_Block_Index<56) {
            context->Message_Block[context->Message_Block_Index++]=0;
        }
    }
    context->Message_Block[56]=(context->Length_High>>24)&0xFF;
    context->Message_Block[57]=(context->Length_High>>16)&0xFF;
    context->Message_Block[58]=(context->Length_High>>8)&0xFF;
    context->Message_Block[59]=(context->Length_High)&0xFF;
    context->Message_Block[60]=(context->Length_Low>>24)&0xFF;
    context->Message_Block[61]=(context->Length_Low>>16)&0xFF;
    context->Message_Block[62]=(context->Length_Low>>8)&0xFF;
    context->Message_Block[63]=(context->Length_Low)&0xFF;
    SHA1ProcessMessageBlock(context);
}

int SHA1Result(SHA1Context*context) {
    if (context->Corrupted) {
        return 0;
    }
    if (!context->Computed) {
        SHA1PadMessage(context);
        context->Computed=1;
    }
    return 1;
}

void SHA1Input(SHA1Context*context,char*message_array,unsigned length) {
    if (!length) {
        return;
    }
    if (context->Computed||context->Corrupted) {
        context->Corrupted=1;
        return;
    }
    while (length-- && !context->Corrupted) {
        context->Message_Block[context->Message_Block_Index++]=(*message_array&0xFF);
        context->Length_Low+=8;
        context->Length_Low&=0xFFFFFFFF; // Low 32 bits
        if (context->Length_Low==0) {
            context->Length_High++;
            context->Length_High&=0xFFFFFFFF; // High 32 bits
            if (context->Length_High==0) {
                context->Corrupted=1; // too long
            }
        }
        if (context->Message_Block_Index==64) {
            SHA1ProcessMessageBlock(context);
        }
        message_array++;
    }
}

void usage(char*cmd) {
    printf("%s v.%s by pschmidt (philipp(>_AT_<)pschmidt.it)\n",PROGRAM,VERSION);
    printf("\n");
    printf("Usage: %s MODE OPT [OPT ...]\n",cmd);
    printf("\n");

    printf("Description:\n");
    printf("  This program will decrypt the mozilla database (signons.sqlite,key3.db)\n");
    printf("  where username and password of logins are stored.\n");
    printf("\n");

    printf("MODE:\n");
    printf("  -n  - Normal mode using libnss (DEFAULT)\n");
    printf("  -f  - Special mode w/o libnss (use %s and %s directly)\n",MOZ_KEY3DB,MOZ_SIGNONS);
    printf("  -s  - Just calculate SHA1-HMAC for key (-k) and text (-t)\n");
    printf("  -a  - Invoke minimalistic ASN.1 parser for hexadecimal text specified by -a option\n");
    printf("\n");

    printf("OPT:\n");
    printf("  -r  - Enable raw output (output w/o description)\n");
    printf("  -k  - Key to use for SHA1-HMAC generation (see -s and -t)\n");
    printf("  -t  - Text/message to use for SHA1-HMAC generation (see -s and -k)\n");
    printf("  -g  - Global salt in hex format (e.g \"01 ef 64 ...\") for des3 decryption \n");
    printf("  -e  - Entry salt in hex format (e.g \"63 53 64 ...\") for des3 decryption\n");
    printf("  -m  - Master key mozilla password\n");
    printf("  -u  - Encrypted username string (base64 encoded)\n");
    printf("  -p  - Encrypted password string (base64 encoded)! NOT the MASTER password (see -m)\n");
    printf("  -R  - Private key entry (RSA key,see -f)\n");
    printf("  -P  - Mozilla profile path\n");
    printf("  -l  - Mozilla (or OS) library path\n");
    printf("  -a  - Hexadecimal string (e.g. 30 59 01 ...) to be tested with the minimalistic ASN.1 parser (\n");
    printf("\n");

    printf("Example usage:\n");
    printf("  %s\n",cmd);
    printf("  %s -n -m \"pAsSw0rd\"\n",cmd);
    printf("  %s -f\n",cmd);
    printf("  %s -f -g \"3b 28 75 c2 a9 0d 40 2b 84 b6 83 e0 de a5 41 49 55 07 f3 d4\" \\\n",cmd);
    printf("     -e \"32 73 a0 bf e4 03 39 86 13 33 9e ff 24 cc 26 4b c2 ef 7c 1a\" (use this together w/ -R)\n");
    printf("  %s -a \"30 13 02 01 05 16 0e 41 6e 79 62 6f 64 79 20 74 68 65 72 65 3f\"\n",cmd);
    printf("  %s -s -t \"15 96 bb 81 12 65 2a 43 e7 bd fb 2f dc 87 99 e5 00 00 00 00\" \\\n",cmd);
    printf("     -k \"8e 1e 3a 52 36 ab c3 44 55 2d 6e 1a 00 67 1a ed 69 2d 48 25\"\n");
    printf("\n");

    printf("CREDITS:\n");
    printf("   ...go especially to Dr Stephen Henson from drh-consultancy who did some research on key3.db which\n");
    printf("   was very useful for me to get started (see http://www.drh-consultancy.demon.co.uk/key3.html)\n");
    printf("\n");

    printf("KNOWN DEFICIENCIES/PROBLEMS/BUGS:\n");
    printf("   Since this tool was designed in a very restricted amount of time, it lacks of a good design.\n");
    printf("   There may be some borderline cases (e.g if you supply malicious/unexpected input etc.) where the tool failes/crashes\n");
    printf("   The project was more about the research of how Mozilla encrypts passwords and not so much on the tool itself\n");
    printf("   Use of more secure functions (as snprintf,strncpy,strncmp etc) would be great, but you know as of know it is a\n");
    printf("   quick-done tool\n");
    printf("\n");

    printf("AUTHORS/CONTRIBUTORS/CONTACT:\n");
    printf("   Please contact me at ph i lipp (AT] ps ch mi dt.it, w/o spaces and (AT] replaced\n");
    printf("   Contributors wanted\n");
    printf("   Please just drop me a mail if you find this tool useful and if you use this (or some of this) code\n");
    printf("   (for any purpose whatsoever,except malicious)\n");
    printf("   Also fixes and other suggestions are VERY welcome. Since the testing phase was NOT so ample,there may be some problems\n");
    printf("   that we can encounter and (hopefully easily) FIX.\n");
}

// e.g. 50 68 69 6C => Phil
char*atohx(char*dst,const char*src,const unsigned int spacing) {
    char*ret=dst;
    const char*srcPtr=src;
    const unsigned int length=strlen(srcPtr);

    int lsb,msb;
    for (lsb=0,msb=0;*src;src+=2+spacing) {  
        if ((src+1+spacing)>srcPtr+length&&src-srcPtr) {
            break;
        }
        msb=tolower(*src);
        lsb=tolower(*(src+1));
        msb-=isdigit(msb)?0x30:0x57;
        lsb-=isdigit(lsb)?0x30:0x57;
        if((msb<0x0||msb>0xf)||(lsb<0x0||lsb>0xf)) {
            *ret=0;
            return NULL;
        }
        *dst++=(char)(lsb|(msb<<4)); 
    }
    *dst=0;
    return ret;
}

char*hxtoa(char*dst,const char*src,const unsigned int padding) {
    int src1=src[0];
    const char*chars="0123456789abcdef";
    char*ret=dst,temp[3],temp2[strlen(ret)];
    unsigned int division;
    strcpy(ret,"");
    if (src1<0) {
        src1+=256;
    }
    while (1) {
        division=src1/16;
        if (division>0) {
            sprintf(temp,"%c",chars[division]);
            strcat(ret,temp);
            src1-=(16*division);
        } else {
            sprintf(temp,"%c",chars[src1%16]);
            strcat(ret,temp);
            break;
        }
    }
    if (ret==NULL||strlen(ret)<1) {
        strcpy(ret,"00");
    }
    while (strlen(ret)<padding) {
        strcpy(temp2,ret);
        strcpy(ret,"0");
        strcat(ret,temp2);
    }
    return ret;
}

// e.g. Phil => 50 68 69 6C
char*hxtostr(char*dst,const char*src,unsigned int length,const char*delimiter,const unsigned int delSize,const unsigned int padding) {
    char*ret=dst;
    int i,j;
    strcpy(ret,"");
    char temp[4];
    for (i=0;i<length;i++) {
        if (i!=0&&delimiter!=NULL) {
            for (j=0;j<delSize;j++) {
                strcat(ret,delimiter);
            }
        }
        hxtoa(temp,src+i,padding);
        strcat(ret,temp);
    }
    return ret;
}

char*getTransTable(char*dst,const unsigned int transMod) {
    char*table=dst;
    char temp[3];
    int i;
    int isNullTerminator=0;
    unsigned int numNullTerminators=0;
    unsigned nullTerminators[255];
    strcpy(dst,"");
    for (i=0;i<256;i++) {
        if ((i^transMod)!=0) {
            sprintf(temp,"%c",i^transMod);
            strcat(table,temp);
            while (isNullTerminator) {
                strcat(table,temp);
                isNullTerminator--;
            }
        } else {
            isNullTerminator++; 
            nullTerminators[numNullTerminators++]=i;
        }
    }
    for (i=0;i<numNullTerminators;i++) {
        table[nullTerminators[i]]='\0';
    }
    return table;
}

char*translate(char*dst,const char*target,const unsigned int size,const char*table) {
    char hxtostrTemp[BUF_MAX_HUGE];
    char output[BUF_MAX_HUGE];
    char*ret=dst;
    strcpy(ret,"");
    char temp[3];
    int i,j;
    // copy string byte per byte (instead of using strdup <-avoid)
    for (i=0;i<size;i++) {
        ret[i]=target[i];
    }
    // do translate
    for (i=0;i<256;i++) {
        if ((int)(table[i])!=i&&((int)(table[i])>0||(255+(int)(table[i]))!=i)) {
            for (j=0;j<size;j++) {
                if ((int)target[j]==i||(256+(int)target[j])==i) {
                    ret[j]=table[i];
                }
            }
        }
    }
    return ret;
}

char*getRawDigest(SHA1Context sha,char*dst,unsigned int*length) {
    char*ret=dst;
    strcpy(ret,"");
    (*length)=0;
    int i,j,blocksize=8,maxSize=sizeof(sha.Message_Digest)/sizeof(*sha.Message_Digest);
    char part[10],temp[4],temp2[4],key_part[4];
    int isNullTerminator=0;
    unsigned int numNullTerminators=0;
    unsigned nullTerminators[maxSize*blocksize];
    for (i=0;i<maxSize;i++) {
        sprintf(part,"%08x",sha.Message_Digest[i]);   // number in %08x must correspond to blocksize
        for (j=0;j<blocksize;j+=2) {
            sprintf(temp2,"%c%c",part[j],part[j+1]);
            if (!strcmp(temp2,"00")) {
                isNullTerminator++; 
                nullTerminators[numNullTerminators++]=i*(blocksize/2)+j/2;
            } else {
                snprintf(key_part,BUF_MAX,"%s",atohx(temp,temp2,0));
                strcat(ret,key_part);
                (*length)++;
                while (isNullTerminator) {
                    strcat(ret,key_part);
                    isNullTerminator--;
                    (*length)++;
                }
            }
        }
    }
    for (j=0;j<numNullTerminators;j++) {
        ret[nullTerminators[j]]='\0';
    }
    return ret;
}

char*getDigestHex(char*dst,SHA1Context sha,const char*delimiter,unsigned int delimiterSize) {
    char*ret=dst;
    strcpy(ret,"");
    if (!SHA1Result(&sha)) {
        printf("[-] Sha1: could not compute message digest\n");
        exit(1);
    } else {
        int i,j,k;
        char temp[10],part[2],temp2[delimiterSize+1];
        for (i=0;i<sizeof(sha.Message_Digest)/sizeof(*sha.Message_Digest);i++) {
            sprintf(temp,"%08x",sha.Message_Digest[i]);
            if (delimiter!=NULL&&strlen(delimiter)) {
                if (i!=0) {
                    strcat(ret,delimiter);
                }
                for (j=0;j<strlen(temp);j+=delimiterSize) {
                    strcpy(temp2,"");
                    for (k=0;k<delimiterSize;k++) {
                        if (j+k<strlen(temp)) {
                            sprintf(part,"%c",temp[j+k]);
                            strcat(temp2,part);
                        }
                    }
                    strcat(ret,temp2);
                    if (j+delimiterSize<strlen(temp)) {
                        strcat(ret," ");
                    }
                }
            } else {
                strcat(ret,temp);
            }
        }
    }
    return ret;
}

void printDigestHex(const char*msg,SHA1Context sha,const char*delimiter,unsigned int delimiterSize) {
    if (!cmdline_raw&&msg!=NULL&&strlen(msg)>0) {
        printf("%s: ",msg);
    }
    char res[BUF_MAX];
    getDigestHex(res,sha,delimiter,delimiterSize);
    if (res!=NULL&&strlen(res)) {
        printf("%s\n",res);
    }
}

char*SHA1_HMAC(char*dst,char*key_input,char*text_input,const unsigned int print) {
    // TEST case:
    // strcpy(text_input,"15 96 bb 81 12 65 2a 43 e7 bd fb 2f dc 87 99 e5 00 00 00 00 15 96 bb 81 12 65 2a 43 e7 bd fb 2f dc 87 99 e5");
    // strcpy(key_input,"8e 1e 3a 52 36 ab c3 44 55 2d 6e 1a 00 67 1a ed 69 2d 48 25");
    // dst == 167439405b76bdcb62eab21a71e559129cf2cb6d
    char*ret=dst;
    strcpy(ret,"");
    unsigned int inLength=strlen(key_input);
    if (strlen(text_input)<1||inLength<1) {
        printf("[-] Please specify both text and key\n");
        exit(1);
    }
    unsigned int blocksize=64;
    char text[BUF_MAX];
    char temp[BUF_MAX];
    char key[BUF_MAX];
    SHA1Context sha;
    SHA1Context outer;
    SHA1Context inner;
    SHA1Reset(&sha);
    SHA1Reset(&outer);
    SHA1Reset(&inner);
    unsigned int i,rawDigestLength;
    char part[3];
    if (inLength>blocksize) {
        for (i=0;i<inLength;i+=3) {
            sprintf(part,"%c%c",key_input[i],key_input[i+1]);
            SHA1Input(&sha,atohx(temp,part,0),1);
        }
        if (!SHA1Result(&sha)) {
            printf("[-] Sha1: could not compute message digest for %s\n",key_input);
            exit(1);
        } else {
            getRawDigest(sha,key,&rawDigestLength);
        }
    } else {
        atohx(key,key_input,1);
    }
    // add padding if not filled until blocksize
    int curSize=inLength/3+1;
    while (curSize<blocksize) {
        key[curSize]='\0';
        curSize++;
    }
    // 0x5C - 92
    char trans_5C[BUF_MAX_LARGE];
    getTransTable(trans_5C,0x5C);
    char translated_5C[BUF_MAX];
    translate(translated_5C,key,blocksize,trans_5C);
    SHA1Input(&outer,translated_5C,blocksize);
    // 0x36 - 54
    char trans_36[BUF_MAX_LARGE];
    getTransTable(trans_36,0x36);
    char translated_36[BUF_MAX];
    translate(translated_36,key,blocksize,trans_36);
    SHA1Input(&inner,translated_36,blocksize);
    if (text_input!=NULL&&strlen(text_input)>0) {
        atohx(text,text_input,1);
        SHA1Input(&inner,text,strlen(text_input)/3+1);
    }

    if (!SHA1Result(&inner)) {
        printf("[-] Sha1: could not compute message digest for the inner block\n");
        exit(1);
    } else {
        char inner_sha[BUF_MAX];
        getRawDigest(inner,inner_sha,&rawDigestLength);
        SHA1Input(&outer,inner_sha,rawDigestLength);
        if (print) {
            printDigestHex("[+] Resulting SHA1-HMAC",outer," ",2);
        } else {
            getDigestHex(ret,outer," ",2);
        }
    }
    return ret;
}

int recoverWithLibNss(int cmdOptCount,char**cmdOpts) {
	char*profilePath=NULL,*mozDir=NULL,*user=NULL,*pass=NULL,*master=NULL;
    bool fromCmdLine=false;
    int ret=0;
    // check command opts
    if (cmdOptCount>1) {
        int max=cmdOptCount;
        if (max>2) {
            cmdOptCount=0;
            char next[8];
            strcpy(next,"");
            while (++cmdOptCount<max) {
                if (strlen(next)>0) {
                    if (!strcmp(next,"user")) {
				        user=(char*)malloc(strlen(cmdOpts[cmdOptCount])+3);
                        strcpy(user,cmdOpts[cmdOptCount]);
                    } else if (!strcmp(next,"pass")) {
				        pass=(char*)malloc(strlen(cmdOpts[cmdOptCount])+3);
                        strcpy(pass,cmdOpts[cmdOptCount]);
                    } else if (!strcmp(next,"path")) {
				        profilePath=(char*)malloc(strlen(cmdOpts[cmdOptCount])+3);
                        strcpy(profilePath,cmdOpts[cmdOptCount]);
                    } else if (!strcmp(next,"lib")) {
				        mozDir=(char*)malloc(strlen(cmdOpts[cmdOptCount])+3);
                        strcpy(mozDir,cmdOpts[cmdOptCount]);
                    } else if (!strcmp(next,"master")) {
				        master=(char*)malloc(strlen(cmdOpts[cmdOptCount])+3);
                        strcpy(master,cmdOpts[cmdOptCount]);
                    }
                    strcpy(next,"");
                } else if (!strcmp(cmdOpts[cmdOptCount],"-P")||!strcmp(cmdOpts[cmdOptCount],"-profile")||!strcmp(cmdOpts[cmdOptCount],"-path")) {
                    strcpy(next,"path");
                } else if (!strcmp(cmdOpts[cmdOptCount],"-l")||!strcmp(cmdOpts[cmdOptCount],"-lib")) {
                    strcpy(next,"lib");
                } else if (!strcmp(cmdOpts[cmdOptCount],"-u")||!strcmp(cmdOpts[cmdOptCount],"-user")) {
                    strcpy(next,"user");
                } else if (!strcmp(cmdOpts[cmdOptCount],"-p")||!strcmp(cmdOpts[cmdOptCount],"-pass")) {
                    strcpy(next,"pass");
                } else if (!strcmp(cmdOpts[cmdOptCount],"-m")||!strcmp(cmdOpts[cmdOptCount],"-master")) {
                    strcpy(next,"master");
                }
            } 
        }

        if (max>2&&user!=NULL&&pass!=NULL) {
            fromCmdLine=true;
        } else if (!cmdline_raw) {
            printf("[!] User/password command line options were not supplied\n");
        }
    }
    // loop through the list of available TB and FF directories
    bool loop=true;
    while (loop) {
        // check moz profile path
        if (profilePath==NULL||strlen(profilePath)<1) {
            profilePath=getMozProfilePath(1,FF_USER_PATH);
            if (profilePath==NULL||strlen(profilePath)<1) {
                profilePath=getMozProfilePath(0,TB_USER_PATH);
            }
        } else if (!strstr(profilePath,FF_USER_PATH)) {
            loop=false; 
        }
	    if (profilePath&&!dirExists(profilePath)) {
	    	printf("[-] Mozilla profile does not exists, tried with %s\n",profilePath);
	    	ret=1;
	    }
        if (!ret) {
            if (mozDir==NULL||strlen(mozDir)<1) {
                mozDir=getMozLibPath();
            }
        }
	    if (!ret&&initMozLibs(mozDir)) {
	    	if (!initNSSLibrary(profilePath)) {
                if (!fromCmdLine) {
                    char*signonFile=(char*)malloc(sizeof(char)*(strlen(profilePath)+strlen(MOZ_SIGNONS))+3);
                    strcpy(signonFile,profilePath);
                    strcat(signonFile,"/");
                    strcat(signonFile,MOZ_SIGNONS);
	    		    decryptSQLite(signonFile,master);
                } else {
                    decryptCmdLine(user,pass,master);
                }
	    	}
	    } else if (!ret) {
            if (!cmdline_raw) {
                printf("[-] Failed to initialize Mozilla libraries. Please check the lib path (-l or MOZ_DEFAULT_LIB_PATH)\n");
                printf("    and/or dependencies.\n");
                ret=1;
            }
        }

        if (strstr(profilePath,FF_USER_PATH)!=NULL) {
            if (profilePath) {
                free(profilePath);
            }
            profilePath=getMozProfilePath(0,TB_USER_PATH);
            NSSUnload(); // we need to RELOAD it for other paths
            if (!cmdline_raw) {
                printf("\n\n"); 
            }
        } else {
            loop=false;
        }
        if (!profilePath||strlen(profilePath)<1) {
            loop=false;
        }
    }
    // yes also some cleanup is needed of course
    if (user) {
        free(user); 
    }
    if (pass) {
        free(pass); 
    }
    if (mozDir) {
        free(mozDir); 
    }
    if (master) {
        free(master); 
    }
	return ret;
}

unsigned int ASN1GetNum(const char*element) {
    unsigned int ret=-1;
    if (ASN1_NAMES==NULL||element==NULL||strlen(element)<1) {
        return ret;
    }
    unsigned int i,max=sizeof(ASN1_NAMES)/sizeof(char**);
    for (i=0;i<max;i++) {
        if (!strcmp(ASN1_NAMES[i],element)) {
            ret=i+1; 
            break;
        }
    }
    return ret;
}

char*ASN1GetName(char*dst,const char num) {
    char*ret=dst;
    strcpy(ret,"");
    if (ASN1_NAMES==NULL) {
        return ret;
    }
    if (num>=1&&num<=sizeof(ASN1_NAMES)/sizeof(char**)) {
        strncpy(ret,ASN1_NAMES[num-1],BUF_MAX);
    }
    if (strlen(ret)<1) {
        strncpy(ret,ASN1_NAMES[ASN1_DEFAULT_NAME-1],BUF_MAX);
    }
    return ret;
}

void ASN1PrintLine(const char*text,const unsigned int num,bool newline) {
    int i;
    for (i=0;i<num*ASN1_INDENTATION;i++) {
        printf(" ");
    }
    printf("%s",text);
    if (newline) {
        printf("\n");
    } else {
        printf(" ");
    }
}

void ASN1Print(const char*encoded,bool decode,const unsigned int maxSize,const unsigned int indentation) {
    unsigned int tempLength;
    if (maxSize>0) {
        tempLength=maxSize; 
    } else {
        tempLength=strlen(encoded); 
    }
    char temp[tempLength+1];
    unsigned long max=0;
    if (decode) {
        if (encoded==NULL||strlen(encoded)<3) {
            printf("[-] ASN.1 text was NOT specified. Abort\n"); 
            return;
        } 
        atohx(temp,encoded,1);
        int i;
        if (encoded[2]!=' ' ||strlen(encoded)<(unsigned char)temp[1]) {
            printf("[-] ASN.1 input string seems to be NOT valid. The format must be in hexadecimal (e.g. \"30 12 01 ...\")\n"); 
            return;
        }
        max=strlen(encoded)/3;
    } else {
        int j;
        strcpy(temp,"");
        char temp2[3];
        int isNullTerminator=0;
        unsigned int numNullTerminators=0;
        unsigned nullTerminators[maxSize];
        int i;
        for (j=0;j<maxSize;j++) {
            if (encoded[j]!='\0') {
                sprintf(temp2,"%c",encoded[j]);
                strcat(temp,temp2);
                while (isNullTerminator) {
                    strcat(temp,temp2);
                    isNullTerminator--;
                }
            } else {
                isNullTerminator++; 
                nullTerminators[numNullTerminators++]=j;
            }
        }
        for (j=0;j<numNullTerminators;j++) {
            temp[nullTerminators[j]]='\0';
        }
        max=maxSize;
    }
    unsigned long pos=0,k=0;
    unsigned char length;
    char type[BUF_MAX],value[BUF_MAX_SMALL],tempASN1Name[BUF_MAX];
    while (pos<max) {
        // header
        strncpy(type,ASN1GetName(tempASN1Name,(unsigned char)temp[pos++]),BUF_MAX);
        // respect the TLV definition: see http://en.wikipedia.org/wiki/Basic_Encoding_Rules
        // check the L (length) of TLV (type,length,value)
        length=temp[pos++];
        if (length>127) { // 0x7F 0b1111111
            int i,max=length&0x7F; // the amount of bytes used for value indication
            length=0;
            for (i=0;i<max;i++) {
                length+=(unsigned char)temp[pos++];
            }
        }
        if (length>max) {
            length=max-1; 
        }
        if  (!strcmp(type,ASN1_NAMES[ASN1_SEQUENCE-1])) {
            // nested - recursive
            ASN1PrintLine(type,indentation,0);
            ASN1PrintLine("{",0,1);
            ASN1Print(temp+pos,0,length,indentation+1);
            ASN1PrintLine("}",indentation,1);
        } else {
            // print value
            ASN1PrintLine(type,indentation,0);
            if (!strcmp(type,ASN1_NAMES[ASN1_NULL-1])) {
                while (temp[pos-1]!='0') {
                    pos++;
                }
                // NULL value does NOT need to be printed
                pos-=length; // to prevent pos+=length to take effect
            } else if (!strcmp(type,ASN1_NAMES[ASN1_BOOLEAN-1])) {
                snprintf(value,4,"%02x",(unsigned char)temp[pos-1]);
                ASN1PrintLine(value,0,0);
                pos-=length; // to prevent pos+=length to take effect
            } else {
                for (k=0;k<length;k++) {
                    snprintf(value,4,"%02x",(unsigned char)temp[pos+k]);
                    ASN1PrintLine(value,0,0);
                }
            }
            ASN1PrintLine("",indentation,1);
        }
        pos+=length;
    }
}

char*ASN1GetElement(char*dst,const char*encoded,bool decode,const unsigned int maxSize,const unsigned int searchType,unsigned int*num) {
    char*ret=dst;
    strcpy(ret,"");
    if (*num<1) {
        return dst; 
    }
    unsigned int tempLength;
    if (maxSize>0) {
        tempLength=maxSize; 
    } else {
        tempLength=strlen(encoded); 
    }
    char temp[tempLength+1];
    unsigned long max;
    if (decode) {
        if (encoded==NULL||strlen(encoded)<3) {
            printf("[-] ASN.1 text missing. Abort\n"); 
            return ret; 
        } 
        atohx(temp,encoded,1);
        if (encoded[2]!=' ' ||strlen(encoded)<(unsigned char)temp[1]) {
            printf("[-] ASN.1 string seems to be NOT valid. The format is incorrect\n"); 
            return ret;
        }
        max=strlen(encoded)/3;
    } else {
        int j;
        strcpy(temp,"");
        char temp2[3];
        int isNullTerminator=0;
        unsigned int numNullTerminators=0;
        unsigned nullTerminators[maxSize];
        for (j=0;j<maxSize;j++) {
            if (encoded[j]!=0) {
                sprintf(temp2,"%c",encoded[j]);
                strcat(temp,temp2);
                while (isNullTerminator) {
                    strcat(temp,temp2);
                    isNullTerminator--;
                }
            } 
            else {
                isNullTerminator++; 
                nullTerminators[numNullTerminators++]=j;
            }
        }
        for (j=0;j<numNullTerminators;j++) {
            temp[nullTerminators[j]]='\0';
        }
        max=maxSize;
    }
    unsigned long pos=0;
    unsigned char length;
    char type[BUF_MAX],value[BUF_MAX_SMALL],tempASN1Name[BUF_MAX],*result;
    while (pos<max) {
        // header
        strncpy(type,ASN1GetName(tempASN1Name,temp[pos++]),BUF_MAX);
        length=temp[pos++];
        if (length>127) { // 0x7F 0b1111111
            int i,max=length&0x7F; // the amount of bytes used for value indication
            length=0;
            for (i=0;i<max;i++) {
                length+=(unsigned char)temp[pos++];
            }
        }
        if (length>max) {   // a bit hacky? something strange that this can happen,isn't it
            length=max-1; 
        }
        if  (!strcmp(type,ASN1_NAMES[ASN1_SEQUENCE-1])) {
            ASN1GetElement(ret,temp+pos,0,length,searchType,num);
            if (ret!=NULL&&strlen(ret)>0) {
                break;
            }
        } else if (searchType==temp[pos-2]) {
            if ((--(*num))==0) {
                strcpy(ret,"");
                if (!strcmp(type,ASN1_NAMES[ASN1_NULL-1])) {
                    while (temp[pos-1]!='0') {
                        pos++;
                    }
                    snprintf(value,4,"");
                    strcat(ret,value);
                } else if (!strcmp(type,ASN1_NAMES[ASN1_BOOLEAN-1])) {
                    snprintf(value,4,"%02x",(unsigned char)temp[pos-1]);
                    strcat(ret,value);
                } else {
                    unsigned long k=0;
                    for (k=0;k<length&&k+pos<max;k++) {
                        if (k!=0) {
                            strcat(ret," ");
                        }
                        snprintf(value,4,"%02x",(unsigned char)temp[pos+k]);
                        strcat(ret,value);
                    }
                }
                break;
            } 
        }
        pos+=length;
    }
    return ret;
}

void printASN1Structure(const unsigned int argc,char**argv) {
    unsigned int max=argc,argsCount=1;
    char text_input[BUF_MAX_LARGE];
    strcpy(text_input,"");

    while (++argsCount<max) {
        if (argv[argsCount][0]=='-') {
            printf("[!] Unknown option to ASN.1 parser. %s option skipped\n",argv[argsCount]);
        } else {
            strncpy(text_input,argv[argsCount],BUF_MAX_LARGE-1);
            break;
        }
    }
    if (text_input!=NULL&&strlen(text_input)>1) {
        ASN1Print(text_input,1,0,0);
    } else {
        printf("[-] Comand line options NOT correct. ASN.1 text was NOT specified\n");
        exit(1); 
    }
}

/* DES EDE (ENCRYPT DECRYPT ENCRYPT) 3 - CBC (Cipher Block Chaining) */
#if __x86_64__
#define DES_LONG unsigned int
#else 
#define DES_LONG unsigned long  // Not 64 bit
#endif

#define DES_ENCRYPT 1
#define DES_DECRYPT 0

#if defined(__i386)||defined(__i386__)||defined(__x86_64)||defined(__x86_64__)
#define ROTATE(a,n) ({ \
    register unsigned int ret; \
    asm ("rorl %1,%0" \
         :"=r"(ret) \
         :"I"(n),"0"(a) \
         :"cc"); \
    ret; \
})
#else
#define ROTATE(a,n) (((a)>>(n))+((a)<<(32-(n))))
#endif

#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
    u=R^s[S]; \
    t=R^s[S+1]
#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define ENCRYPT(LL,R,S) { \
    LOAD_DATA_tmp(R,S,u,t,E0,E1); \
    t=ROTATE(t,4); \
    LL^= \
    *(const DES_LONG *)(des_SP+((u)&0xfc))^ \
    *(const DES_LONG *)(des_SP+0x200+((u>> 8L)&0xfc))^ \
    *(const DES_LONG *)(des_SP+0x400+((u>>16L)&0xfc))^ \
    *(const DES_LONG *)(des_SP+0x600+((u>>24L)&0xfc))^ \
    *(const DES_LONG *)(des_SP+0x100+((t)&0xfc))^ \
    *(const DES_LONG *)(des_SP+0x300+((t>> 8L)&0xfc))^ \
    *(const DES_LONG *)(des_SP+0x500+((t>>16L)&0xfc))^ \
    *(const DES_LONG *)(des_SP+0x700+((t>>24L)&0xfc)); \
}
#define c2l(c,l) ( \
    l=((DES_LONG)(*((c)++))), \
    l|=((DES_LONG)(*((c)++)))<< 8L, \
    l|=((DES_LONG)(*((c)++)))<<16L, \
    l|=((DES_LONG)(*((c)++)))<<24L \
)
#define l2c(l,c) ( \
    *((c)++)=(unsigned char)(((l))&0xff), \
    *((c)++)=(unsigned char)(((l)>>8L)&0xff), \
    *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
    *((c)++)=(unsigned char)(((l)>>24L)&0xff) \
)
#define l2cn(l1,l2,c,n) { \
    c+=n; \
    switch (n) { \
        case 8: *(--(c))=(unsigned char)(((l2)>>24L)&0xff); \
        case 7: *(--(c))=(unsigned char)(((l2)>>16L)&0xff); \
        case 6: *(--(c))=(unsigned char)(((l2)>> 8L)&0xff); \
        case 5: *(--(c))=(unsigned char)(((l2))&0xff); \
        case 4: *(--(c))=(unsigned char)(((l1)>>24L)&0xff); \
        case 3: *(--(c))=(unsigned char)(((l1)>>16L)&0xff); \
        case 2: *(--(c))=(unsigned char)(((l1)>> 8L)&0xff); \
        case 1: *(--(c))=(unsigned char)(((l1))&0xff); \
    } \
}
#define PERM_OP(a,b,t,n,m) ( \
    (t)=((((a)>>(n))^(b))&(m)), \
    (b)^=(t), \
    (a)^=((t)<<(n)) \
)
#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)), \
    (a)=(a)^(t)^(t>>(16-(n))))
#define IP(l,r) { \
    register DES_LONG tt; \
    PERM_OP(r,l,tt,4,0x0f0f0f0fL); \
    PERM_OP(l,r,tt,16,0x0000ffffL); \
    PERM_OP(r,l,tt,2,0x33333333L); \
    PERM_OP(l,r,tt,8,0x00ff00ffL); \
    PERM_OP(r,l,tt,1,0x55555555L); \
}
#define FP(l,r) { \
    register DES_LONG tt; \
    PERM_OP(l,r,tt,1,0x55555555L); \
    PERM_OP(r,l,tt,8,0x00ff00ffL); \
    PERM_OP(l,r,tt,2,0x33333333L); \
    PERM_OP(r,l,tt,16,0x0000ffffL); \
    PERM_OP(l,r,tt,4,0x0f0f0f0fL); \
}

const DES_LONG trans[8][64]={{
    0x02080800L,0x00080000L,0x02000002L,0x02080802L,0x02000000L,0x00080802L,0x00080002L,0x02000002L,
    0x00080802L,0x02080800L,0x02080000L,0x00000802L,0x02000802L,0x02000000L,0x00000000L,0x00080002L,
    0x00080000L,0x00000002L,0x02000800L,0x00080800L,0x02080802L,0x02080000L,0x00000802L,0x02000800L,
    0x00000002L,0x00000800L,0x00080800L,0x02080002L,0x00000800L,0x02000802L,0x02080002L,0x00000000L,
    0x00000000L,0x02080802L,0x02000800L,0x00080002L,0x02080800L,0x00080000L,0x00000802L,0x02000800L,
    0x02080002L,0x00000800L,0x00080800L,0x02000002L,0x00080802L,0x00000002L,0x02000002L,0x02080000L,
    0x02080802L,0x00080800L,0x02080000L,0x02000802L,0x02000000L,0x00000802L,0x00080002L,0x00000000L,
    0x00080000L,0x02000000L,0x02000802L,0x02080800L,0x00000002L,0x02080002L,0x00000800L,0x00080802L,
    },{
    0x40108010L,0x00000000L,0x00108000L,0x40100000L,0x40000010L,0x00008010L,0x40008000L,0x00108000L,
    0x00008000L,0x40100010L,0x00000010L,0x40008000L,0x00100010L,0x40108000L,0x40100000L,0x00000010L,
    0x00100000L,0x40008010L,0x40100010L,0x00008000L,0x00108010L,0x40000000L,0x00000000L,0x00100010L,
    0x40008010L,0x00108010L,0x40108000L,0x40000010L,0x40000000L,0x00100000L,0x00008010L,0x40108010L,
    0x00100010L,0x40108000L,0x40008000L,0x00108010L,0x40108010L,0x00100010L,0x40000010L,0x00000000L,
    0x40000000L,0x00008010L,0x00100000L,0x40100010L,0x00008000L,0x40000000L,0x00108010L,0x40008010L,
    0x40108000L,0x00008000L,0x00000000L,0x40000010L,0x00000010L,0x40108010L,0x00108000L,0x40100000L,
    0x40100010L,0x00100000L,0x00008010L,0x40008000L,0x40008010L,0x00000010L,0x40100000L,0x00108000L,
    },{
    0x04000001L,0x04040100L,0x00000100L,0x04000101L,0x00040001L,0x04000000L,0x04000101L,0x00040100L,
    0x04000100L,0x00040000L,0x04040000L,0x00000001L,0x04040101L,0x00000101L,0x00000001L,0x04040001L,
    0x00000000L,0x00040001L,0x04040100L,0x00000100L,0x00000101L,0x04040101L,0x00040000L,0x04000001L,
    0x04040001L,0x04000100L,0x00040101L,0x04040000L,0x00040100L,0x00000000L,0x04000000L,0x00040101L,
    0x04040100L,0x00000100L,0x00000001L,0x00040000L,0x00000101L,0x00040001L,0x04040000L,0x04000101L,
    0x00000000L,0x04040100L,0x00040100L,0x04040001L,0x00040001L,0x04000000L,0x04040101L,0x00000001L,
    0x00040101L,0x04000001L,0x04000000L,0x04040101L,0x00040000L,0x04000100L,0x04000101L,0x00040100L,
    0x04000100L,0x00000000L,0x04040001L,0x00000101L,0x04000001L,0x00040101L,0x00000100L,0x04040000L,
    },{
    0x00401008L,0x10001000L,0x00000008L,0x10401008L,0x00000000L,0x10400000L,0x10001008L,0x00400008L,
    0x10401000L,0x10000008L,0x10000000L,0x00001008L,0x10000008L,0x00401008L,0x00400000L,0x10000000L,
    0x10400008L,0x00401000L,0x00001000L,0x00000008L,0x00401000L,0x10001008L,0x10400000L,0x00001000L,
    0x00001008L,0x00000000L,0x00400008L,0x10401000L,0x10001000L,0x10400008L,0x10401008L,0x00400000L,
    0x10400008L,0x00001008L,0x00400000L,0x10000008L,0x00401000L,0x10001000L,0x00000008L,0x10400000L,
    0x10001008L,0x00000000L,0x00001000L,0x00400008L,0x00000000L,0x10400008L,0x10401000L,0x00001000L,
    0x10000000L,0x10401008L,0x00401008L,0x00400000L,0x10401008L,0x00000008L,0x10001000L,0x00401008L,
    0x00400008L,0x00401000L,0x10400000L,0x10001008L,0x00001008L,0x10000000L,0x10000008L,0x10401000L,
    },{
    0x08000000L,0x00010000L,0x00000400L,0x08010420L,0x08010020L,0x08000400L,0x00010420L,0x08010000L,
    0x00010000L,0x00000020L,0x08000020L,0x00010400L,0x08000420L,0x08010020L,0x08010400L,0x00000000L,
    0x00010400L,0x08000000L,0x00010020L,0x00000420L,0x08000400L,0x00010420L,0x00000000L,0x08000020L,
    0x00000020L,0x08000420L,0x08010420L,0x00010020L,0x08010000L,0x00000400L,0x00000420L,0x08010400L,
    0x08010400L,0x08000420L,0x00010020L,0x08010000L,0x00010000L,0x00000020L,0x08000020L,0x08000400L,
    0x08000000L,0x00010400L,0x08010420L,0x00000000L,0x00010420L,0x08000000L,0x00000400L,0x00010020L,
    0x08000420L,0x00000400L,0x00000000L,0x08010420L,0x08010020L,0x08010400L,0x00000420L,0x00010000L,
    0x00010400L,0x08010020L,0x08000400L,0x00000420L,0x00000020L,0x00010420L,0x08010000L,0x08000020L,
    },{
    0x80000040L,0x00200040L,0x00000000L,0x80202000L,0x00200040L,0x00002000L,0x80002040L,0x00200000L,
    0x00002040L,0x80202040L,0x00202000L,0x80000000L,0x80002000L,0x80000040L,0x80200000L,0x00202040L,
    0x00200000L,0x80002040L,0x80200040L,0x00000000L,0x00002000L,0x00000040L,0x80202000L,0x80200040L,
    0x80202040L,0x80200000L,0x80000000L,0x00002040L,0x00000040L,0x00202000L,0x00202040L,0x80002000L,
    0x00002040L,0x80000000L,0x80002000L,0x00202040L,0x80202000L,0x00200040L,0x00000000L,0x80002000L,
    0x80000000L,0x00002000L,0x80200040L,0x00200000L,0x00200040L,0x80202040L,0x00202000L,0x00000040L,
    0x80202040L,0x00202000L,0x00200000L,0x80002040L,0x80000040L,0x80200000L,0x00202040L,0x00000000L,
    0x00002000L,0x80000040L,0x80002040L,0x80202000L,0x80200000L,0x00002040L,0x00000040L,0x80200040L,
    },{
    0x00004000L,0x00000200L,0x01000200L,0x01000004L,0x01004204L,0x00004004L,0x00004200L,0x00000000L,
    0x01000000L,0x01000204L,0x00000204L,0x01004000L,0x00000004L,0x01004200L,0x01004000L,0x00000204L,
    0x01000204L,0x00004000L,0x00004004L,0x01004204L,0x00000000L,0x01000200L,0x01000004L,0x00004200L,
    0x01004004L,0x00004204L,0x01004200L,0x00000004L,0x00004204L,0x01004004L,0x00000200L,0x01000000L,
    0x00004204L,0x01004000L,0x01004004L,0x00000204L,0x00004000L,0x00000200L,0x01000000L,0x01004004L,
    0x01000204L,0x00004204L,0x00004200L,0x00000000L,0x00000200L,0x01000004L,0x00000004L,0x01000200L,
    0x00000000L,0x01000204L,0x01000200L,0x00004200L,0x00000204L,0x00004000L,0x01004204L,0x01000000L,
    0x01004200L,0x00000004L,0x00004004L,0x01004204L,0x01000004L,0x01004200L,0x01004000L,0x00004004L,
    },{
    0x20800080L,0x20820000L,0x00020080L,0x00000000L,0x20020000L,0x00800080L,0x20800000L,0x20820080L,
    0x00000080L,0x20000000L,0x00820000L,0x00020080L,0x00820080L,0x20020080L,0x20000080L,0x20800000L,
    0x00020000L,0x00820080L,0x00800080L,0x20020000L,0x20820080L,0x20000080L,0x00000000L,0x00820000L,
    0x20000000L,0x00800000L,0x20020080L,0x20800080L,0x00800000L,0x00020000L,0x20820000L,0x00000080L,
    0x00800000L,0x00020000L,0x20000080L,0x20820080L,0x00020080L,0x20000000L,0x00000000L,0x00820000L,
    0x20800080L,0x20020080L,0x20020000L,0x00800080L,0x20820000L,0x00000080L,0x00800080L,0x20020000L,
    0x20820080L,0x00800000L,0x20800000L,0x20000080L,0x00820000L,0x00020080L,0x20020080L,0x20800000L,
    0x00000080L,0x20820000L,0x00820080L,0x00000000L,0x20000000L,0x20800080L,0x00020000L,0x00820080L,
}};

static const DES_LONG skb[8][64]={{
    0x00000000L,0x00000010L,0x20000000L,0x20000010L,0x00010000L,0x00010010L,0x20010000L,0x20010010L,
    0x00000800L,0x00000810L,0x20000800L,0x20000810L,0x00010800L,0x00010810L,0x20010800L,0x20010810L,
    0x00000020L,0x00000030L,0x20000020L,0x20000030L,0x00010020L,0x00010030L,0x20010020L,0x20010030L,
    0x00000820L,0x00000830L,0x20000820L,0x20000830L,0x00010820L,0x00010830L,0x20010820L,0x20010830L,
    0x00080000L,0x00080010L,0x20080000L,0x20080010L,0x00090000L,0x00090010L,0x20090000L,0x20090010L,
    0x00080800L,0x00080810L,0x20080800L,0x20080810L,0x00090800L,0x00090810L,0x20090800L,0x20090810L,
    0x00080020L,0x00080030L,0x20080020L,0x20080030L,0x00090020L,0x00090030L,0x20090020L,0x20090030L,
    0x00080820L,0x00080830L,0x20080820L,0x20080830L,0x00090820L,0x00090830L,0x20090820L,0x20090830L,
    },{
    0x00000000L,0x02000000L,0x00002000L,0x02002000L,0x00200000L,0x02200000L,0x00202000L,0x02202000L,
    0x00000004L,0x02000004L,0x00002004L,0x02002004L,0x00200004L,0x02200004L,0x00202004L,0x02202004L,
    0x00000400L,0x02000400L,0x00002400L,0x02002400L,0x00200400L,0x02200400L,0x00202400L,0x02202400L,
    0x00000404L,0x02000404L,0x00002404L,0x02002404L,0x00200404L,0x02200404L,0x00202404L,0x02202404L,
    0x10000000L,0x12000000L,0x10002000L,0x12002000L,0x10200000L,0x12200000L,0x10202000L,0x12202000L,
    0x10000004L,0x12000004L,0x10002004L,0x12002004L,0x10200004L,0x12200004L,0x10202004L,0x12202004L,
    0x10000400L,0x12000400L,0x10002400L,0x12002400L,0x10200400L,0x12200400L,0x10202400L,0x12202400L,
    0x10000404L,0x12000404L,0x10002404L,0x12002404L,0x10200404L,0x12200404L,0x10202404L,0x12202404L,
    },{
    0x00000000L,0x00000001L,0x00040000L,0x00040001L,0x01000000L,0x01000001L,0x01040000L,0x01040001L,
    0x00000002L,0x00000003L,0x00040002L,0x00040003L,0x01000002L,0x01000003L,0x01040002L,0x01040003L,
    0x00000200L,0x00000201L,0x00040200L,0x00040201L,0x01000200L,0x01000201L,0x01040200L,0x01040201L,
    0x00000202L,0x00000203L,0x00040202L,0x00040203L,0x01000202L,0x01000203L,0x01040202L,0x01040203L,
    0x08000000L,0x08000001L,0x08040000L,0x08040001L,0x09000000L,0x09000001L,0x09040000L,0x09040001L,
    0x08000002L,0x08000003L,0x08040002L,0x08040003L,0x09000002L,0x09000003L,0x09040002L,0x09040003L,
    0x08000200L,0x08000201L,0x08040200L,0x08040201L,0x09000200L,0x09000201L,0x09040200L,0x09040201L,
    0x08000202L,0x08000203L,0x08040202L,0x08040203L,0x09000202L,0x09000203L,0x09040202L,0x09040203L,
    },{
    0x00000000L,0x00100000L,0x00000100L,0x00100100L,0x00000008L,0x00100008L,0x00000108L,0x00100108L,
    0x00001000L,0x00101000L,0x00001100L,0x00101100L,0x00001008L,0x00101008L,0x00001108L,0x00101108L,
    0x04000000L,0x04100000L,0x04000100L,0x04100100L,0x04000008L,0x04100008L,0x04000108L,0x04100108L,
    0x04001000L,0x04101000L,0x04001100L,0x04101100L,0x04001008L,0x04101008L,0x04001108L,0x04101108L,
    0x00020000L,0x00120000L,0x00020100L,0x00120100L,0x00020008L,0x00120008L,0x00020108L,0x00120108L,
    0x00021000L,0x00121000L,0x00021100L,0x00121100L,0x00021008L,0x00121008L,0x00021108L,0x00121108L,
    0x04020000L,0x04120000L,0x04020100L,0x04120100L,0x04020008L,0x04120008L,0x04020108L,0x04120108L,
    0x04021000L,0x04121000L,0x04021100L,0x04121100L,0x04021008L,0x04121008L,0x04021108L,0x04121108L,
    },{
    0x00000000L,0x10000000L,0x00010000L,0x10010000L,0x00000004L,0x10000004L,0x00010004L,0x10010004L,
    0x20000000L,0x30000000L,0x20010000L,0x30010000L,0x20000004L,0x30000004L,0x20010004L,0x30010004L,
    0x00100000L,0x10100000L,0x00110000L,0x10110000L,0x00100004L,0x10100004L,0x00110004L,0x10110004L,
    0x20100000L,0x30100000L,0x20110000L,0x30110000L,0x20100004L,0x30100004L,0x20110004L,0x30110004L,
    0x00001000L,0x10001000L,0x00011000L,0x10011000L,0x00001004L,0x10001004L,0x00011004L,0x10011004L,
    0x20001000L,0x30001000L,0x20011000L,0x30011000L,0x20001004L,0x30001004L,0x20011004L,0x30011004L,
    0x00101000L,0x10101000L,0x00111000L,0x10111000L,0x00101004L,0x10101004L,0x00111004L,0x10111004L,
    0x20101000L,0x30101000L,0x20111000L,0x30111000L,0x20101004L,0x30101004L,0x20111004L,0x30111004L,
    },{
    0x00000000L,0x08000000L,0x00000008L,0x08000008L,0x00000400L,0x08000400L,0x00000408L,0x08000408L,
    0x00020000L,0x08020000L,0x00020008L,0x08020008L,0x00020400L,0x08020400L,0x00020408L,0x08020408L,
    0x00000001L,0x08000001L,0x00000009L,0x08000009L,0x00000401L,0x08000401L,0x00000409L,0x08000409L,
    0x00020001L,0x08020001L,0x00020009L,0x08020009L,0x00020401L,0x08020401L,0x00020409L,0x08020409L,
    0x02000000L,0x0A000000L,0x02000008L,0x0A000008L,0x02000400L,0x0A000400L,0x02000408L,0x0A000408L,
    0x02020000L,0x0A020000L,0x02020008L,0x0A020008L,0x02020400L,0x0A020400L,0x02020408L,0x0A020408L,
    0x02000001L,0x0A000001L,0x02000009L,0x0A000009L,0x02000401L,0x0A000401L,0x02000409L,0x0A000409L,
    0x02020001L,0x0A020001L,0x02020009L,0x0A020009L,0x02020401L,0x0A020401L,0x02020409L,0x0A020409L,
    },{
    0x00000000L,0x00000100L,0x00080000L,0x00080100L,0x01000000L,0x01000100L,0x01080000L,0x01080100L,
    0x00000010L,0x00000110L,0x00080010L,0x00080110L,0x01000010L,0x01000110L,0x01080010L,0x01080110L,
    0x00200000L,0x00200100L,0x00280000L,0x00280100L,0x01200000L,0x01200100L,0x01280000L,0x01280100L,
    0x00200010L,0x00200110L,0x00280010L,0x00280110L,0x01200010L,0x01200110L,0x01280010L,0x01280110L,
    0x00000200L,0x00000300L,0x00080200L,0x00080300L,0x01000200L,0x01000300L,0x01080200L,0x01080300L,
    0x00000210L,0x00000310L,0x00080210L,0x00080310L,0x01000210L,0x01000310L,0x01080210L,0x01080310L,
    0x00200200L,0x00200300L,0x00280200L,0x00280300L,0x01200200L,0x01200300L,0x01280200L,0x01280300L,
    0x00200210L,0x00200310L,0x00280210L,0x00280310L,0x01200210L,0x01200310L,0x01280210L,0x01280310L,
    },{
    0x00000000L,0x04000000L,0x00040000L,0x04040000L,0x00000002L,0x04000002L,0x00040002L,0x04040002L,
    0x00002000L,0x04002000L,0x00042000L,0x04042000L,0x00002002L,0x04002002L,0x00042002L,0x04042002L,
    0x00000020L,0x04000020L,0x00040020L,0x04040020L,0x00000022L,0x04000022L,0x00040022L,0x04040022L,
    0x00002020L,0x04002020L,0x00042020L,0x04042020L,0x00002022L,0x04002022L,0x00042022L,0x04042022L,
    0x00000800L,0x04000800L,0x00040800L,0x04040800L,0x00000802L,0x04000802L,0x00040802L,0x04040802L,
    0x00002800L,0x04002800L,0x00042800L,0x04042800L,0x00002802L,0x04002802L,0x00042802L,0x04042802L,
    0x00000820L,0x04000820L,0x00040820L,0x04040820L,0x00000822L,0x04000822L,0x00040822L,0x04040822L,
    0x00002820L,0x04002820L,0x00042820L,0x04042820L,0x00002822L,0x04002822L,0x00042822L,0x04042822L,
}};

typedef unsigned char DES_cblock[MOZ_IV_SIZE];
typedef struct DES_ks {
    union {
        DES_cblock cblock;
        DES_LONG deslong[2];
    } ks[16];
} DES_key_schedule;

void desSetKey(DES_cblock*key,DES_key_schedule*schedule) {
    static const int shifts2[16]={0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};
    register DES_LONG c,d,t,s,t2;
    register int i;
    register const unsigned char*in=&(*key)[0];
    register DES_LONG*k=&schedule->ks->deslong[0];
    c2l(in,c);
    c2l(in,d);
    PERM_OP(d,c,t,4,0x0f0f0f0fL);
    HPERM_OP(c,t,-2,0xcccc0000L);
    HPERM_OP(d,t,-2,0xcccc0000L);
    PERM_OP(d,c,t,1,0x55555555L);
    PERM_OP(c,d,t,8,0x00ff00ffL);
    PERM_OP(d,c,t,1,0x55555555L);
    d=(((d&0x000000ffL)<<16L)|(d&0x0000ff00L)|
       ((d&0x00ff0000L)>>16L)|((c&0xf0000000L)>>4L));
    c&=0x0fffffffL;
    for (i=0;i<16;i++) {
        if (shifts2[i]) {
            c=((c>>2L)|(c<<26L)); d=((d>>2L)|(d<<26L)); 
        } else {
            c=((c>>1L)|(c<<27L)); d=((d>>1L)|(d<<27L));
        }
        c&=0x0fffffffL;
        d&=0x0fffffffL;
        s=skb[0][(c)&0x3f]|
          skb[1][((c>> 6L)&0x03)|((c>> 7L)&0x3c)]|
          skb[2][((c>>13L)&0x0f)|((c>>14L)&0x30)]|
          skb[3][((c>>20L)&0x01)|((c>>21L)&0x06)|
                        ((c>>22L)&0x38)];
        t=skb[4][(d)&0x3f]|
          skb[5][((d>>7L)&0x03)|((d>> 8L)&0x3c)]|
          skb[6][(d>>15L)&0x3f]|
          skb[7][((d>>21L)&0x0f)|((d>>22L)&0x30)];
        t2=((t<<16L)|(s&0x0000ffffL))&0xffffffffL;
        *(k++)=ROTATE(t2,30)&0xffffffffL;
        t2=((s>>16L)|(t&0xffff0000L));
        *(k++)=ROTATE(t2,26)&0xffffffffL;
    }
}

void desDecrypt2(DES_LONG*data,DES_key_schedule*ks,int enc) {
    register DES_LONG l,r,t,u;
    register const unsigned char*des_SP=(const unsigned char*)trans;
    register int i;
    register DES_LONG*s;
    r=data[0];
    l=data[1];
    r=ROTATE(r,29)&0xffffffffL;
    l=ROTATE(l,29)&0xffffffffL;
    s=ks->ks->deslong;
    if (enc) {
        for (i=0;i<32;i+=4) {
            ENCRYPT(l,r,i+0);
            ENCRYPT(r,l,i+2);
        }
    } else {
        for (i=30;i>0;i-=4) {
            ENCRYPT(l,r,i-0);
            ENCRYPT(r,l,i-2);
        }
    }
    data[0]=ROTATE(l,3)&0xffffffffL;
    data[1]=ROTATE(r,3)&0xffffffffL;
    l=r=t=u=0;
}

void desDecrypt(DES_LONG*data,DES_key_schedule*ks1,DES_key_schedule*ks2,DES_key_schedule*ks3) {
    register DES_LONG l,r;
    l=data[0];
    r=data[1];
    IP(l,r);
    data[0]=l;
    data[1]=r;
    desDecrypt2((DES_LONG*)data,ks3,DES_DECRYPT);
    desDecrypt2((DES_LONG*)data,ks2,DES_ENCRYPT);
    desDecrypt2((DES_LONG*)data,ks1,DES_DECRYPT);
    l=data[0];
    r=data[1];
    FP(r,l);
    data[0]=l;
    data[1]=r;
}

char*decrypt(const char*i,char*output,char*k,char*ivIn,unsigned int*outlen) {
    char*ret=output;
    strcpy(output,"");
    register DES_LONG tin0,tin1;
    register DES_LONG tout0,tout1,xor0,xor1;
    const unsigned long length=strlen(i)/3;
    char input[length+1];
    atohx(input,i,1);
    register const unsigned char*in=(unsigned char*)input;
    register long l=length;
    unsigned char*out=(unsigned char*)output;
    char ivec_str[MOZ_IV_SIZE];
    atohx(ivec_str,ivIn,1);
    DES_cblock*ivec=(DES_cblock*)ivec_str;
    unsigned char*iv=&(*ivec)[0];
    const unsigned long keysize=strlen(k)/3;
    char key[keysize+1];
    atohx(key,k,1);
    DES_cblock*deskey=(DES_cblock*)key;
    DES_key_schedule*ks1=(DES_key_schedule*)malloc(sizeof(*ks1));
    desSetKey(&deskey[0],ks1);
    DES_key_schedule*ks2=(DES_key_schedule*)malloc(sizeof(*ks2));
    desSetKey(&deskey[1],ks2);
    DES_key_schedule*ks3=(DES_key_schedule*)malloc(sizeof(*ks3));
    desSetKey(&deskey[2],ks3);
    register DES_LONG t0,t1;
    DES_LONG tin[2];
    c2l(iv,xor0);
    c2l(iv,xor1);
    for (l-=8;l>=0;l-=8) {
        c2l(in,tin0);
        c2l(in,tin1);
        t0=tin0;
        t1=tin1;
        tin[0]=tin0;
        tin[1]=tin1;
        desDecrypt((DES_LONG*)tin,ks1,ks2,ks3);
        tout0=tin[0];
        tout1=tin[1];
        tout0^=xor0;
        tout1^=xor1;
        l2c(tout0,out);
        l2c(tout1,out);
        xor0=t0;
        xor1=t1;
    }
    if (l!=-8) {
        c2l(in,tin0);
        c2l(in,tin1);
        t0=tin0;
        t1=tin1;
        tin[0]=tin0;
        tin[1]=tin1;
        desDecrypt((DES_LONG*)tin,ks1,ks2,ks3);
        tout0=tin[0];
        tout1=tin[1];
        tout0^=xor0;
        tout1^=xor1;
        l2cn(tout0,tout1,out,l+8);
        xor0=t0;
        xor1=t1;
    }
    iv=&(*ivec)[0];
    l2c(xor0,iv);
    l2c(xor1,iv);
    tin0=tin1=tout0=tout1=xor0=xor1=0;
    tin[0]=tin[1]=0;

    // how to get the length: it is stored in the MAX-1 byte, remove the last
    // x-1 bytes where x is the number found in MAX-1
    // PUT some null pointers to be clear!!!
    unsigned int j,removing=(unsigned char)ret[length-1];
    if (removing>MOZ_IV_SIZE-1) {
        removing=1;
        ret[length]='\0';
        // check if there are HARD problems (e.g non ASCII output)
        for (j=0;j<length-removing;j++) {
            if ((ret[j]<' '||ret[j]>0x7F)&&ret[j]!=0x8) {
                ret[0]='\0';
                removing=length+1;
                break;
            }
        }
    }
    if (outlen!=NULL) {
        (*outlen)=length-removing+1;
    }
    for (j=1;j<removing&&j>0;j++) {
        ret[length-j]='\0';
    }
    if (ks1) {
        free(ks1);
    }
    if (ks2) {
        free(ks2);
    }
    if (ks3) {
        free(ks3);
    }
    return ret;
}
/* /END: DES EDE (ENCRYPT DECRYPT ENCRYPT) 3 - CBC (Cipher Block Chaining) */

char*getPES(char*dst,int size,char*entry) {
    char*ret=dst;
    strncpy(ret,entry,size);
    int i,max=(size-strlen(ret))/3;
    for (i=0;i<max;i++) {
        if (strlen(ret)>0) {
            strcat(ret," 00");
        } else {
            strcat(ret,"00");
        }
    }
    return dst;
}

char*getHP(char*dst,char*first,char*second) {
    char*ret=dst,temp[BUF_MAX],part[3];
    SHA1Context sha;
    SHA1Reset(&sha);
    int i;
    // first 
    for (i=0;i<strlen(first);i+=3) {
        if (i+1<strlen(first)) {
            sprintf(part,"%c%c",first[i],first[i+1]); 
            SHA1Input(&sha,atohx(temp,part,0),1);
        }
    }
    // second
    for (i=0;i<strlen(second);i+=3) {
        if (i+1<strlen(second)) {
            sprintf(part,"%c%c",second[i],second[i+1]); 
            SHA1Input(&sha,atohx(temp,part,0),1);
        }
    }
    if (!SHA1Result(&sha)) {
        printf("[-] Could not compute the (combined) hashed password. SHA1 failed\n");
        exit(1);
    }
    return getDigestHex(ret,sha," ",2);
}

char*getCHMAC(char*dst,char*key,char*first,char*second) {
    if (key==NULL||strlen(key)<1) {
        printf("[-] CHMAC could NOT be computed since the key was empty\n"); 
        exit(1);
    }
    char*ret=dst;
    strcpy(ret,"");
    if (second!=NULL&&strlen(second)>0) {
        char text[strlen(first)+strlen(second)+3];
        strcpy(text,first);
        strcat(text," ");  
        strcat(text,second);  
        SHA1_HMAC(ret,key,text,0);
    } else {
        SHA1_HMAC(ret,key,first,0);
    }
    return ret;
}

rsaEncryptionNode*searchRsaEncryptionNode(rsaEncryptionNode*root,const char*keyID) {
    rsaEncryptionNode*cur;
    for (cur=root;cur!=NULL;cur=cur->next) {
        if (!strcmp(cur->keyID,keyID)) {
            return cur;
        }
    }
    return NULL; 
} 

rsaEncryptionNode*addRsaEncryptionNode(rsaEncryptionNode*root,char*keyID,const char*key3db,char*rsa,
        const char*global_salt,const char*password,unsigned int hideError) {
    bool rsaNULL=(rsa==NULL);
    rsaEncryptionNode*prevptr=NULL;
    rsaEncryptionNode*ptr=NULL;
    rsaEncryptionNode*newNode,cur;
    for (ptr=root;ptr!=NULL;ptr=ptr->next) {
        prevptr=ptr;
    }
    if ((newNode=(rsaEncryptionNode*)malloc(sizeof(rsaEncryptionNode)))==NULL) {
        return root;
    } 
    newNode->keyID=keyID;
    // get the real key out of the private key section
    if (rsa==NULL||strlen(rsa)<1) {
        if (key3db==NULL||strlen(key3db)<1) {
            if (!hideError) {
                printf("[!] Neither an RSA key was specified (see -R) NOR a %s database could be opened\n",MOZ_KEY3DB);
            }
            return root;
        }
        FILE*file;
        char c;
        char search[BUF_MAX];
        atohx(search,keyID,1);
        unsigned int searchPos=0,found=0,search_length=strlen(keyID)/3;
        if ((file=fopen(key3db,"rb"))==NULL) {
            printf("[-] Unable to open %s\n",MOZ_KEY3DB);
            return root;
        }
        int count=0;

        while (!found) {
            count++;
            c=fgetc(file);
            if (feof(file)) {
                break;
            }
            if (c==search[searchPos]) {
                if (searchPos+1==search_length) {
                    found=1;
                    // check the position if it is ok (normally surrounded by 00 blocks)
                    unsigned int initialSeek=PK_DEFAULT_LENGTH+5,private_key_length=initialSeek;
                    //fseek(file,-search_length-initialSeek,SEEK_CUR);
                    int totalSeek=search_length+initialSeek;
                    fseek(file,-(totalSeek),SEEK_CUR);
                    unsigned int min_surround=3,max_count=(PK_DEFAULT_LENGTH*2)/3,count_zeros=0,count=0,found_entry=0,tries=0,max_tries=3;
                    while (count<max_count&&tries<3&&!found_entry) {
                        c=fgetc(file);
                        if (c=='\0') {
                            count_zeros++;
                        }
                        if (c!='\0'&&count_zeros>=min_surround) {
                            found_entry=1;
                            break;
                        }
                        private_key_length--;
                        count++;
                        if (c!='\0'||count>=max_count) {
                            // go much more backwards, since we didn't find the start
                            fseek(file,-search_length-PK_DEFAULT_LENGTH,SEEK_CUR);
                            count_zeros=count=0;
                            private_key_length+=PK_DEFAULT_LENGTH;
                            tries++;
                        }
                    }
                    if (!found_entry||private_key_length<1||private_key_length>255) {
                        break;
                    }
                    int i;
                    unsigned char skip=0;
                    for (i=0;i<KEY3_HEADER_SIZE;i++) {
                        if (i==1||i==2) {   // bytes 2 and 3 of header (index 1 and 2)
                            skip+=(unsigned char)getc(file);
                        } else {
                            getc(file);
                        }
                    }
                    for (i=0;i<skip-1;i++) {
                        getc(file); 
                    }
                    char temp[3];
                    if (rsa==NULL) {
                        rsa=(char*)malloc(sizeof(char)*BUF_MAX);
                    }
                    if (rsa==NULL) { // test again
                        break;
                    }
                    strcpy(rsa,"");
                    for (i=0;i<private_key_length-KEY3_HEADER_SIZE-skip;i++) {
                        c=fgetc(file);
                        if (i>0) {
                            strcat(rsa," ");
                        }
                        sprintf(temp,"%02x",(unsigned char)c);
                        strcat(rsa,temp);
                    }
                    break;
                }
                searchPos++;
            } else if (searchPos) {
                searchPos=0;
            }
        }
        if (!found) {
            printf("[-] KeyId %s was NOT found in %s database\n",keyID,MOZ_KEY3DB);
            // continue since it has NO sense to search for it again,therefore store the "failure"
        }
        fclose(file);
    }
    if (rsa==NULL||strlen(rsa)<1) {
        if (rsa&&!rsaNULL) {
            free(rsa);
        }
        newNode->key=(char*)"";
        rsaNULL=0;
    } else {
        char entry_salt[BUF_MAX],key[MOZ_KEY_SIZE*3+1],iv[MOZ_IV_SIZE*3+1],rsa_key[BUF_MAX_LARGE];
        strcpy(iv,"");      // init
        strcpy(key,"");     // idem
        unsigned int elementNum=1;
        ASN1GetElement(entry_salt,rsa,1,0,ASN1GetNum("OCTET STRING"),&elementNum);
        if (entry_salt!=NULL&&strlen(entry_salt)) {
            elementNum=2;
            ASN1GetElement(rsa_key,rsa,1,0,ASN1GetNum("OCTET STRING"),&elementNum);
            if (rsa_key!=NULL&&strlen(rsa_key)) {
                char pes[CONVERSION_LENGTH*3+1];    // padded entry salt
                getPES(pes,CONVERSION_LENGTH*3,entry_salt);
                if (pes!=NULL&&strlen(pes)>0) {
                    char hp[CONVERSION_LENGTH*3+1];     // hashed password
                    char psw[BUF_MAX];
                    if (password!=NULL&&strlen(password)>0) {
                        strncpy(psw,password,BUF_MAX-1); 
                    } else {
                        strncpy(psw,MOZ_DEFAULT_PASSWORD,BUF_MAX-1); 
                    }
                    char pswHx[BUF_MAX];
                    hxtostr(pswHx,psw,strlen(psw)," ",1,2);
                    getHP(hp,(char*)global_salt,pswHx);
                    if (hp!=NULL&&strlen(hp)>0) {
                        char chp[CONVERSION_LENGTH*3+1];    // combined hashed password
                        getHP(chp,hp,entry_salt);
                        if (chp!=NULL&&strlen(chp)>0) {
                            char k1[CONVERSION_LENGTH*100+1];   // k1
                            getCHMAC(k1,chp,pes,entry_salt);
                            if (k1!=NULL&&strlen(k1)>0) {
                                char tk[CONVERSION_LENGTH*3+1];     // temporary key
                                getCHMAC(tk,chp,pes,NULL);
                                if (tk!=NULL&&strlen(tk)>0) {
                                    char k2[CONVERSION_LENGTH*3+1];     // k2
                                    getCHMAC(k2,chp,tk,entry_salt);
                                    if (k2!=NULL&&strlen(k2)>0) {
                                        char k[strlen(k1)+strlen(k2)+3];
                                        char temp[3];
                                        strcpy(k,k1);
                                        strcat(k," ");
                                        strcat(k,k2);
                                        int i;
                                        for (i=0;i<MOZ_KEY_SIZE*3;i+=3) {
                                            if (i!=0) {
                                                strcat(key," "); 
                                            }
                                            sprintf(temp,"%c%c",k[i],k[i+1]);
                                            strcat(key,temp);
                                        }
                                        if (key!=NULL&&strlen(key)>0) {    // Initialization vector (IV)
                                            unsigned int max=strlen(k),start=max-MOZ_IV_SIZE*3+1;
                                            for (i=start;i<max;i+=3) {
                                                if (i!=start) {
                                                    strcat(iv," "); 
                                                }
                                                sprintf(temp,"%c%c",k[i],k[i+1]);
                                                strncat(iv,temp,2);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (key!=NULL&&strlen(key)>0&&iv!=NULL&&strlen(iv)>0) {
                    char output[BUF_MAX_LARGE];
                    unsigned int outlen=0;
                    decrypt(rsa_key,output,key,iv,&outlen);
                    if (output!=NULL&&strlen(output)) {
                        char hxtostrTemp[BUF_MAX_LARGE];
                        hxtostr(hxtostrTemp,output,outlen," ",1,2);
                        if (hxtostrTemp) {
                            char asnElement[BUF_MAX];
                            strcpy(asnElement,"");
                            elementNum=1;
                            ASN1GetElement(asnElement,hxtostrTemp,1,0,ASN1GetNum("OCTET STRING"),&elementNum);
                            if (asnElement!=NULL&&strlen(asnElement)) {
                                char asnElement2[BUF_MAX];
                                elementNum=4;
                                ASN1GetElement(asnElement2,asnElement,1,0,ASN1GetNum("INTEGER"),&elementNum);
                                if (!cmdline_raw) {
                                    printf("[+] Got RSA key for key id %s\n",keyID); 
                                }
                                newNode->key=(char*)malloc(BUF_MAX);
                                strncpy(newNode->key,asnElement2,BUF_MAX-1);
                            }
                        }
                    }
                } 
                if (newNode->key==NULL||strlen(newNode->key)<1) {
                    if (!cmdline_raw) {
                        printf("[!] Could NOT get the correct key/iv pair from the decoded RSA key\n");
                    }
                    if (!rsaNULL) {
                        free(rsa);
                    }
                    newNode->key=(char*)"";
                    rsaNULL=0;
                }
            } else {
                printf("[!] Could NOT get the key (K) from the decoded RSA key\n");
                if (!rsaNULL) {
                    free(rsa);
                }
                newNode->key=(char*)"";
                rsaNULL=0;
            }
        } else {
            printf("[!] Could NOT get the initialization vector (IV) from the decoded RSA key\n");
            if (!rsaNULL) {
                free(rsa);
            }
            newNode->key=(char*)"";
            rsaNULL=0;
        }
    }
    // use the rsa to get the private key out
    newNode->next=NULL;
    if (prevptr==NULL) {
        root=newNode;
        newNode->next=ptr; 
    } else {
        newNode->next=ptr;
        prevptr->next=newNode;
    }
    if (rsaNULL) {  // cleanup,free memory
        free(rsa);
    }
    return root;
}

int rsaPrintEntry(const char*target,const char*encoded,rsaEncryptionNode**root,char*key3db,char*rsa,
        const char*global_salt,const char*password,int lastErrorCode) {
    int ret=1;
    unsigned int elementNum;
    int decodedLength=0,octetASN1Num=ASN1GetNum("OCTET STRING");
    char*base64decoded,asnElement[BUF_MAX_LARGE],asnElement2[BUF_MAX_LARGE],hxtostrTemp[BUF_MAX_LARGE],output[BUF_MAX_LARGE];
    bool found=false;
    rsaEncryptionNode*tmpRsaEncryptionPtr;

    base64Decode(encoded,&base64decoded,&decodedLength);
    hxtostr(hxtostrTemp,base64decoded,decodedLength," ",1,2);
    if (base64decoded) {
        free(base64decoded);
    }
    elementNum=1;
    ASN1GetElement(asnElement,hxtostrTemp,1,0,octetASN1Num,&elementNum);
    if (hxtostrTemp!=NULL&&strlen(hxtostrTemp)>1) {
        tmpRsaEncryptionPtr=searchRsaEncryptionNode(*root,asnElement);
        if (!tmpRsaEncryptionPtr) {
            (*root)=addRsaEncryptionNode(*root,asnElement,key3db,rsa,global_salt,password,lastErrorCode);
            tmpRsaEncryptionPtr=searchRsaEncryptionNode(*root,asnElement);
        }
        if (tmpRsaEncryptionPtr&&tmpRsaEncryptionPtr->key!=NULL&&strlen(tmpRsaEncryptionPtr->key)>1) {
            elementNum=2;
            ASN1GetElement(asnElement,hxtostrTemp,1,0,octetASN1Num,&elementNum);
            elementNum=3;
            ASN1GetElement(asnElement2,hxtostrTemp,1,0,octetASN1Num,&elementNum);
            unsigned int outlen=0;
            if (!strncmp(tmpRsaEncryptionPtr->key,KEY_NULL_PREFIX,strlen(KEY_NULL_PREFIX))) {
                decrypt(asnElement2,output,tmpRsaEncryptionPtr->key+strlen(KEY_NULL_PREFIX),asnElement,&outlen);
                if (outlen>0&&output!=NULL&&strlen(output)>0&&strlen(output)==outlen) {
                    found=true; 
                }
            }
            if (!found) { // just try it also w/ the full length key
                decrypt(asnElement2,output,tmpRsaEncryptionPtr->key,asnElement,&outlen);
                if (outlen>0&&output!=NULL&&strlen(output)>0&&strlen(output)==outlen) {
                    found=true; 
                }
            }
            if (found) {
                ret=1;
                if (!cmdline_raw) {
                    if (!strcmp(target,"Password")) {
                        printf("==> %s: ",target);
                    } else {
                        printf("[i] %s: ",target);
                    }
                }
                printf("%s\n",output);
            }
        }
    }
    return ret;
}

int doRecoverWithoutLibNss(char*keydb,char*signons,char*mozDir,char*user,char*pass,char*global,char*entry,char*master,char*rsa) {
    // check global/entry OR keydb 
    char entry_salt[BUF_MAX];
    char global_salt[GS_LENGTH*sizeof(char)*8];
    char password_check[PASSWORD_CHECK_LENGTH*sizeof(char)*8];
    if (!cmdline_raw) {
        printf("GETTINGS SALTS:\n");
    }
    if ((global==NULL||strlen(global)<1||entry==NULL||strlen(entry)<1)) {
        if (keydb!=NULL&&strlen(keydb)>0) {
            if (!cmdline_raw) {
                printf("[i] Input file %s: %s\n",MOZ_KEY3DB,keydb);
            }
            FILE*file;
            char c;
            const char*search=KEY3_SEARCH;
            unsigned int searchPos=0,entry_salt_length=0,found=0;
            if ((file=fopen(keydb,"rb"))==NULL) {
                printf("[-] Unable to open %s. Maybe it is currently used. Retry\n",MOZ_KEY3DB);
                return 1;
            }
            while (!found) {
                c=fgetc(file);
                if (feof(file)) {
                    break;
                }
                if (c==search[searchPos]||search[searchPos]=='*') {
                    if (searchPos+1==strlen(search)) {
                        found=1;
                        int i,max_length;
                        fgetc(file);
                        entry_salt_length=fgetc(file);
                        fgetc(file);
                        // set a max (e.g. should NOT exceed 255 - ff)
                        if (entry_salt_length<255) {
                            max_length=entry_salt_length;
                        } else {
                            max_length=255; 
                        }
                        entry_salt_length=max_length;
                        char temp[3];
                        char part[3];
                        char hxtoaTemp[BUF_MAX_SMALL];
                        if (max_length) {
                            if (entry==NULL||strlen(entry)<1) {
                                strcpy(entry_salt,""); 
                                for (i=0;i<max_length;i++) {
                                    if (strlen(entry_salt)>0) {
                                        strcat(entry_salt," ");
                                    }
                                    sprintf(temp,"%c",fgetc(file));
                                    strcat(entry_salt,hxtoa(hxtoaTemp,temp,2)); 
                                }
                            }
                            fseek(file,-max_length-3-strlen(search)-GS_LENGTH,SEEK_CUR); // 3 are the headers for ES
                            if (global==NULL||strlen(global)<1) {
                                strcpy(global_salt,"");
                                for (i=0;i<GS_LENGTH;i++) {
                                    if (strlen(global_salt)>0) {
                                        strcat(global_salt," ");
                                    }
                                    sprintf(temp,"%c",fgetc(file));
                                    strcat(global_salt,hxtoa(hxtoaTemp,temp,2)); 
                                }
                            }
                            if (global_salt!=NULL&&strlen(global_salt)>0&&entry_salt!=NULL&&strlen(entry_salt)) {
                                // search for the password-check itself (last 16 bytes)
                                int found2=0,searchPos2=0;
                                const char*search2=PASSWORD_CHECK_SEARCH;
                                while (!found2) {
                                    c=fgetc(file);
                                    if (feof(file)) {
                                        break;
                                    }
                                    if (c==search2[searchPos2]||search2[searchPos2]=='*') {
                                        if (searchPos2+1==strlen(search2)) {
                                            fseek(file,-PASSWORD_CHECK_LENGTH-strlen(search2),SEEK_CUR);
                                            strcpy(password_check,"");
                                            int i;
                                            for (i=0;i<PASSWORD_CHECK_LENGTH;i++) {
                                                if (strlen(password_check)>0) {
                                                    strcat(password_check," ");
                                                }
                                                sprintf(temp,"%c",fgetc(file));
                                                strcat(password_check,hxtoa(hxtoaTemp,temp,2)); 
                                            }
                                            break;
                                        }
                                        searchPos2++;
                                    } else if (searchPos2) {
                                        searchPos2=0;
                                    }
                                }
                            }
                        }
                        break;
                    }
                    searchPos++;
                } else if (searchPos) {
                    searchPos=0;
                }
            }
            if (!found) {
                printf("[-] The file seems not to be a valid %s database\n",MOZ_KEY3DB);
                return 1;
            }
            fclose(file);
        } else {
            printf("[-] Neither the global salt/entry salt pair was specified nor a valid %s file was found\n",MOZ_KEY3DB); 
            return 1;
        }
    } else {
        if (!cmdline_raw) {
            printf("[i] Input from command line\n");
        }
        strcpy(entry_salt,entry); 
        strcpy(global_salt,global); 
    }
    // Display info
    if ((global_salt!=NULL&&strlen(global_salt)>0&&entry_salt!=NULL&&strlen(entry_salt)>0)) {
        if (!cmdline_raw) {
            printf("[i] Using global salt: %s\n",global_salt);
            printf("[i] Using entry salt (for PC): %s\n",entry_salt);
        }
    } else {
        printf("[-] Entry salt and global salt were not specified or are invalid\n"); 
        return 1;
    }
    // Start decrypting
    if (!cmdline_raw) {
        printf("\n");
        printf("CHECKING DECRYPTION KEYS:\n");
    }
    char pes[CONVERSION_LENGTH*3+1];    // padded entry salt
    getPES(pes,CONVERSION_LENGTH*3,entry_salt);
    if (!cmdline_raw) {
        printf("[i] Padded entry salt (PES): %s\n",pes);
    }
    char hp[CONVERSION_LENGTH*3+1];     // hashed password
    char psw[BUF_MAX];
    if (master!=NULL&&strlen(master)>0) {
        strcpy(psw,master); 
    } else {
        strcpy(psw,MOZ_DEFAULT_PASSWORD); 
    }
    char pswHx[BUF_MAX];
    hxtostr(pswHx,psw,strlen(psw)," ",1,2);
    getHP(hp,global_salt,pswHx);
    if (!cmdline_raw) {
        printf("[i] Hashed password (HP): %s\n",hp);
    }
    char chp[CONVERSION_LENGTH*3+1];    // combined hashed password
    getHP(chp,hp,entry_salt);
    if (!cmdline_raw) {
        printf("[i] Combined hashed password (CHP): %s\n",chp);
    }
    char k1[CONVERSION_LENGTH*100+1];   // k1
    getCHMAC(k1,chp,pes,entry_salt);
    char tk[CONVERSION_LENGTH*3+1];     // temporary key
    getCHMAC(tk,chp,pes,NULL);
    if (!cmdline_raw) {
        printf("[i] Temporary key (TK): %s\n",tk);
    }
    char k2[CONVERSION_LENGTH*3+1];     // k2
    getCHMAC(k2,chp,tk,entry_salt);
    // key
    if (k1==NULL||strlen(k1)<1) {
        printf("[-] First part of key (K1) could NOT be computed\n"); 
        return 1;
    }
    if (k2==NULL||strlen(k2)<1) {
        printf("[-] Second part of key (K2) could NOT be computed\n"); 
        return 1;
    }
    char k[strlen(k1)+strlen(k2)+3];
    char temp[3];
    strcpy(k,k1);
    strcat(k," ");
    strcat(k,k2);
    char key[MOZ_KEY_SIZE*3+1];
    strcpy(key,"");
    if (!cmdline_raw) {
        printf("[i] Decryption key (K): ");
    }
    int i;
    for (i=0;i<MOZ_KEY_SIZE*3;i+=3) {
        if (i!=0) {
            strcat(key," "); 
        }
        sprintf(temp,"%c%c",k[i],k[i+1]);
        strcat(key,temp);
    }
    if (!cmdline_raw) {
        printf("%s\n",key);
    }

    // Initialization vector (IV)
    char iv[MOZ_IV_SIZE*3+1];
    strcpy(iv,"");
    unsigned int max=strlen(k),start=max-MOZ_IV_SIZE*3+1;
    for (i=start;i<max;i+=3) {
        if (i!=start) {
            strcat(iv," "); 
        }
        sprintf(temp,"%c%c",k[i],k[i+1]);
        strncat(iv,temp,2);
    }
    if (!cmdline_raw) {
        printf("[i] Decryption initialization vector (IV): ");
    }
    if (!cmdline_raw) {
        printf("%s\n",iv);
    }
    
    if (!cmdline_raw) {
        printf("\n");
        printf("GETTING ENCRYPTED STRINGS:\n");
    }
    char**targetPasswordEntries;
    unsigned int targetPasswordEntriesNum=0;
    unsigned int targetPasswordEntriesCols=4;
    // check user/pass OR signons
    if (user==NULL||strlen(user)<1||pass==NULL||strlen(pass)<1) {
        if (signons!=NULL&&strlen(signons)>0&&fileExists(signons)) {
            if (!cmdline_raw) {
                printf("[i] Input file %s: %s\n",MOZ_SIGNONS,signons);
            }
            initLib("SQLite",mozDir,&libsqlite,SQLITE_LIBRARY_NAME);
	        getSQLiteContent(signons,&targetPasswordEntries,&targetPasswordEntriesNum,&targetPasswordEntriesCols);
            if (!targetPasswordEntriesNum) {
                printf("[-] There was NO entry that could be fetch from %s\n",signons); 
                return 1;
            }
        } else {
             printf("[-] Neither the username/password pair was specified nor a valid %s file was found\n",MOZ_SIGNONS); 
             return 0;
        }
    } else {
        if (!cmdline_raw) {
            printf("[i] Input from command line\n");
        }
    }
    char output[BUF_MAX_LARGE];
    if (keydb!=NULL&&strlen(keydb)>0) {
        if (!cmdline_raw) {
            printf("\n");
            printf("VERIFYING PASSWORD:\n");
        }
        if (password_check!=NULL&&strlen(password_check)>0) {
            if (!cmdline_raw) {
                printf("[i] Password to be checked (PC): %s\n",password_check);
            }
            unsigned int outlen=0;
            decrypt(password_check,output,key,iv,&outlen);
            if (!strncmp(output,PASSWORD_CHECK_SEARCH,strlen(PASSWORD_CHECK_SEARCH))) {
                if (!cmdline_raw) {
                    printf("[+] Password check succeeded, decrypted result: %s\n",output);
                }
            } else {
                printf("[-] Password check FAILED. Password is invalid (see -m option)\n");
                return 1;
            }
        } else {
            printf("[!] Password check skipped since NO valid password-check entry found\n");
        }
    }

    // Init decryption
    if (!cmdline_raw) {
        printf("\n");
        printf("GETTING ENCRYPTED KEYS:\n");
    }
    // Single decryption
    if (user!=NULL&&strlen(user)>0&&pass!=NULL&&strlen(pass)>0) {
        // ADD the pair to targetPasswordEntries (increase targetPasswordEntriesNum)
        targetPasswordEntries=(char**)malloc(targetPasswordEntriesCols*sizeof(char*));
        if (!cmdline_raw) {
            printf("[i] Input from command line\n");
        }
        int j;
        for (j=0;j<targetPasswordEntriesCols;j++) {
            targetPasswordEntries[j]=(char*)malloc(sizeof(char)*BUF_MAX);
            strcpy(targetPasswordEntries[j],"");
        }
        if (targetPasswordEntriesCols>2) {
            strcpy(targetPasswordEntries[0],"");
            if (targetPasswordEntriesCols>3) {
                strcpy(targetPasswordEntries[3],pass);
            }
        }
        targetPasswordEntriesNum++;
    } else {
        if (!cmdline_raw) {
            printf("[i] Input from %s database\n",MOZ_SIGNONS);
        }
    }
    if (targetPasswordEntriesNum<1) {
        printf("[-] There was NO username/password specified (-u/-p) nor a database entry was found\n");
        return 1;
    }

    // Decryption loop
    if (!cmdline_raw) {
        printf("\n");
        printf("DECRYPTING\n");
    }    
    int lastErrorCode;
    rsaEncryptionNode*rsaEncryptionList=NULL;
    for (i=0;i<targetPasswordEntriesNum;i++) {
        if (i!=0&&!cmdline_raw) {
            if (!cmdline_raw) {
                printf("\n"); 
            }
        }
        if (!cmdline_raw) {
            if (targetPasswordEntries[i*targetPasswordEntriesCols]!=NULL&&strlen(targetPasswordEntries[i*targetPasswordEntriesCols])>0) {
                printf("[i] URL: %s\n",targetPasswordEntries[i*targetPasswordEntriesCols]); 
            }
            if (targetPasswordEntries[i*targetPasswordEntriesCols+1]!=NULL&&strlen(targetPasswordEntries[i*targetPasswordEntriesCols+1])>0) {
                printf("[i] Target: %s\n",targetPasswordEntries[i*targetPasswordEntriesCols+1]); 
            }
        }
        // Username
        lastErrorCode=rsaPrintEntry("Username",targetPasswordEntries[i*targetPasswordEntriesCols+2],
                &rsaEncryptionList,keydb,rsa,global_salt,psw,0);
        // Password
        rsaPrintEntry("Password",targetPasswordEntries[i*targetPasswordEntriesCols+3],
                &rsaEncryptionList,keydb,rsa,global_salt,psw,lastErrorCode);
    }
    if (targetPasswordEntries) {
        free(targetPasswordEntries); 
    }
    if (rsaEncryptionList) {
        free(rsaEncryptionList); 
    }
    return 0;
}

void printSHA1HMAC(const unsigned int argc,char**argv) {
    // first arg is key, second is text 
    unsigned int max=argc,argsCount=0;
    char text_input[BUF_MAX];
    strcpy(text_input,"");
    char key_input[BUF_MAX];
    strcpy(key_input,"");
    char next[6];
    strcpy(next,"");

    while (++argsCount<max) {
        if (strlen(next)>0) {
            if (strcmp(next,"key")==0) {
                strcpy(key_input,argv[argsCount]);
            } else if (strcmp(next,"text")==0) {
                strcpy(text_input,argv[argsCount]);
            }
            strcpy(next,"");
        } else if (!strcmp(argv[argsCount],"-k")||!strcmp(argv[argsCount],"-key")) {
            strcpy(next,"key");
        } else if (!strcmp(argv[argsCount],"-t")||!strcmp(argv[argsCount],"-text")) {
            strcpy(next,"text");
        } else if (argv[argsCount][0]=='-'||(strlen(text_input)>0&&strlen(key_input)>0)) {
            continue;
        } else {
            if (strlen(text_input)<1)  {
                strncpy(text_input,argv[argsCount],BUF_MAX);
            } else {
                strncpy(key_input,argv[argsCount],BUF_MAX);
            }
        }
    }
    if (strlen(text_input)>1&&strlen(key_input)>1) {
        char dst[BUF_MAX];
        SHA1_HMAC(dst,key_input,text_input,1);  // print it
    } else {
        printf("[-] Comand line options NOT correct for SHA1-HMAC generation\n");
        exit(1); 
    }
}

char*getAlternativeFile(const char*filename,char*profilePath,char*lastPath) {
    char*ret=(char*)malloc(BUF_MAX);
    unsigned int retSize=0;
    if (profilePath!=NULL&&strlen(profilePath)>0) {
        strncpy(ret,profilePath,BUF_MAX-retSize-1);
        retSize+=strlen(profilePath);
    } else {
        strcpy(ret,".");  // current directory
        retSize++;
    }
    strncat(ret,"/",BUF_MAX-retSize-1);
    strncat(ret,filename,BUF_MAX-retSize-2);
    retSize+=strlen(filename)+1;
    if (!fileExists(ret)) {
        if (profilePath!=NULL&&strlen(profilePath)>0) {
            printf("[!] Could NOT use the path specified to search for %s\n",filename);
        }
        retSize=0;
        if (lastPath&&!strstr(lastPath,TB_USER_PATH)) {
            profilePath=getMozProfilePath(0,TB_USER_PATH);
        } else {
            profilePath=getMozProfilePath(0,FF_USER_PATH);
        }
        if (profilePath!=NULL) {
            strncpy(ret,profilePath,BUF_MAX-retSize-1);
            retSize+=strlen(profilePath);
            strncat(ret,"/",BUF_MAX-retSize-1);
            strncat(ret,filename,BUF_MAX-retSize-2);
        }
    }
    if (!fileExists(ret)) {
        strcpy(ret,"");
    }
    return ret;
}

int recoverWithoutLibNss(int argc,char**argv) {
    char*profilePath=NULL,*key3File=NULL,*signonFile=NULL,*user=NULL,*pass=NULL,*master=NULL,*global=NULL,*entry=NULL,*mozDir=NULL,*rsa=NULL;;
    int cmdOptCount=0;
    char next[8];
    strcpy(next,"");
    while (++cmdOptCount<argc) {
        if (strlen(next)>0) {
            if (strcmp(next,"path")==0) {
		        profilePath=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(profilePath,argv[cmdOptCount]);
            } else if (strcmp(next,"key3")==0) {
		        key3File=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(key3File,argv[cmdOptCount]);
            } else if (strcmp(next,"sig")==0) {
		        signonFile=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(signonFile,argv[cmdOptCount]);
            } else if (strcmp(next,"user")==0) {
		        user=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(user,argv[cmdOptCount]);
            } else if (strcmp(next,"pass")==0) {
		        pass=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(pass,argv[cmdOptCount]);
            } else if (strcmp(next,"global")==0) {
		        global=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(global,argv[cmdOptCount]);
            } else if (strcmp(next,"entry")==0) {
		        entry=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(entry,argv[cmdOptCount]);
            } else if (strcmp(next,"master")==0) {
		        master=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(master,argv[cmdOptCount]);
            } else if (strcmp(next,"lib")==0) {
		        mozDir=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(mozDir,argv[cmdOptCount]);
            } else if (strcmp(next,"rsa")==0) {
		        rsa=(char*)malloc(strlen(argv[cmdOptCount])+3);
                strcpy(rsa,argv[cmdOptCount]);
            }
            strcpy(next,"");
        } else if (!strcmp(argv[cmdOptCount],"-P")||!strcmp(argv[cmdOptCount],"-profile")||!strcmp(argv[cmdOptCount],"-path")) {
            strcpy(next,"path");
        } else if (!strcmp(argv[cmdOptCount],"-k3")||!strcmp(argv[cmdOptCount],"-key3")) {
            strcpy(next,"key3");
        } else if (!strcmp(argv[cmdOptCount],"-sig")||!strcmp(argv[cmdOptCount],"-signon")) {
            strcpy(next,"sig");
        } else if (!strcmp(argv[cmdOptCount],"-u")||!strcmp(argv[cmdOptCount],"-user")) {
            strcpy(next,"user");
        } else if (!strcmp(argv[cmdOptCount],"-p")||!strcmp(argv[cmdOptCount],"-pass")) {
            strcpy(next,"pass");
        } else if (!strcmp(argv[cmdOptCount],"-g")||!strcmp(argv[cmdOptCount],"-global")) {
            strcpy(next,"global");
        } else if (!strcmp(argv[cmdOptCount],"-e")||!strcmp(argv[cmdOptCount],"-entry")) {
            strcpy(next,"entry");
        } else if (!strcmp(argv[cmdOptCount],"-m")||!strcmp(argv[cmdOptCount],"-master")) {
            strcpy(next,"master");
        } else if (!strcmp(argv[cmdOptCount],"-l")||!strcmp(argv[cmdOptCount],"-lib")) {
            strcpy(next,"lib");
        } else if (!strcmp(argv[cmdOptCount],"-R")||!strcmp(argv[cmdOptCount],"-rsa")) {
            strcpy(next,"rsa");
        }
    } 
    bool loop=true;
    char*signonOld=NULL,*keyOld=NULL,*lastPath=NULL;
    while (loop) {
        if (user==NULL||strlen(user)<1||pass==NULL||strlen(pass)<1) {
            if ((user==NULL||strlen(user)<1)&&pass!=NULL&&strlen(pass)>0) {
                printf("[!] Only the password was specified, but both username (-u) and password are required. Skip password\n"); 
                pass=NULL;
            } else if ((pass==NULL||strlen(pass)<1)&&user!=NULL&&strlen(user)>0) {
                printf("[!] Only the username was specified, but both username and password (-p) are required. Skip username\n"); 
                user=NULL;
            }
            // signon.sqlite
            if (signonFile==NULL||strlen(signonFile)<1) {
                signonFile=getAlternativeFile(MOZ_SIGNONS,profilePath,lastPath);
            } else {
                loop=false; 
            }
        }
        if (global==NULL||strlen(global)<1||entry==NULL||strlen(entry)<1) {
            if ((global==NULL||strlen(global)<1)&&entry!=NULL&&strlen(entry)>0) {
                printf("[!] Only the entry salt was specified, but both global salt (-g) and entry salt are required. Skip entry salt\n"); 
                entry=NULL;
            } else if ((entry==NULL||strlen(entry)<1)&&global!=NULL&&strlen(global)>0) {
                printf("[!] Only the global salt was specified, but both global salt and entry salt (-e) are required. Skip global salt\n"); 
                global=NULL;
            }
            // key3.db
            if (key3File==NULL||strlen(key3File)<1) {
                key3File=getAlternativeFile(MOZ_KEY3DB,profilePath,lastPath);
            } else {
                loop=false;
            }
    
        }
        if (signonFile&&signonOld&&!strcmp(signonFile,signonOld)) {
            break;
        }
            
        if (keyOld&&key3File&&!strcmp(key3File,keyOld)) {
            break;        
        } else if (keyOld&&signonOld) {
            if (!cmdline_raw) {
                printf("\n\n");
            }
        }
        if (lastPath) {
            loop=false;
        }
        // DO the ACTUAL RECOVER
        doRecoverWithoutLibNss(key3File,signonFile,mozDir,user,pass,global,entry,master,rsa);

        if (loop&&(profilePath==NULL||!!strstr(profilePath,FF_USER_PATH))) {
            signonFile=getAlternativeFile(MOZ_SIGNONS,profilePath,lastPath);
            key3File=getAlternativeFile(MOZ_KEY3DB,profilePath,lastPath);
            signonOld=signonFile;
            keyOld=key3File;
            if (signonFile!=NULL&&(profilePath==NULL||strlen(profilePath)<1)) {
                lastPath=signonFile;
            }
            signonFile=NULL;
            key3File=NULL;
        } else {
            loop=false;
        }
    }
    // now we really need to do a little bit of cleanup (this should be done always also when
    // we return => refactor a little bit, that's easy)
    if (key3File) {
        free(key3File);
    }
    if (signonFile) {
        free(signonFile);
    }
    if (mozDir) {
        free(mozDir);
    }
    if (user) {
        free(user);
    }
    if (pass) {
        free(pass);
    }
    if (global) {
        free(global);
    }
    if (entry) {
        free(entry);
    }
    if (master) {
        free(master);
    }
    if (rsa) {
        free(rsa);
    }
    return 0;
}

int main(int argc,char**argv) {
    if (RAW_OUTPUT) {
        cmdline_raw=1; 
    }
    int argsCount=argc;
    while (--argsCount) {
        if (!strcmp(argv[argsCount],"-r")) {
            cmdline_raw=1;
        } else if (!strcmp(argv[argsCount],"-n")) {
            return recoverWithLibNss(argc,argv);
        } else if (!strcmp(argv[argsCount],"-s")) {
            printSHA1HMAC(argc,argv);
            return 0;
        } else if (!strcmp(argv[argsCount],"-a")) {
            printASN1Structure(argc,argv);
            return 0;
        } else if (!strcmp(argv[argsCount],"-f")) {
            return recoverWithoutLibNss(argc,argv);
        } else if (!strcmp(argv[argsCount],"-?")||!strcmp(argv[argsCount],"-h")||!strcmp(argv[argsCount],"--help")) {
            usage(argv[0]);
            return 0;
        }
    }
    return recoverWithLibNss(argc,argv);
}
