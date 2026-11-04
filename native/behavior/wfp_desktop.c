/* Fixed desktop demo WFP controller. Run only inside an isolated Windows VM.
 * Persistent SID blocks survive a controller crash. Permits live in a dynamic
 * BFE session and are removed automatically when this process exits.
 * An ALE_APP_ID condition is a file-path condition, never a PID condition.
 */
#define WIN32_LEAN_AND_MEAN
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <initguid.h>
#include <fwpmu.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Zig 0.13's MinGW header lacks some WFP GUID declarations. Values are from
 * Windows SDK 10.0.26100.0 fwpmu.h, also installed with the Windows SDK. */
#ifdef __MINGW32__
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#define FWPM_SUBLAYER_FLAG_PERSISTENT 0x00000001
#define FWPM_FILTER_FLAG_PERSISTENT 0x00000001
#define FWPM_FILTER_FLAG_DISABLED 0x00000020
DEFINE_GUID(FWPM_LAYER_ALE_AUTH_CONNECT_V4,0xc38d57d1,0x05a7,0x4c33,0x90,0x4f,0x7f,0xbc,0xee,0xe6,0x0e,0x82);
DEFINE_GUID(FWPM_LAYER_ALE_AUTH_CONNECT_V6,0x4a72393b,0x319f,0x44bc,0x84,0xc3,0xba,0x54,0xdc,0xb3,0xb6,0xb4);
DEFINE_GUID(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,0xe1cd9fe7,0xf4b5,0x4273,0x96,0xc0,0x59,0x2e,0x48,0x7b,0x86,0x50);
DEFINE_GUID(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,0xa3b42c97,0x9f04,0x4672,0xb8,0x7e,0xce,0xe9,0xc4,0x83,0x25,0x7f);
DEFINE_GUID(FWPM_CONDITION_ALE_USER_ID,0xaf043a0a,0xb34d,0x4f86,0x97,0x9c,0xc9,0x03,0x71,0xaf,0x6e,0x66);
DEFINE_GUID(FWPM_CONDITION_ALE_APP_ID,0xd78e1e87,0x8644,0x4ea5,0x94,0x37,0xd8,0x09,0xec,0xef,0xc9,0x71);
DEFINE_GUID(FWPM_CONDITION_IP_REMOTE_ADDRESS,0xb235ae9a,0x1d64,0x49b8,0xa4,0x4c,0x5f,0xf3,0xd9,0x09,0x50,0x45);
DEFINE_GUID(FWPM_CONDITION_IP_REMOTE_PORT,0xc35a604d,0xd22b,0x4e1a,0x91,0xb4,0x68,0xf6,0x74,0xee,0x67,0x4b);
DEFINE_GUID(FWPM_CONDITION_IP_PROTOCOL,0x3971ef2b,0x623e,0x4f9a,0x8c,0xb1,0x6e,0x79,0xb8,0x06,0xb9,0xa7);
#endif

typedef struct {
    GUID sublayer;
    GUID deny[4];
} PolicyKeys;

/* A separate sublayer and four filter keys are derived for each dedicated
 * local SID. Fixed global keys cannot represent multiple sandbox users. */
static DWORD policy_keys(PSID sid,PolicyKeys *keys) {
    static const char domain[]="transpect.desktop-wfp.policy.v2";
    BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;
    BYTE digest[32];DWORD code=ERROR_SUCCESS;
    NTSTATUS status=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0);
    if(status){code=ERROR_INVALID_DATA;goto done;}
    status=BCryptCreateHash(alg,&hash,NULL,0,NULL,0,0);
    if(status){code=ERROR_INVALID_DATA;goto done;}
    status=BCryptHashData(hash,(PUCHAR)domain,(ULONG)strlen(domain),0);
    if(status){code=ERROR_INVALID_DATA;goto done;}
    status=BCryptHashData(hash,(PUCHAR)sid,GetLengthSid(sid),0);
    if(status){code=ERROR_INVALID_DATA;goto done;}
    status=BCryptFinishHash(hash,digest,sizeof(digest),0);
    if(status){code=ERROR_INVALID_DATA;goto done;}
    GUID *out[5]={&keys->sublayer,&keys->deny[0],&keys->deny[1],&keys->deny[2],&keys->deny[3]};
    for(unsigned i=0;i<5;i++) {
        memcpy(out[i],digest,sizeof(GUID));
        out[i]->Data4[7]^=(BYTE)i;
        out[i]->Data3=(out[i]->Data3&0x0fff)|0x5000;
        out[i]->Data4[0]=(out[i]->Data4[0]&0x3f)|0x80;
    }
done:
    if(hash)BCryptDestroyHash(hash);
    if(alg)BCryptCloseAlgorithmProvider(alg,0);
    return code;
}

typedef struct {
    PSID sid;
    PolicyKeys keys;
    PACL acl;
    PSECURITY_DESCRIPTOR absolute;
    PSECURITY_DESCRIPTOR relative;
    FWP_BYTE_BLOB blob;
} UserCondition;

static void user_free(UserCondition *u) {
    if(u->sid) LocalFree(u->sid);
    free(u->acl);free(u->absolute);free(u->relative);
    memset(u,0,sizeof(*u));
}

static DWORD user_condition(const wchar_t *sid_text,UserCondition *u) {
    memset(u,0,sizeof(*u));
    if(!ConvertStringSidToSidW(sid_text,&u->sid))return GetLastError();
    if(!IsValidSid(u->sid))return ERROR_INVALID_SID;
    DWORD key_code=policy_keys(u->sid,&u->keys);if(key_code)return key_code;
    DWORD sid_bytes=GetLengthSid(u->sid);
    DWORD acl_bytes=sizeof(ACL)+sizeof(ACCESS_ALLOWED_ACE)-sizeof(DWORD)+sid_bytes;
    u->acl=calloc(1,acl_bytes);u->absolute=calloc(1,SECURITY_DESCRIPTOR_MIN_LENGTH);
    if(!u->acl||!u->absolute)return ERROR_OUTOFMEMORY;
    if(!InitializeAcl(u->acl,acl_bytes,ACL_REVISION) ||
       !AddAccessAllowedAce(u->acl,ACL_REVISION,FWP_ACTRL_MATCH_FILTER,u->sid) ||
       !InitializeSecurityDescriptor(u->absolute,SECURITY_DESCRIPTOR_REVISION) ||
       !SetSecurityDescriptorDacl(u->absolute,TRUE,u->acl,FALSE))return GetLastError();
    DWORD bytes=0;
    MakeSelfRelativeSD(u->absolute,NULL,&bytes);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER)return GetLastError();
    u->relative=malloc(bytes);if(!u->relative)return ERROR_OUTOFMEMORY;
    if(!MakeSelfRelativeSD(u->absolute,u->relative,&bytes))return GetLastError();
    u->blob.size=bytes;u->blob.data=(UINT8*)u->relative;
    return ERROR_SUCCESS;
}

static int dedicated_user(PSID sid) {
    SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY;
    if(*GetSidSubAuthorityCount(sid)!=5 || memcmp(GetSidIdentifierAuthority(sid),&nt,sizeof(nt))!=0 ||
       *GetSidSubAuthority(sid,0)!=21)return 0;
    wchar_t account[256],domain[256],computer[256];DWORD an=256,dn=256,cn=256;
    SID_NAME_USE type=SidTypeUnknown;
    if(!LookupAccountSidW(NULL,sid,account,&an,domain,&dn,&type)||type!=SidTypeUser||
       !GetComputerNameW(computer,&cn)||_wcsicmp(domain,computer))return 0;
    WELL_KNOWN_SID_TYPE forbidden[]={WinWorldSid,WinAuthenticatedUserSid,WinLocalSystemSid,
        WinLocalServiceSid,WinNetworkServiceSid,WinBuiltinAdministratorsSid,WinBuiltinUsersSid};
    for(unsigned i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);i++)
        if(IsWellKnownSid(sid,forbidden[i]))return 0;
    HANDLE token=NULL;DWORD n=0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return 0;
    GetTokenInformation(token,TokenUser,NULL,0,&n);
    TOKEN_USER *owner=malloc(n);
    int okay=owner && GetTokenInformation(token,TokenUser,owner,n,&n) && !EqualSid(owner->User.Sid,sid);
    free(owner);CloseHandle(token);return okay;
}

static int filter_sid_matches(FWPM_FILTER0 *f,PSID sid) {
    if(!f||f->numFilterConditions!=1 ||
       !IsEqualGUID(&f->filterCondition[0].fieldKey,&FWPM_CONDITION_ALE_USER_ID) ||
       f->filterCondition[0].conditionValue.type!=FWP_SECURITY_DESCRIPTOR_TYPE)return 0;
    FWP_BYTE_BLOB *b=f->filterCondition[0].conditionValue.sd;
    if(!b||!b->data)return 0;
    BOOL present=FALSE,defaulted=FALSE;PACL acl=NULL;
    if(!GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)b->data,&present,&acl,&defaulted)||!present||!acl)return 0;
    if(acl->AceCount!=1)return 0;
    for(DWORD i=0;i<acl->AceCount;i++) {
        ACCESS_ALLOWED_ACE *ace=NULL;
        if(GetAce(acl,i,(void**)&ace) && ace->Header.AceType==ACCESS_ALLOWED_ACE_TYPE &&
           ace->Mask==FWP_ACTRL_MATCH_FILTER && EqualSid((PSID)&ace->SidStart,sid))return 1;
    }
    return 0;
}

static DWORD open_engine(HANDLE *engine,int dynamic) {
    FWPM_SESSION0 s={0};s.flags=dynamic?FWPM_SESSION_FLAG_DYNAMIC:0;
    s.displayData.name=L"Transpect fixed desktop demo";
    return FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&s,engine);
}

static DWORD inspect_block(HANDLE e,const GUID *key,const GUID *layer,const GUID *sublayer,PSID sid,UINT64 *id) {
    FWPM_FILTER0 *f=NULL;DWORD code=FwpmFilterGetByKey0(e,key,&f);
    if(code)return code;
    if(!IsEqualGUID(&f->layerKey,layer)||!IsEqualGUID(&f->subLayerKey,sublayer)||
       f->providerKey||
       f->weight.type!=FWP_UINT8||f->weight.uint8!=1||
       f->action.type!=FWP_ACTION_BLOCK||!(f->flags&FWPM_FILTER_FLAG_PERSISTENT)||
       (f->flags&FWPM_FILTER_FLAG_DISABLED)||
       !filter_sid_matches(f,sid))code=ERROR_INVALID_DATA;
    if(id)*id=f->filterId;
    FwpmFreeMemory0((void**)&f);return code;
}

static DWORD inspect_sublayer(HANDLE e,const GUID *key) {
    FWPM_SUBLAYER0 *s=NULL;DWORD code=FwpmSubLayerGetByKey0(e,key,&s);
    if(code)return code;
    if(s->providerKey||s->weight!=0x8000||!(s->flags&FWPM_SUBLAYER_FLAG_PERSISTENT))
        code=ERROR_INVALID_DATA;
    FwpmFreeMemory0((void**)&s);return code;
}

static DWORD verify_blocks(HANDLE e,UserCondition *u,UINT64 ids[4]) {
    DWORD c=inspect_sublayer(e,&u->keys.sublayer);if(c)return c;
    c=inspect_block(e,&u->keys.deny[0],&FWPM_LAYER_ALE_AUTH_CONNECT_V4,&u->keys.sublayer,u->sid,&ids[0]);
    if(c)return c;
    c=inspect_block(e,&u->keys.deny[1],&FWPM_LAYER_ALE_AUTH_CONNECT_V6,&u->keys.sublayer,u->sid,&ids[1]);
    if(c)return c;
    c=inspect_block(e,&u->keys.deny[2],&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,&u->keys.sublayer,u->sid,&ids[2]);
    return c?c:inspect_block(e,&u->keys.deny[3],&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,&u->keys.sublayer,u->sid,&ids[3]);
}

static DWORD add_block(HANDLE e,const GUID *key,const GUID *layer,UserCondition *u) {
    FWPM_FILTER_CONDITION0 c={0};
    c.fieldKey=FWPM_CONDITION_ALE_USER_ID;c.matchType=FWP_MATCH_EQUAL;
    c.conditionValue.type=FWP_SECURITY_DESCRIPTOR_TYPE;c.conditionValue.sd=&u->blob;
    FWPM_FILTER0 f={0};f.filterKey=*key;f.displayData.name=L"Transpect dedicated desktop user default deny";
    f.layerKey=*layer;f.subLayerKey=u->keys.sublayer;
    f.flags=FWPM_FILTER_FLAG_PERSISTENT;f.action.type=FWP_ACTION_BLOCK;
    /* FWP_UINT8 is a range index, valid only from 0 through 15. */
    f.weight.type=FWP_UINT8;f.weight.uint8=1;
    f.numFilterConditions=1;f.filterCondition=&c;
    return FwpmFilterAdd0(e,&f,NULL,NULL);
}

static DWORD install(HANDLE e,UserCondition *u) {
    UINT64 ids[4]={0};DWORD c=verify_blocks(e,u,ids);
    if(!c)return ERROR_ALREADY_EXISTS;
    /* A partial or malformed installation is an error, not an invitation to
       overwrite another policy object's key. */
    if(c!=FWP_E_FILTER_NOT_FOUND && c!=FWP_E_SUBLAYER_NOT_FOUND)return c;
    c=FwpmTransactionBegin0(e,0);if(c)return c;
    /* Providerless persistent filters avoid BFE disabling provider-owned
       filters when the provider has no auto-start service binding. */
    FWPM_SUBLAYER0 s={0};s.subLayerKey=u->keys.sublayer;s.displayData.name=L"Transpect desktop SID egress";
    s.weight=0x8000;s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;
    c=FwpmSubLayerAdd0(e,&s,NULL);if(c)goto fail;
    c=add_block(e,&u->keys.deny[0],&FWPM_LAYER_ALE_AUTH_CONNECT_V4,u);if(c)goto fail;
    c=add_block(e,&u->keys.deny[1],&FWPM_LAYER_ALE_AUTH_CONNECT_V6,u);if(c)goto fail;
    c=add_block(e,&u->keys.deny[2],&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,u);if(c)goto fail;
    c=add_block(e,&u->keys.deny[3],&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,u);if(c)goto fail;
    c=FwpmTransactionCommit0(e);if(c)return c;
    return verify_blocks(e,u,ids);
fail:
    FwpmTransactionAbort0(e);return c;
}

static DWORD remove_blocks(HANDLE e,UserCondition *u) {
    UINT64 ids[4]={0};DWORD c=verify_blocks(e,u,ids);if(c)return c;
    c=FwpmTransactionBegin0(e,0);if(c)return c;
    for(unsigned i=0;i<4;i++){c=FwpmFilterDeleteByKey0(e,&u->keys.deny[i]);if(c)goto fail;}
    c=FwpmSubLayerDeleteByKey0(e,&u->keys.sublayer);if(c)goto fail;
    return FwpmTransactionCommit0(e);
fail:
    FwpmTransactionAbort0(e);return c;
}

static int sha256_matches(const wchar_t *path,const wchar_t *expected) {
    if(wcslen(expected)!=64)return 0;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(file==INVALID_HANDLE_VALUE)return 0;
    BCRYPT_ALG_HANDLE alg=NULL;BCRYPT_HASH_HANDLE hash=NULL;
    BYTE digest[32],buffer[65536];DWORD n=0;int ok=0;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,NULL,0))goto done;
    if(BCryptCreateHash(alg,&hash,NULL,0,NULL,0,0))goto done;
    while(1){if(!ReadFile(file,buffer,sizeof(buffer),&n,NULL))goto done;if(!n)break;
        if(BCryptHashData(hash,buffer,n,0))goto done;}
    if(BCryptFinishHash(hash,digest,32,0))goto done;
    wchar_t hex[65];for(int i=0;i<32;i++)swprintf(hex+i*2,3,L"%02x",digest[i]);
    ok=!_wcsicmp(hex,expected);
done:
    if(hash)BCryptDestroyHash(hash);if(alg)BCryptCloseAlgorithmProvider(alg,0);CloseHandle(file);return ok;
}

static DWORD verify_target(DWORD pid,ULONGLONG birth,const wchar_t *expected,PSID sid,
                           HANDLE *target,wchar_t *image,DWORD image_capacity,HANDLE *ready) {
    *target=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);
    if(!*target)return GetLastError();
    FILETIME t[4];DWORD length=image_capacity;
    if(!GetProcessTimes(*target,&t[0],&t[1],&t[2],&t[3]))return GetLastError();
    if((((ULONGLONG)t[0].dwHighDateTime<<32)|t[0].dwLowDateTime)!=birth)return ERROR_INVALID_DATA;
    if(!QueryFullProcessImageNameW(*target,0,image,&length))return GetLastError();
    if(!sha256_matches(image,expected)||WaitForSingleObject(*target,0)!=WAIT_TIMEOUT)return ERROR_INVALID_DATA;
    HANDLE token=NULL;DWORD n=0;
    if(!OpenProcessToken(*target,TOKEN_QUERY,&token))return GetLastError();
    GetTokenInformation(token,TokenUser,NULL,0,&n);
    TOKEN_USER *owner=malloc(n);if(!owner){CloseHandle(token);return ERROR_OUTOFMEMORY;}
    BOOL valid=GetTokenInformation(token,TokenUser,owner,n,&n) && EqualSid(owner->User.Sid,sid);
    DWORD code=valid?ERROR_SUCCESS:ERROR_INVALID_DATA;
    free(owner);CloseHandle(token);if(code)return code;
    wchar_t name[160];swprintf(name,160,L"Local\\ttrace-guard-ready-%lu-%llu",pid,birth);
    *ready=OpenEventW(SYNCHRONIZE,FALSE,name);
    if(!*ready)return GetLastError();
    return WaitForSingleObject(*ready,0)==WAIT_OBJECT_0?ERROR_SUCCESS:ERROR_NOT_READY;
}

static DWORD lease(HANDLE e,UserCondition *u,int argc,wchar_t **argv) {
    if(argc!=13)return ERROR_INVALID_PARAMETER;
    DWORD pid=wcstoul(argv[3],NULL,10);ULONGLONG birth=_wcstoui64(argv[4],NULL,10);
    const wchar_t *expected=argv[5],*ip_text=argv[6];unsigned port=wcstoul(argv[7],NULL,10);
    int protocol=!_wcsicmp(argv[8],L"tcp")?IPPROTO_TCP:0;
    unsigned seconds=wcstoul(argv[9],NULL,10);
    DWORD controller_pid=wcstoul(argv[10],NULL,10);ULONGLONG controller_birth=_wcstoui64(argv[11],NULL,10);
    if(!pid||!birth||port<1||port>65535||!protocol||seconds<1||seconds>300||
       !controller_pid||!controller_birth||wcscmp(argv[12],L"--isolated-vm"))return ERROR_INVALID_PARAMETER;
    UINT64 ids[4]={0};DWORD c=verify_blocks(e,u,ids);if(c)return c;
    HANDLE target=NULL,ready=NULL,controller=NULL;wchar_t image[32768]={0};FWP_BYTE_BLOB *app=NULL;
    c=verify_target(pid,birth,expected,u->sid,&target,image,32768,&ready);if(c)goto done;
    controller=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,controller_pid);
    if(!controller){c=GetLastError();goto done;}
    FILETIME controller_times[4];
    if(!GetProcessTimes(controller,&controller_times[0],&controller_times[1],&controller_times[2],&controller_times[3])){
        c=GetLastError();goto done;
    }
    if((((ULONGLONG)controller_times[0].dwHighDateTime<<32)|controller_times[0].dwLowDateTime)!=controller_birth ||
       WaitForSingleObject(controller,0)!=WAIT_TIMEOUT){c=ERROR_INVALID_DATA;goto done;}
    c=FwpmGetAppIdFromFileName0(image,&app);if(c)goto done;
    IN_ADDR v4={0};IN6_ADDR v6={0};int family=0;
    if(InetPtonW(AF_INET,ip_text,&v4)==1)family=AF_INET;
    else if(InetPtonW(AF_INET6,ip_text,&v6)==1)family=AF_INET6;
    else {c=ERROR_INVALID_ADDRESS;goto done;}
    FWPM_SESSION0 s={0};s.flags=FWPM_SESSION_FLAG_DYNAMIC;s.displayData.name=L"Transpect guarded desktop narrow permit";
    HANDLE dynamic=NULL;c=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&s,&dynamic);if(c)goto done;
    FWPM_FILTER_CONDITION0 conditions[5]={0};
    conditions[0].fieldKey=FWPM_CONDITION_ALE_USER_ID;conditions[0].matchType=FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type=FWP_SECURITY_DESCRIPTOR_TYPE;conditions[0].conditionValue.sd=&u->blob;
    conditions[1].fieldKey=FWPM_CONDITION_ALE_APP_ID;conditions[1].matchType=FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type=FWP_BYTE_BLOB_TYPE;conditions[1].conditionValue.byteBlob=app;
    conditions[2].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;conditions[2].matchType=FWP_MATCH_EQUAL;
    FWP_BYTE_ARRAY16 address6={0};
    if(family==AF_INET){conditions[2].conditionValue.type=FWP_UINT32;conditions[2].conditionValue.uint32=ntohl(v4.S_un.S_addr);}
    else {memcpy(address6.byteArray16,&v6,16);conditions[2].conditionValue.type=FWP_BYTE_ARRAY16_TYPE;conditions[2].conditionValue.byteArray16=&address6;}
    conditions[3].fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;conditions[3].matchType=FWP_MATCH_EQUAL;
    conditions[3].conditionValue.type=FWP_UINT16;conditions[3].conditionValue.uint16=(UINT16)port;
    conditions[4].fieldKey=FWPM_CONDITION_IP_PROTOCOL;conditions[4].matchType=FWP_MATCH_EQUAL;
    conditions[4].conditionValue.type=FWP_UINT8;conditions[4].conditionValue.uint8=(UINT8)protocol;
    FWPM_FILTER0 f={0};f.displayData.name=L"Transpect guarded desktop destination";
    f.subLayerKey=u->keys.sublayer;
    f.layerKey=family==AF_INET?FWPM_LAYER_ALE_AUTH_CONNECT_V4:FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    f.action.type=FWP_ACTION_PERMIT;f.weight.type=FWP_UINT8;f.weight.uint8=15;
    f.numFilterConditions=5;f.filterCondition=conditions;
    UINT64 id=0;c=FwpmFilterAdd0(dynamic,&f,NULL,&id);
    if(!c) {
        printf("{\"state\":\"permit_active\",\"filter_id\":%llu,\"pid_exact_filter\":false,\"deadline_seconds\":%u}\n",id,seconds);
        fflush(stdout);
        ULONGLONG end=GetTickCount64()+seconds*1000;
        while(GetTickCount64()<end && WaitForSingleObject(controller,0)==WAIT_TIMEOUT &&
              WaitForSingleObject(target,0)==WAIT_TIMEOUT &&
              WaitForSingleObject(ready,0)==WAIT_OBJECT_0) {
            FWPM_FILTER0 *check=NULL;DWORD health=FwpmFilterGetById0(dynamic,id,&check);
            if(check)FwpmFreeMemory0((void**)&check);
            if(health){c=health;break;}
            Sleep(200);
        }
    }
    /* Explicit deletion triggers reauthorization; session rundown remains the
       fallback if this process crashes or deletion fails. */
    if(dynamic){
        if(id){DWORD revoke=FwpmFilterDeleteById0(dynamic,id);if(!c&&revoke&&revoke!=FWP_E_FILTER_NOT_FOUND)c=revoke;}
        DWORD close=FwpmEngineClose0(dynamic);if(!c)c=close;
    }
done:
    if(app)FwpmFreeMemory0((void**)&app);
    if(ready)CloseHandle(ready);if(target)CloseHandle(target);if(controller)CloseHandle(controller);
    return c;
}

int wmain(int argc,wchar_t **argv) {
    /* install/status/remove SID --isolated-vm
       lease SID pid birth sha256 ip port tcp seconds controller-pid controller-birth --isolated-vm */
    if(argc<4||wcscmp(argv[argc-1],L"--isolated-vm"))return 2;
    if((wcscmp(argv[1],L"install")&&wcscmp(argv[1],L"status")&&
        wcscmp(argv[1],L"remove")&&wcscmp(argv[1],L"lease"))||
       (wcscmp(argv[1],L"lease")&&argc!=4))return 2;
    UserCondition u={0};DWORD code=user_condition(argv[2],&u);
    if(!code&&!dedicated_user(u.sid))code=ERROR_ACCESS_DENIED;
    HANDLE engine=NULL;if(!code)code=open_engine(&engine,0);
    if(!code) {
        if(!wcscmp(argv[1],L"install"))code=install(engine,&u);
        else if(!wcscmp(argv[1],L"remove"))code=remove_blocks(engine,&u);
        else if(!wcscmp(argv[1],L"status")){
            UINT64 ids[4]={0};code=verify_blocks(engine,&u,ids);
            printf("{\"installed\":%s,\"v4_filter_id\":%llu,\"v6_filter_id\":%llu,\"in_v4_filter_id\":%llu,\"in_v6_filter_id\":%llu,\"error\":%lu}\n",
                   code?"false":"true",ids[0],ids[1],ids[2],ids[3],code);
        } else code=lease(engine,&u,argc,argv);
    }
    if(engine){DWORD close=FwpmEngineClose0(engine);if(!code)code=close;}
    user_free(&u);
    if(wcscmp(argv[1],L"status"))printf("{\"operation\":\"%ls\",\"error\":%lu}\n",argv[1],code);
    return code?4:0;
}
