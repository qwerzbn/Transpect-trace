/* Deterministic internal lock tests; no live TLS or plaintext certification. */
#include "../../patches/ecapture-windows/enhanced/schannel_hook.c"
#define CHECK(x) do{if(!(x)){printf("{\"failure_line\":%d}\n",__LINE__);return 1;}}while(0)
static HANDLE held,release_lock,finishing;
static CRITICAL_SECTION*test_lock;
static Context*test_context;static Header test_header;
static DWORD WINAPI hold(void*unused){
    (void)unused;EnterCriticalSection(test_lock);SetEvent(held);
    WaitForSingleObject(release_lock,3000);LeaveCriticalSection(test_lock);return 0;
}
static DWORD WINAPI publish(void*unused){
    (void)unused;SetEvent(finishing);finish(test_context,test_header,(const BYTE*)"test",4,1,0);return 0;
}
static HANDLE holder(CRITICAL_SECTION*which){
    test_lock=which;ResetEvent(held);ResetEvent(release_lock);
    HANDLE t=CreateThread(NULL,0,hold,NULL,0,NULL);
    if(!t||WaitForSingleObject(held,1000)!=WAIT_OBJECT_0)return NULL;return t;
}
static void clear_queue(void){
    while(first){Node*n=first;first=n->next;SecureZeroMemory(n->data,n->h.length);HeapFree(GetProcessHeap(),0,n);}
    first=last=NULL;queued=0;
}
int main(void){
    InitializeCriticalSection(&context_lock);InitializeCriticalSection(&queue_lock);
    held=CreateEventW(NULL,TRUE,FALSE,NULL);release_lock=CreateEventW(NULL,TRUE,FALSE,NULL);
    finishing=CreateEventW(NULL,TRUE,FALSE,NULL);wake=CreateEventW(NULL,FALSE,FALSE,NULL);
    CHECK(held&&release_lock&&finishing&&wake);LARGE_INTEGER f;QueryPerformanceFrequency(&f);frequency=f.QuadPart;
    CtxtHandle ctx={11,22};Header a=header(0),b=header(0);Context*c;
    HANDLE t=holder(&queue_lock);CHECK(t);
    c=begin(&ctx,0,&a);CHECK(c&&dropped==0);test_context=c;test_header=a;
    HANDLE publisher=CreateThread(NULL,0,publish,NULL,0,NULL);CHECK(publisher);
    CHECK(WaitForSingleObject(finishing,1000)==WAIT_OBJECT_0);
    /* Publisher must be waiting for queue_lock, not holding context_lock. */
    Sleep(20);Context*second=begin(&ctx,0,&b);CHECK(second==c&&dropped==0);
    SetEvent(release_lock);CHECK(WaitForSingleObject(t,1000)==WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(publisher,1000)==WAIT_OBJECT_0);CloseHandle(t);CloseHandle(publisher);
    finish(second,b,(const BYTE*)"test",4,1,0);
    CHECK(first&&first->h.sequence==1&&first->next&&first->next->h.sequence==2);
    CHECK((first->h.flags&512)&&(first->next->h.flags&512));clear_queue();
    /* Genuine context contention remains a counted loss, not fake success. */
    t=holder(&context_lock);CHECK(t);Header bad=header(0);
    CHECK(begin(&ctx,0,&bad)==NULL&&ecapture_loss_begin_lock==1&&dropped==1);
    SetEvent(release_lock);CHECK(WaitForSingleObject(t,1000)==WAIT_OBJECT_0);CloseHandle(t);
    /* Admission overflow keeps the loss signal and consumes its sequence. */
    Header full=header(0);c=begin(&ctx,0,&full);CHECK(c);queued=QUEUE_CAP;
    finish(c,full,(const BYTE*)"test",4,1,0);
    CHECK(!first&&ecapture_loss_queue_capacity==1&&dropped==2&&c->seq[0]==3);queued=0;
    /* A new context's serial publications remain FIFO and unflagged. */
    CtxtHandle normal={33,44};Header one=header(0),two=header(0);
    c=begin(&normal,0,&one);CHECK(c);finish(c,one,(const BYTE*)"a",1,1,0);
    c=begin(&normal,0,&two);CHECK(c);finish(c,two,(const BYTE*)"b",1,1,0);
    CHECK(first&&first->h.sequence==1&&first->data[0]=='a'&&!first->h.flags);
    CHECK(first->next&&first->next->h.sequence==2&&first->next->data[0]=='b'&&!first->next->h.flags);
    CHECK(first->h.lost==2&&first->next->h.lost==2);clear_queue();
    CloseHandle(held);CloseHandle(release_lock);CloseHandle(finishing);CloseHandle(wake);
    DeleteCriticalSection(&context_lock);DeleteCriticalSection(&queue_lock);
    puts("{\"queue_contention_preserves_begin\":true,\"publisher_does_not_hold_context_while_waiting_queue\":true,\"context_contention_counted\":true,\"capacity_loss_counted\":true,\"fifo_preserved\":true,\"uncertainty_preserved\":true}");return 0;
}
