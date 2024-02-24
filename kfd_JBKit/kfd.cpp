//
//  kfd.cpp
//  kfd_JBKit
//
//  Created by tihmstar on 09.01.24.
//

#include "kfd.hpp"

#include <JBKit/JBMacros.h>
#include <sys/mman.h>

using namespace JBKit;

struct dynamic_info {
    const char* kern_version;
    // struct fileglob
    uint64_t fileglob__fg_ops;
    uint64_t fileglob__fg_data;
    // struct fileops
    uint64_t fileops__fo_kqfilter;
    // struct fileproc
    // uint64_t fileproc__fp_iocount;
    // uint64_t fileproc__fp_vflags;
    // uint64_t fileproc__fp_flags;
    // uint64_t fileproc__fp_guard_attrs;
    // uint64_t fileproc__fp_glob;
    // uint64_t fileproc__fp_guard;
    // uint64_t fileproc__object_size;
    // struct fileproc_guard
    uint64_t fileproc_guard__fpg_guard;
    // struct kqworkloop
    uint64_t kqworkloop__kqwl_state;
    uint64_t kqworkloop__kqwl_p;
    uint64_t kqworkloop__kqwl_owner;
    uint64_t kqworkloop__kqwl_dynamicid;
    uint64_t kqworkloop__object_size;
    // struct pmap
    uint64_t pmap__tte;
    uint64_t pmap__ttep;
    // struct proc
    uint64_t proc__p_list__le_next;
    uint64_t proc__p_list__le_prev;
    uint64_t proc__p_pid;
    uint64_t proc__p_fd__fd_ofiles;
    uint64_t proc__object_size;
    // struct pseminfo
    uint64_t pseminfo__psem_usecount;
    uint64_t pseminfo__psem_uid;
    uint64_t pseminfo__psem_gid;
    uint64_t pseminfo__psem_name;
    uint64_t pseminfo__psem_semobject;
    // struct psemnode
    // uint64_t psemnode__pinfo;
    // uint64_t psemnode__padding;
    // uint64_t psemnode__object_size;
    // struct semaphore
    uint64_t semaphore__owner;
    // struct specinfo
    uint64_t specinfo__si_rdev;
    // struct task
    uint64_t task__map;
    uint64_t task__threads__next;
    uint64_t task__threads__prev;
    uint64_t task__itk_space;
    uint64_t task__object_size;
    // struct thread
    uint64_t thread__task_threads__next;
    uint64_t thread__task_threads__prev;
    uint64_t thread__map;
    uint64_t thread__thread_id;
    uint64_t thread__object_size;
    // struct uthread
    uint64_t uthread__object_size;
    // struct vm_map_entry
    uint64_t vm_map_entry__links__prev;
    uint64_t vm_map_entry__links__next;
    uint64_t vm_map_entry__links__start;
    uint64_t vm_map_entry__links__end;
    uint64_t vm_map_entry__store__entry__rbe_left;
    uint64_t vm_map_entry__store__entry__rbe_right;
    uint64_t vm_map_entry__store__entry__rbe_parent;
    // struct vnode
    uint64_t vnode__v_un__vu_specinfo;
    // struct _vm_map
    uint64_t _vm_map__hdr__links__prev;
    uint64_t _vm_map__hdr__links__next;
    uint64_t _vm_map__hdr__links__start;
    uint64_t _vm_map__hdr__links__end;
    uint64_t _vm_map__hdr__nentries;
    uint64_t _vm_map__hdr__rb_head_store__rbh_root;
    uint64_t _vm_map__pmap;
    uint64_t _vm_map__hint;
    uint64_t _vm_map__hole_hint;
    uint64_t _vm_map__holes_list;
    uint64_t _vm_map__object_size;
    // kernelcache static addresses
    uint64_t kernelcache__kernel_base;
    uint64_t kernelcache__cdevsw;
    uint64_t kernelcache__gPhysBase;
    uint64_t kernelcache__gPhysSize;
    uint64_t kernelcache__gVirtBase;
    uint64_t kernelcache__perfmon_devices;
    uint64_t kernelcache__perfmon_dev_open;
    uint64_t kernelcache__ptov_table;
    uint64_t kernelcache__vm_first_phys_ppnum;
    uint64_t kernelcache__vm_pages;
    uint64_t kernelcache__vm_page_array_beginning_addr;
    uint64_t kernelcache__vm_page_array_ending_addr;
    uint64_t kernelcache__vn_kqfilter;
};


#pragma mark constructor
Exploit_kfd::Exploit_kfd()
: _di(NULL)
{
    //
}

Exploit_kfd::~Exploit_kfd(){
    if (_di) {
        munlock(_di, sizeof(struct dynamic_info));
        munmap(_di, sizeof(struct dynamic_info)); _di = NULL;
    }
}

#pragma mark public
#pragma mark infos
const char *Exploit_kfd::exploitName(){
    return "kfd";
}

#pragma mark exploit
bool Exploit_kfd::initExploit(JBKit::JBOffsets offsets, readfunc_t func_read, writefunc_t func_write, execfunc_t func_exec){
    /*
        We don't require pre-exising read/write/exec functions to run kfd
     */
    (void)func_read;
    (void)func_write;
    (void)func_exec;

    /*
        Make sure offsets are never paged out!
     */
    retassure((_di = (struct dynamic_info*)mmap(NULL, sizeof(struct dynamic_info), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) != MAP_FAILED, "Failed to map memory for offstets");
    retassure(!mlock(_di, sizeof(struct dynamic_info)), "Failed to mlock offsets memory");
    memset(_di, 0, sizeof(struct dynamic_info));
    
    /*
        Transfer offsets to our internal struct to not bother with the class during critical sections in the exploit!
     */
    _di->fileglob__fg_ops = offsets.getOffset("struct_offset:fileglob.fg_ops");
    _di->task__map = offsets.getOffset("struct_offset:task.map");
    _di->kernelcache__gPhysBase = offsets.getOffset("var:gPhysBase");
    _di->kernelcache__gVirtBase = offsets.getOffset("var:gVirtBase");

    reterror("TODO: initialize the remaining offsets");
    return true;
}

void Exploit_kfd::cleanupExploit(){
    //TODO: perform exploit cleanup
}

void Exploit_kfd::runExploit(){
    reterror("TODO implement exploit");
}

#pragma mark primitives
uint64_t Exploit_kfd::unstable_read64(kptr_t kaddr){
    reterror("TODO implement read64");
}

void Exploit_kfd::unstable_write64(kptr_t kaddr, uint64_t val){
    reterror("TODO implement write64");
}

kptr_t Exploit_kfd::getKernelBase(){
    reterror("TODO implement getKernelBase");
}


#pragma mark register exploit in framework
__attribute__((constructor))
void libconstructor(void){
    auto kfd = new Exploit_kfd;
    JBExploit::registerExploit(kfd);
}
