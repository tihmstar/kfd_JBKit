//
//  kfd.cpp
//  kfd_JBKit
//
//  Created by tihmstar on 09.01.24.
//

#include "kfd.hpp"
#include <JBKit/JBMacros.h>

using namespace JBKit;


#pragma mark constructor
Exploit_kfd::Exploit_kfd(){
    //
}

Exploit_kfd::~Exploit_kfd(){
    //
}

#pragma mark public
#pragma mark infos
const char *Exploit_kfd::exploitName(){
    return "kfd";
}

#pragma mark exploit
bool Exploit_kfd::initExploit(JBKit::JBOffsets offsets, readfunc_t func_read, writefunc_t func_write, execfunc_t func_exec){
    (void)func_read;
    (void)func_write;
    (void)func_exec;

    
    
    reterror("TODO implement exploit init");
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

#pragma mark register exploit in framework
__attribute__((constructor))
void libconstructor(void){
    auto kfd = new Exploit_kfd;
    JBExploit::registerExploit(kfd);
}
