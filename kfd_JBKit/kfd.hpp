//
//  kfd.hpp
//  kfd_JBKit
//
//  Created by tihmstar on 09.01.24.
//

#ifndef kfd_hpp
#define kfd_hpp

#include <JBKit/JBKit.h>

class Exploit_kfd : public JBKit::JBExploit {

public:
    Exploit_kfd();
    virtual ~Exploit_kfd() override;

#pragma mark infos
    virtual const char *exploitName() override;

#pragma mark exploit
    virtual bool initExploit(JBKit::JBOffsets offsets, readfunc_t func_read = NULL, writefunc_t func_write = NULL, execfunc_t func_exec = NULL) override;
    virtual void cleanupExploit() override;
    virtual void runExploit() override;
    
#pragma mark primitives
    virtual uint64_t unstable_read64(kptr_t kaddr) override;
    virtual void unstable_write64(kptr_t kaddr, uint64_t val) override;
};

#endif /* kfd_hpp */
