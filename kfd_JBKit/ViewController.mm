//
//  ViewController.m
//  kfd_JBKit
//
//  Created by tihmstar on 09.01.24.
//

#import "ViewController.h"
#include <JBKit/JBKit.h>

#define NO_EXCEPT_ASSURE
#include <libgeneral/macros.h>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>

extern "C"{
#include <libgrabkernel/libgrabkernel.h>
};

using namespace tihmstar;

@interface ViewController ()

@end

std::string getKernelPath(void){
    std::string ret;
    NSString *documents = [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] objectAtIndex:0].path;
    NSString *kernel = [documents stringByAppendingString:@"/kernel.img4"];
    
    ret = [kernel UTF8String];
    
    retassure(!grabkernel(ret.c_str(), 0), "Failed to grab kernel");

    return ret;
}

JBKit::JBOffsets getOffsetsForKFD(const char *kernelpath){
    patchfinder::kernelpatchfinder64 *kpf = nullptr;
    cleanup([&]{
        safeDelete(kpf);
    });
    JBKit::JBOffsets offsets;
    
    kpf = patchfinder::kernelpatchfinder64::make_kernelpatchfinder64(kernelpath);
    
    offsets.setOffset("struct_offset:fileglob.fg_ops", kpf->find_struct_offset_for_PACed_member("fileglob.fg_ops"));
    offsets.setOffset("struct_offset:task.map", kpf->find_struct_offset_for_PACed_member("task.map"));
    offsets.setOffset("var:gPhysBase", kpf->find_gPhysBase());
    offsets.setOffset("var:gVirtBase", kpf->find_gVirtBase());
    reterror("TODO: find the remaining offsets");
    
    return offsets;
}

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    std::string kernelpath = getKernelPath();
    
    JBKit::JBOffsets offsets = getOffsetsForKFD(kernelpath.c_str());

    auto expl = JBKit::JBExploit::getExploitWithName("kfd");
    
    //prepare exploit
    expl->initExploit(offsets);
    
    //run exploit!
    expl->runExploit();
    
    //if we succeeded, we can now do kernel read/write
    auto kernel_base = expl->getKernelBase();
    expl->unstable_write64(kernel_base, 0x4142434445464748);
}


@end
