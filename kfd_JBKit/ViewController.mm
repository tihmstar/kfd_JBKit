//
//  ViewController.m
//  kfd_JBKit
//
//  Created by tihmstar on 09.01.24.
//

#import "ViewController.h"
#include <JBKit/JBKit.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    JBKit::JBOffsets offsets;
    /*
     TODO 
        - grab kernel
        - run patchfinder
        - initialize offsets
     */
    
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
