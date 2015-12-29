#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/desc_defs.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include "customPageFault.h"

static int init_page_fault_listener(void){
    int retval;
    printk(KERN_INFO "Page fault listener: Init.\n");
    //register the new page fault handler
    retval = registerPageFaultListener();
    if(retval)
        return retval;
    return 0;
}

static void exit_page_fault_listener(void){
    //unregister our new page fault handler
    unregisterPageFaultListener();
    printk(KERN_INFO "Page fault listener: Exit.\n");
}
module_init(init_page_fault_listener);
module_exit(exit_page_fault_listener);
MODULE_LICENSE("Dual BSD/GPL");
