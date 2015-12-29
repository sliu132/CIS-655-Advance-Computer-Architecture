#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/desc_defs.h>
#include <asm/siginfo.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/signal.h>
#include "customPageFault.h"
#include <linux/rcupdate.h>
#include <linux/debugfs.h>

//PGFAULT_NR is the interrupt number of page fault. 
//It is platform specific.
#if defined(CONFIG_X86_64)
#define PGFAULT_NR X86_TRAP_PF
#else
#error The module only use for X86_64 kernel
#endif

#define SIG_TEST 44

static unsigned long newIDTTablePage;
static struct desc_ptr defaultIDTR;

//addresses of some symbols
//address of default 'page_fault'
static unsigned long defaultPageFaultAddress    = 0UL; 
//address of default 'do_page_fault'
static unsigned long defaultDoPageFaultAddress  = 0UL; 
//address of 'pv_irq_ops'
static unsigned long pv_IRQ_OPS                 = 0UL; 
//content of pv_IRO_OPS.modify exceptionframe,
static unsigned long modifyExceptionFrame;             
static unsigned long errorEntryAddress          = 0UL;
static unsigned long errorExit                  = 0UL;

module_param(defaultPageFaultAddress, ulong, S_IRUGO);
module_param(defaultDoPageFaultAddress, ulong, S_IRUGO);
module_param(pv_IRQ_OPS, ulong, S_IRUGO);
module_param(errorEntryAddress, ulong, S_IRUGO);
module_param(errorExit, ulong, S_IRUGO);

#define checkParamMacro(x) do{\
    if(!x){\
        printk(KERN_INFO "Page fault Listener: Error: need to set '%s'\n", #x);\
        isAnyParamUnset = 1;\
    }\
    printk(KERN_INFO "Page fault Listener: %s=0x%lx\n", #x, x);\
}while(0)

static int checkParam(void){
    int isAnyParamUnset = 0;
    checkParamMacro(defaultPageFaultAddress);
    checkParamMacro(defaultDoPageFaultAddress);
    checkParamMacro(pv_IRQ_OPS);
    checkParamMacro(errorEntryAddress);
    checkParamMacro(errorExit);
    return isAnyParamUnset;
}

typedef void (*do_page_fault_t)(struct pt_regs*, unsigned long);

struct dentry *file;
void customDoPageFault(struct pt_regs* regs, unsigned long error_code){
    
    struct task_struct * task = current;
    printk(KERN_INFO "Page fault Listener : page fault detected in process %lu.\n", (unsigned long)task->pid);
    //Invoke original page fault mechnism
    ((do_page_fault_t)defaultDoPageFaultAddress)(regs, error_code);
    
}

asmlinkage void customPageFault(void);
asm("   .text");
asm("   .type customPageFault,@function");
asm("customPageFault:");
asm("   .byte 0x66");
asm("   xchg %ax, %ax");
asm("   callq *modifyExceptionFrame");
asm("   sub $0x78, %rsp");
asm("   callq *errorEntryAddress");
asm("   mov %rsp, %rdi");
asm("   mov 0x78(%rsp), %rsi");
asm("   movq $0xffffffffffffffff, 0x78(%rsp)");
asm("   callq customDoPageFault");
asm("   jmpq *errorExit");
asm("   nopl (%rax)");

//pack_gate borrow from kernel source
static inline void pack_gate(gate_desc *gate, unsigned type, unsigned long func,
                         unsigned dpl, unsigned ist, unsigned seg){
    gate->offset_low    = PTR_LOW(func);
    gate->segment       = __KERNEL_CS;
    gate->ist           = ist;
    gate->p             = 1;
    gate->dpl           = dpl;
    gate->zero0         = 0;
    gate->zero1         = 0;
    gate->type          = type;
    gate->offset_middle = PTR_MIDDLE(func);
    gate->offset_high   = PTR_HIGH(func);
}

static void loadMyIDTTable(void *info){
    struct desc_ptr *idtr_ptr = (struct desc_ptr *)info;
    load_idt(idtr_ptr);
}
static ssize_t write_pid(struct file *file,const char __user *buf,size_t count,loff_t *ppos){
    //Send signal to user Space
    char mybuf[10];
    
    int ret = 0;
    int pid = 0;
    struct siginfo info;
    struct task_struct *t;
    copy_from_user(mybuf,buf,count);
    sscanf(mybuf,"%d",&pid);
    printk("pid = %d\n",pid);

    memset(&info,0,sizeof(struct siginfo));
    info.si_signo = SIG_TEST;
    info.si_code = SI_QUEUE;
    info.si_int = 1234;

    rcu_read_lock();
    //t = find_task_by_pid_type(PIDTYPE_PID, pid);  //find the task_struct associated with this pid
    t = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
    if(t == NULL){
        printk(KERN_INFO "no such pid\n");
        rcu_read_unlock();
        return -ENODEV;
    }
    rcu_read_unlock();

    ret = send_sig_info(SIG_TEST,&info, t);

    if(ret<0){
        printk(KERN_INFO "send signal error");
    }
    return count;
}
static const struct file_operations my_fops = {
    .write = write_pid,
};

static int initMyFault(void){
    //check all the module_parameters are set properly
    if(checkParam())
        return -1;
    //get the address of 'adjust_exception_frame' from pv_irq_ops struct
    modifyExceptionFrame = *(unsigned long *)(pv_IRQ_OPS + 0x30);

    //get pid from this file
    file = debugfs_create_file("signalconfpid",0200,NULL,NULL ,&my_fops);

    return 0;
}

int registerPageFaultListener(void){
    struct desc_ptr idtr;
    gate_desc *old_idt, *new_idt;
    int retval;

    //first, do some initialization work.
    retval = initMyFault();
    if(retval)
        return retval;

    //record the default idtr
    store_idt(&defaultIDTR);

    //read the content of idtr register and get the address of old IDT table
    old_idt = (gate_desc *)defaultIDTR.address; //'defaultIDTR' is initialized in 'my_virt_drv_init'

    //allocate a page to store the new IDT table
    printk(KERN_INFO "Page fault Listener: alloc a page to store new idt table.\n");
    newIDTTablePage = __get_free_page(GFP_KERNEL);
    if(!newIDTTablePage)
        return -ENOMEM;

    idtr.address = newIDTTablePage;
    idtr.size = defaultIDTR.size;
    
    //copy the old idt table to the new one
    new_idt = (gate_desc *)idtr.address;
    memcpy(new_idt, old_idt, idtr.size);
    pack_gate(&new_idt[PGFAULT_NR], GATE_INTERRUPT, (unsigned long)customPageFault, 0, 0, __KERNEL_CS);
    
    //load idt for all the processors
    printk(KERN_INFO "Page fault Listener: Load the new idt table.\n");
    load_idt(&idtr);
    
    printk(KERN_INFO "Page fault Listener: new idt table loaded.\n");
    smp_call_function(loadMyIDTTable, (void *)&idtr, 1); //wait till all are finished
    printk(KERN_INFO "Page fault Listener: all CPUs have loaded the new idt table.\n");
    
    return 0;
}

void unregisterPageFaultListener(void){
    struct desc_ptr idtr;
    store_idt(&idtr);
    //if the current idt is not the default one, restore the default one
    if(idtr.address != defaultIDTR.address || idtr.size != defaultIDTR.size){
        load_idt(&defaultIDTR);
        smp_call_function(loadMyIDTTable, (void *)&defaultIDTR, 1);
        free_page(newIDTTablePage);
    }
    debugfs_remove(file);
}

MODULE_LICENSE("Dual BSD/GPL");
