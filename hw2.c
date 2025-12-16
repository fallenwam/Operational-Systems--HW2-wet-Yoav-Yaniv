#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/rcupdate.h>

#define BAN_GETPID 1
#define BAN_PIPE 2
#define BAN_KILL 4

asmlinkage long sys_hello(void) {
 printk("Hello, World!\n");
 return 0;
}

asmlinkage long sys_set_ban(int ban_getpid, int ban_pipe, int ban_kill){
	if(ban_getpid < 0 || ban_pipe < 0 || ban_kill < 0){
		return -EINVAL;
	}
	
	if(!capable(CAP_SYS_ADMIN)){ //possibly change to check EUID==0. hints in dry
		return -EPERM;
	}
	
	char mask = 0;
	if(ban_getpid >= 1){
		mask |= BAN_GETPID;
	}
	if(ban_pipe >= 1){
		mask |= BAN_PIPE;
	}
	if(ban_kill >= 1){
		mask |= BAN_KILL;
	}
	
	current->ban_mask = mask;
	return 0;
}

asmlinkage long sys_get_ban(char ban) {
	int bit_to_check = 0;
	if(ban == 'g') bit_to_check = BAN_GETPID;
	else if(ban == 'p') bit_to_check = BAN_PIPE;
	else if(ban == 'k') bit_to_check = BAN_KILL;
	else return -EINVAL;

	if(current->ban_mask & bit_to_check){
		return 1;
	}
	return 0;
}

asmlinkage long sys_check_ban(pid_t pid, char ban){
	int bit_to_check = 0;
	if(ban == 'g') bit_to_check = BAN_GETPID;
	else if(ban == 'p') bit_to_check = BAN_PIPE;
	else if(ban == 'k') bit_to_check = BAN_KILL;
	else return -EINVAL;
	
	
	rcu_read_lock();
	struct task_struct *target_task = find_task_by_vpid(pid);
	if(!target_task){
		rcu_read_unlock();
		return -ESRCH;
	}
	
	if(get_ban(ban)){
		rcu_read_unlock();
		return -EPERM;
	}
	
	rcu_read_unlock();
	return (target_task->ban_mask & bit_to_check) == bit_to_check;
	
}

asmlinkage long sys_flip_ban_branch(int height, char ban){
	
	if(height <= 0){
		return -EINVAL;
	}
	
	int bit_to_flip = 0;
	if(ban == 'g') bit_to_flip = BAN_GETPID;
	else if(ban == 'p') bit_to_flip = BAN_PIPE;
	else if(ban == 'k') bit_to_flip = BAN_KILL;
	else return -EINVAL;
	
	if(get_ban(ban)){
		return -EPERM;
	}
    
	rcu_read_lock();
	struct task_struct *process_pcb = current->parent;
	int num = 0;

	for(int i = 0; i < height; i++){
		if(!process_pcb){
			break;
		}
		
		process_pcb->ban_mask ^= bit_to_flip;
		if((process_pcb->ban_mask & bit_to_flip) == bit_to_flip){
			num++;
		}
		
		process_pcb = process_pcb->parent;	
	}
	rcu_read_unlock();
	return num;

}
