#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/capability.h>

#define BAN_GETPID 1
#define BAN_PIPE 2
#define BAN_KILL 4

asmlinkage long sys_hello(void) {
 printk("Hello, World!\n");
 return 0;
}

asmlinkage long set_ban(int ban_getpid, int ban_pipe, int ban_kill){
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
	struct task_struct *process_pcb = current;
	current->ban_mask = mask;
	return 0;
}

asmlinkage long get_ban(char ban) {
	struct task_struct *process_pcb = current;

	if(ban == 'g'){
		return (current->ban_mask & BAN_GETPID) == BAN_GETPID;
	}
	if(ban == 'p'){
			return (current->ban_mask & BAN_PIPE) == BAN_PIPE;
	}
	if(ban == 'k'){
			return (current->ban_mask & BAN_KILL) == BAN_KILL;
	}
	else {
	return -EINVAL;
	}
}

asmlinkage long check_ban(pid_t pid, char ban){
	if(ban != 'k' && ban != 'p' && ban != 'g'){
			return -EINVAL;
	}
	
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
	
	if(ban == 'g'){
		rcu_read_unlock();
		return (target_task->ban_mask & BAN_GETPID) == BAN_GETPID;
	}
	if(ban == 'p'){
		rcu_read_unlock();
		return (target_task->ban_mask & BAN_PIPE) == BAN_PIPE;
	}
	if(ban == 'k'){
		rcu_read_unlock();
		return (target_task->ban_mask & BAN_KILL) == BAN_KILL;
	}
}

asmlinkage long flip_ban_branch(int height, char ban){
	if(ban != 'k' && ban != 'p' && ban != 'g' || height <= 0){
		return -EINVAL;
	}
	if(get_ban(ban)){
		return -EPERM;
	}
	rcu_read_lock();
		struct task_struct *process_pcb = current;
		int num = 0;

	for(int i = 0; i <= height; i++, current = current.parent){
		if(i = 0) {continue;}
		if(ban == 'g'){			
			int new_value = (target_task->ban_mask ^ (BAN_GETPID);
			if(new_value & BAN_GETPID == BAN_GETPID){num++;}
		}
		if(ban == 'p'){
			int new_value = (target_task->ban_mask ^ (BAN_GETPID);
			if(new_value & BAN_GETPID == BAN_GETPID){num++;}
		}
		if(ban == 'k'){
			int new_value = (target_task->ban_mask ^ (BAN_GETPID);
			if(new_value & BAN_GETPID == BAN_GETPID){num++;}
		}		
	}
	return num;

}
