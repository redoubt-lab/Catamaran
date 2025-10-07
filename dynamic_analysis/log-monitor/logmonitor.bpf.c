#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#include "logmonitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<16);
} rb SEC(".maps");


int ebpf_pid = 0;
int real_handler_pid = 0;
int handle_target_pid = 0;
int decide_file_type_pid = 0;
int logcat_monitor_pid = 0;
int rules_config_update_pid = 0;
int send_to_analyzer_thread_pid = 0;

int syscall_openat_id = 0;

void fill_event_comm(struct event *e){
    struct task_struct *task = (void *) bpf_get_current_task();

    e->pid = BPF_CORE_READ(task, pid);
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->task_name, sizeof(e->task_name));
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{

        unsigned long syscall_id = ctx->args[1];
        if(syscall_id != syscall_openat_id)
            return 0;

        int pid = bpf_get_current_pid_tgid() >> 32;
        if (pid == ebpf_pid)
            return 0;
        if (pid == real_handler_pid)
            return 0;
        if (pid == handle_target_pid)
            return 0;
        if (pid == decide_file_type_pid)
            return 0;
        if (pid == logcat_monitor_pid)
            return 0;
        if (pid == rules_config_update_pid)
            return 0;
        if (pid == send_to_analyzer_thread_pid)
            return 0;


        struct event *event;
        event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
        if (!event)
            return 0;

        event->type = OPEN;
        fill_event_comm(event);

        struct pt_regs *regs;
        regs = (struct pt_regs *)ctx->args[0];

        char *filepath = (char *)PT_REGS_PARM2_CORE(regs);
        bpf_probe_read(&event->filepath, sizeof(event->filepath),filepath);

        bpf_ringbuf_submit(event, 0);


        return 0;
}


SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == ebpf_pid)
        return 0;
    if (pid == real_handler_pid)
        return 0;
    if (pid == handle_target_pid)
        return 0;
    if (pid == decide_file_type_pid)
        return 0;

    struct event *event;
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type=WRITE;
    fill_event_comm(event);

    struct dentry *dentry;
    struct qstr dname;
    struct inode *inode;

    // get the dentry from the file pointer
    bpf_probe_read(&dentry, sizeof(dentry), &file->f_path.dentry);
    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);
    bpf_probe_read(&dname, sizeof(dname), (const void*)&dentry->d_name);

    bpf_probe_read(&event->i_ino, sizeof(event->i_ino), (const void*)&inode->i_ino);
    bpf_probe_read(&event->filename, sizeof(event->filename), dname.name);
    bpf_probe_read(&event->content, sizeof(event->content), buf);

    bpf_ringbuf_submit(event, 0);

    return 0;
}
