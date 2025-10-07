
#ifndef __WRITEFILTER_H
#define __WRITEFILTER_H

#define MAX_NAME_LEN 255

enum EVENT_TYPE{
    OPEN,
    WRITE
};

struct event{
    enum EVENT_TYPE type;
    int pid;
    int ppid;
    char task_name[MAX_NAME_LEN];

    ino_t i_ino; // i_node number
    char filepath[MAX_NAME_LEN];
    char filename[MAX_NAME_LEN];
    char content[MAX_NAME_LEN];
};

struct ready_decide_file{
    char filepath[MAX_NAME_LEN];
    ino_t i_ino;  // i_node number
};

struct target_file{
    char filepath[MAX_NAME_LEN];
    off_t read_start_pos;
    ino_t i_ino;  // i_node number
};

struct inode_table_item{
    ino_t INODE_NUMBER;
    char FILE_PATH[MAX_NAME_LEN];
    off_t READ_START_POS;
    int TYPE;
};

struct match_target_path_data{
    char path[MAX_NAME_LEN];
    bool is_match;
};

struct find_target_path_data{
    ino_t inode_number;
    char path[MAX_NAME_LEN];
    bool is_found;
};

struct log_content{
    char content[50000];
    char filepath[MAX_NAME_LEN];
    char client_id[MAX_NAME_LEN];
    char remark[MAX_NAME_LEN];
};
#endif
