#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <magic.h>
#include <sqlite3.h>

#include <bpf/libbpf.h>
#include "logmonitor.skel.h"
#include "logmonitor.h"
#include <glib.h>
#include <regex.h>
#include <uuid/uuid.h>
#include <libgen.h>

#define CONFIG_MATCH_CONTAIN 1
#define CONFIG_MATCH_EQUAL 2
#define CONFIG_MATCH_START 3

#define CONFIG_KEY_CLIENT_ID "client_id"
#define CONFIG_KEY_SEND_LOGS_TO_SERVER_URL "send_logs_to_server_url"
#define CONFIG_KEY_TARGET_EXE_PATH "target_exe_path"
#define CONFIG_KEY_TARGET_FILE_PATH "target_file_path"
#define CONFIG_KEY_EXCLUDED_TASK_NAME "excluded_task_name"
#define CONFIG_KEY_EXCLUDED_FILE_NAME "excluded_file_name"
#define CONFIG_KEY_TARGET_FILE_SUFFIX "target_file_suffix"
#define CONFIG_KEY_START_READING_LOG_THRESHOLD "start_reading_log_threshold"
#define CONFIG_KEY_STOP_READING_LOG_SIZE "stop_reading_log_size"
#define CONFIG_KEY_DECIDE_FILE_TYPE_MINI_LINES "decide_file_type_mini_lines"
#define CONFIG_KEY_DECIDE_FILE_TYPE_MINI_SIZE "decide_file_type_mini_size"
#define CONFIG_KEY_DECIDE_FILE_LOG_MINI_LINES "decide_file_log_mini_lines"

#define DATABASE_TARGET_INODE_TYPE 1
#define DATABASE_EXCLUDED_INODE_TYPE 2

char SEND_LOGS_TO_SERVER_URL[50];
char CLIENT_ID[50];

int START_READING_LOG_THRESHOLD;
int STOP_READING_LOG_SIZE;

char *MAGIC_DB_PATH = "magic.mgc";

struct logmonitor_bpf *skel;

GQueue *event_queue;
GQueue *decide_file_queue;
GQueue *handle_target_file_queue;
GHashTable* inode_in_process;

GQueue *analyzer_logcat_queue;
GQueue *analyzer_file_queue;

pthread_t handle_thread;
pthread_t decide_file_thread;
pthread_t handle_target_file_thread;
pthread_t logcat_monitor_thread;
pthread_t rule_update_thread;
pthread_t analyzer_thread;
pthread_mutex_t rule_lock;

GHashTable* config_excluded_suffix;
GHashTable* config_excluded_filename;
GHashTable* config_excluded_task_name;
GHashTable* config_target_path;
GHashTable* config_target_suffix;
GHashTable* config_target_exe_path;

GHashTable* inode_to_path_cache;
GHashTable* excluded_inode;
GHashTable* target_inode;

bool is_trace=TRUE;

sqlite3 *db;

/***
#######################################################
########## INIT DATA
#######################################################
***/
void init_data() {
    event_queue = g_queue_new();
    decide_file_queue = g_queue_new();
    handle_target_file_queue = g_queue_new();
    inode_in_process = g_hash_table_new(g_direct_hash, g_direct_equal);

    analyzer_logcat_queue = g_queue_new();
    analyzer_file_queue = g_queue_new();


    inode_to_path_cache = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    excluded_inode = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    target_inode = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
}

void get_program_directory(char *dir, size_t size) {
    char exe_path[1024];
    ssize_t count = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);

    if (count == -1) {
        perror("readlink() error");
        exit(EXIT_FAILURE);
    }

    exe_path[count] = '\0';
    strncpy(dir, dirname(exe_path), size - 1);
    dir[size - 1] = '\0';
}
/***
#######################################################
########## INIT DATA
#######################################################
***/

/***
#######################################################
########## SQLITE
#######################################################
***/

int init_database() {
    int rc;

    char program_dir[1024];
    get_program_directory(program_dir, sizeof(program_dir));
    char db_file_path[PATH_MAX];
    snprintf(db_file_path, sizeof(db_file_path), "%s/%s", program_dir, "data.db");

    rc = sqlite3_open(db_file_path, &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    return 1;
}

int execute_sql(char *sql) {
    char *err_msg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

void init_table(){
    // TYPE 1, which means target_inode; TYPE 2, which means excluded_inode
    const char *sql = "CREATE TABLE IF NOT EXISTS INODE("
                      "INODE_NUMBER INTEGER PRIMARY KEY,"
                      "FILE_PATH TEXT NOT NULL,"
                      "READ_START_POS INTEGER,"
                      "TYPE INTEGER"
                      ");";
    execute_sql(sql);
}

void load_table_data_to_cache(){
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, "SELECT INODE_NUMBER, FILE_PATH, READ_START_POS, TYPE FROM INODE", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if(sqlite3_column_int(stmt, 3) == DATABASE_TARGET_INODE_TYPE) {
            struct target_file *target_file = (struct target_file *)g_malloc(sizeof(struct target_file));
            target_file->i_ino= sqlite3_column_int(stmt, 0);
            strcpy(target_file->filepath,(char *)sqlite3_column_text(stmt, 1));
            target_file->read_start_pos = sqlite3_column_int(stmt, 2);
            g_hash_table_insert(target_inode, GINT_TO_POINTER(sqlite3_column_int(stmt, 0)), target_file);
        } else if(sqlite3_column_int(stmt, 3) == DATABASE_EXCLUDED_INODE_TYPE) {
            g_hash_table_insert(excluded_inode, GINT_TO_POINTER(sqlite3_column_int(stmt, 0)), g_strdup((const char *)sqlite3_column_text(stmt, 1)));
        } else {
            g_hash_table_insert(inode_to_path_cache, GINT_TO_POINTER(sqlite3_column_int(stmt, 0)), g_strdup((char *)sqlite3_column_text(stmt, 1)));
        }
    }
}

static int check_inode_callback(void *data, int argc, char **argv, char **azColName) {
    *(bool *)data = true;
    return 0;
}

bool is_contain_inode(ino_t inode) {
    bool found = false;
    char *err_msg = 0;
    char sql[256];
    sprintf(sql, "SELECT 1 FROM INODE WHERE INODE_NUMBER = %lld LIMIT 1;", (long long)inode);
    if (sqlite3_exec(db, sql, check_inode_callback, &found, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
    }
    return found;
}

void add_target_inode(ino_t inode,struct target_file *target_file){
    if(!is_contain_inode(inode)){
        char sql[1024];
        snprintf(sql, sizeof(sql), "INSERT INTO INODE (INODE_NUMBER, FILE_PATH, TYPE) VALUES (%lld, '%s', %d);",
                 (long long)inode, target_file->filepath, DATABASE_TARGET_INODE_TYPE);
        execute_sql(sql);
    }else{
        char sql[256];
        snprintf(sql, sizeof(sql), "UPDATE INODE SET TYPE = %d WHERE INODE_NUMBER = %lld;", DATABASE_TARGET_INODE_TYPE, (long long)inode);
        execute_sql(sql);
    }
}

void update_target_inode_read_pos(struct target_file *target_file,long long read_number){
    target_file->read_start_pos+=read_number;

    char sql[256];
    snprintf(sql, sizeof(sql), "UPDATE INODE SET READ_START_POS = %lld WHERE INODE_NUMBER = %lld;", target_file->read_start_pos, (long long)target_file->i_ino);
    execute_sql(sql);
}

void add_target_inode_with_cache(ino_t inode,struct target_file *target_file){
    g_hash_table_insert(target_inode,GINT_TO_POINTER(inode),target_file);
    add_target_inode(inode,target_file);
}

void add_excluded_inode(ino_t inode,char *filepath){
    if(!is_contain_inode(inode)){
        char sql[1024];
        snprintf(sql, sizeof(sql), "INSERT INTO INODE (INODE_NUMBER, FILE_PATH, TYPE) VALUES (%lld, '%s', %d);",
                 (long long)inode, filepath, DATABASE_EXCLUDED_INODE_TYPE);
        execute_sql(sql);
    }else {
        char sql[256];
        snprintf(sql, sizeof(sql), "UPDATE INODE SET TYPE = %d WHERE INODE_NUMBER = %lld;", DATABASE_EXCLUDED_INODE_TYPE,
                 (long long) inode);
        execute_sql(sql);
    }
}

void add_excluded_inode_with_cache(ino_t inode,char *filepath){
    g_hash_table_insert(excluded_inode, GINT_TO_POINTER(inode), g_strdup(filepath));
    add_excluded_inode(inode,filepath);
}

void add_inode(ino_t inode,char *filepath){
    if(is_contain_inode(inode)){
        return;
    }
    char *sql_template = "INSERT INTO INODE (INODE_NUMBER, FILE_PATH) VALUES (%lld, '%s');";
    char sql[1024];
    snprintf(sql, sizeof(sql), sql_template, (long long)inode, filepath);
    execute_sql(sql);
}

void add_inode_with_cache(ino_t inode,char *filepath){
    g_hash_table_insert(inode_to_path_cache, GINT_TO_POINTER(inode), g_strdup(filepath));
    add_inode(inode,filepath);
}

void delete_inode(ino_t inode){
    char sql[256];
    sprintf(sql, "DELETE FROM INODE WHERE INODE_NUMBER = %lld;", (long long)inode);
    execute_sql(sql);
}

void delete_inode_with_cache(ino_t inode){
    g_hash_table_remove(inode_to_path_cache,GINT_TO_POINTER(inode));
    g_hash_table_remove(excluded_inode,GINT_TO_POINTER(inode));
    g_hash_table_remove(target_inode,GINT_TO_POINTER(inode));
    delete_inode(inode);
}

/***
#######################################################
########## SQLITE END
#######################################################
***/


/***
#######################################################
########## COMMON
#######################################################
***/

void get_pid_info(pid_t pid,char *path,int mode) {

    char link[32];
    char proc_dir[32];
    ssize_t len;

    char *temp_path;
    if(mode==1){
        temp_path="/proc/%d/exe";
    }else if(mode==2){
        temp_path="/proc/%d/cmdline";
    }

    // Construct the symbolic link name
    sprintf(proc_dir, "/proc/%d", pid);
    sprintf(link, temp_path, pid);

    if(access(proc_dir, F_OK) == -1) {
        return;
    }

    len = readlink(link, path, 255 - 1);
    // Check for errors
    if (len == -1) {
        //Terminate the string
        path[0] = '\0';
        return;
    }

    //Terminate the string
    path[len] = '\0';
}

char* get_current_time() {
    static char buffer[80];
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    return buffer;
}

ino_t get_inode_num_by_path(char *filepath) {
    struct stat fileStat;
    if (stat(filepath, &fileStat) < 0) {
        return -1;
    }
    return fileStat.st_ino;
}

char* get_file_suffix(const char* filepath) {
    const char *dot = strrchr(filepath, '.');  // Find the last occurrence of dot in the filepath.
    if(!dot || dot == filepath) return "";  // Return empty string if no dot found or dot is the first character.
    return dot;
}

off_t get_file_size(const char *filename) {
    struct stat st;

    if (stat(filename, &st) == 0) {
        return st.st_size;
    } else {
        perror("stat");
        return -1;
    }
}

bool is_directory(const char *path) {
    struct stat path_stat;

    if (stat(path, &path_stat) != 0) {
        return false;
    }

    if(S_ISDIR(path_stat.st_mode)==1)
        return true;
    return false;
}


void print_kv(gpointer key, gpointer value, gpointer user_data) {
    printf("%lu -> %s\n", (long int *)key, (char*) value);
}

void print_queue_element(gpointer data, gpointer user_data) {
    printf("target_queue: %s\n", ((struct target_file*) data)->filepath);
}

/***
#######################################################
########## COMMON END
#######################################################
***/

/***
#######################################################
########## CONFIG SECTION START #######################
#######################################################
***/
void init_config_data() {
    config_excluded_suffix= g_hash_table_new(g_str_hash, g_str_equal);
    config_excluded_filename= g_hash_table_new(g_str_hash, g_str_equal);
    config_excluded_task_name= g_hash_table_new(g_str_hash, g_str_equal);
    config_target_path = g_hash_table_new(g_str_hash, g_str_equal);
    config_target_suffix=g_hash_table_new(g_str_hash, g_str_equal);
    config_target_exe_path=g_hash_table_new(g_str_hash, g_str_equal);
}

void init_excluded_file_suffix(){
    char program_dir[1024];
    get_program_directory(program_dir, sizeof(program_dir));
    char config_path[1024];
    snprintf(config_path, sizeof(config_path), "%s/excluded.file.suffix.config", program_dir);
    FILE *file = fopen(config_path, "r");
    if (!file) {
        perror("Failed to open the file\n");
        return;
    }

    char line[20];
    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        char *key = g_strdup(line);
        char *value = g_strdup(line);
        g_hash_table_insert(config_excluded_suffix, key, value);
    }

    fclose(file);
}

void trim_spaces(char *str) {
    char *end;

    // Trim leading spaces
    while (*str == ' ') str++;

    // Trim trailing spaces and newline characters
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\n' || *end == '\r')) end--;

    // Null terminate
    *(end + 1) = 0;
}

void init_config(){
    init_config_data();
    init_excluded_file_suffix();

    char program_dir[1024];
    get_program_directory(program_dir, sizeof(program_dir));
    char config_path[1024];
    snprintf(config_path, sizeof(config_path), "%s/filter.config", program_dir);

    FILE *fp = fopen(config_path, "r");
    if (fp == NULL) {
        perror("fopen() error");
        return 1;
    }
    if (!fp) {
        perror("Failed to open filter.config");
        exit(EXIT_FAILURE);
    }

    char line[2*MAX_NAME_LEN];
    while (fgets(line, sizeof(line), fp)) {
        char key[MAX_NAME_LEN], value[MAX_NAME_LEN];

        char* separator = strchr(line, '=');
        if (separator) {
            *separator = 0;  // split the string into two parts
            strncpy(key, line, sizeof(key)-1);
            strncpy(value, separator+1, sizeof(value)-1);

            trim_spaces(key);
            trim_spaces(value);

            if (strcmp(key, CONFIG_KEY_CLIENT_ID) == 0) {
                strcpy(CLIENT_ID, value);
            }else if (strcmp(key, CONFIG_KEY_SEND_LOGS_TO_SERVER_URL) == 0) {
                strcpy(SEND_LOGS_TO_SERVER_URL, value);
            }else if (strcmp(key, CONFIG_KEY_TARGET_EXE_PATH) == 0) {
                char *key = g_strdup(value);
                g_hash_table_insert(config_target_exe_path, key, NULL);
            } else if (strcmp(key, CONFIG_KEY_TARGET_FILE_PATH) == 0) {
                char *key = g_strdup(value);
                g_hash_table_insert(config_target_path, key, NULL);
            } else if (strcmp(key, CONFIG_KEY_EXCLUDED_TASK_NAME) == 0) {
                char *key = g_strdup(value);
                g_hash_table_insert(config_excluded_task_name, key, NULL);
            }
            else if (strcmp(key, CONFIG_KEY_EXCLUDED_FILE_NAME) == 0) {
                g_hash_table_insert(config_excluded_filename, g_strdup(value), g_strdup(value));
            }
            else if (strcmp(key, CONFIG_KEY_TARGET_FILE_SUFFIX) == 0) {
                char *key = g_strdup(value);
                g_hash_table_insert(config_target_suffix, key, NULL);
            }else if (strcmp(key, CONFIG_KEY_START_READING_LOG_THRESHOLD) == 0) {
                char temp_str[10];
                strcpy(temp_str, value);
                START_READING_LOG_THRESHOLD = atoi(temp_str);
            }else if (strcmp(key, CONFIG_KEY_STOP_READING_LOG_SIZE) == 0) {
                char temp_str[10];
                strcpy(temp_str, value);
                STOP_READING_LOG_SIZE = atoi(temp_str);
            }
        }
    }

    fclose(fp);
}

bool is_excluded_file_suffix_by_config(char *filepath){
    char *suffix=get_file_suffix(filepath);
    if (g_hash_table_contains(config_excluded_suffix, suffix)) {
        return true;
    }
    return false;
}

void print_hash_table(GHashTable *hash_table) {
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, hash_table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        printf("%s -> %s\n", (char*)key, (char*)value);
    }
}

bool is_excluded_filename_by_config(char *filename){
    if (filename != NULL && filename[0] == '\0') {
        return true;
    }
    if (g_hash_table_contains(config_excluded_filename, filename)) {
        return true;
    }
    return false;
}

bool is_excluded_exe_path_by_config(char *exe){
    char *all="*";
    if (g_hash_table_contains(config_target_exe_path, all)) {
        return false;
    }
    if (g_hash_table_contains(config_target_exe_path, exe)) {
        return false;
    }
    return true;
}

bool is_excluded_task_name_by_config(char *task_name){
    if (g_hash_table_contains(config_excluded_task_name, task_name)) {
        return true;
    }
    return false;
}

void match_target_file_iterator(gpointer key, gpointer value, gpointer param_data) {
    struct match_target_path_data* data = (struct match_target_path_data*)param_data;
    if (data == NULL || key == NULL) {
        return;
    }
    if (!data->is_match) {
        if (strncmp(data->path, (char*)key, strlen((char*)key)) == 0) {
            data->is_match = true;
        }
    }
}

bool is_match_target_filepath_by_config(char *filepath){
    struct match_target_path_data* data = malloc(sizeof(struct match_target_path_data));
    if (!data) {
        return false;
    }
    strcpy(data->path, filepath);
    data->is_match = false;
    g_hash_table_foreach(config_target_path, (GHFunc)match_target_file_iterator, data);
    bool res = data->is_match;
    free(data);
    return res;
}

bool is_excluded_filepath_by_config(char *filepath){
    if(!is_match_target_filepath_by_config(filepath)) {
        return true;
    }
    return false;
}

bool is_target_filepath_by_config(char *filepath){
    char *all="*";
    char *log = "log";
    char *filepath_lower = strdup(filepath);
    char *suffix=get_file_suffix(filepath);
    if (g_hash_table_contains(config_target_suffix, all)) {
        return true;
    }
    if (g_hash_table_contains(config_target_suffix, suffix)) {
        return true;
    }
    if(strstr(filepath_lower, log)){
        return true;
    }
    return false;
}

bool is_str_ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) {
        return false;
    }
    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);
    if (len_suffix > len_str) {
        return false;
    }
    return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

/**
#######################################################
########## CONFIG SECTION END #########################
#######################################################
**/

bool inode_to_path(ino_t i_ino,char *target_path,char *filepath){

    if(g_hash_table_contains(inode_to_path_cache,GINT_TO_POINTER(i_ino))){
        char* path_in_cache = g_hash_table_lookup(inode_to_path_cache, GINT_TO_POINTER(i_ino));
        if(is_trace) {
            printf("write hit the open cache inode:%lu\n",i_ino);
        }
            strcpy(filepath, path_in_cache);
        return true;
    }


    char cmd[512];
    bool is_match=false;
    if(is_trace) {
        printf("Start finding file i_no:%ld  target_path:%s \n", i_ino, target_path);
    }
    snprintf(cmd, sizeof(cmd), "find %s -inum %ld 2>/dev/null", target_path, i_ino);

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run find command");
        return is_match;
    }

    char result[MAX_NAME_LEN];
    while (fgets(result, sizeof(result)-1, fp) != NULL) {
        char *end = strchr(result, '\n');
        if (end) {
            *end = '\0';
        }
        is_match=true;
        if(is_trace) {
            printf("Get file i_no:%ld  path:%s \n", i_ino, result);
        }
        strcpy(filepath, result);
        break;
    }
    pclose(fp);

    return is_match;
}

void search_path_by_target_path_iterator(gpointer key, gpointer value, gpointer param_data) {
    struct find_target_path_data* data = (struct find_target_path_data*)param_data;
    if (data == NULL || key == NULL) {
        return;
    }
    if (!data->is_found) {
        if(inode_to_path(data->inode_number, (char*)key, data->path)){
            if(is_directory(data->path)){
                return;
            }
            data->is_found = true;
        }
    }
}

void add_into_decide_file_queue(struct event *event){
    struct find_target_path_data* data = malloc(sizeof(struct find_target_path_data));
    if (!data) {
        return false;
    }
    data->inode_number = event->i_ino;
    data->is_found = false;
    g_hash_table_foreach(config_target_path, (GHFunc)search_path_by_target_path_iterator, data);
    if(data->is_found){
        struct ready_decide_file *decide_file = malloc(sizeof(struct ready_decide_file));
        strcpy(decide_file->filepath, data->path);
        decide_file->i_ino=data->inode_number;
        g_queue_push_tail(decide_file_queue, decide_file);
    }
    free(data);
}

void* real_handler(void* arg) {
    int pid = getpid();
    skel->bss->real_handler_pid = pid;
    while(true) {
        if (g_queue_is_empty(event_queue)) {
            sleep(1);
            continue;
        }

        struct event *event=(struct event *)g_queue_pop_head(event_queue);
        if (g_hash_table_contains(excluded_inode,GINT_TO_POINTER(event->i_ino))) {

            char *filepath = (char *)g_hash_table_lookup(excluded_inode, GINT_TO_POINTER(event->i_ino));
            if(!is_str_ends_with(filepath,event->filename)){
                if(is_trace) {
                    printf("cache expire path %s, filename %s\n", filepath,event->filename);
                }
                delete_inode_with_cache(event->i_ino);
                add_into_decide_file_queue(event);
            }else {
                if (is_trace) {
                    printf("this is a excluded inode %lu\n", event->i_ino);
                }
                g_hash_table_remove(inode_in_process, GINT_TO_POINTER(event->i_ino));
            }
            free(event);
            continue;
        }

        if (g_hash_table_contains(target_inode,GINT_TO_POINTER(event->i_ino))) {
            struct target_file *target_file = (struct target_file *)g_hash_table_lookup(target_inode, GINT_TO_POINTER(event->i_ino));

            if(!is_str_ends_with(target_file->filepath,event->filename)){
                if(is_trace) {
                    printf("cache expire path %s, filename %s\n", target_file->filepath,event->filename);
                }
                delete_inode_with_cache(event->i_ino);
                add_into_decide_file_queue(event);
                free(event);
                continue;
            }

            if(is_trace) {
                printf("hit target_file cache %s\n", target_file->filepath);
            }
            struct target_file *target_file_to_queue= malloc(sizeof(struct target_file));
            target_file_to_queue->read_start_pos=target_file->read_start_pos;
            target_file_to_queue->i_ino=target_file->i_ino;
            strcpy(target_file_to_queue->filepath, target_file->filepath);
            g_queue_push_tail(handle_target_file_queue, target_file_to_queue);

            free(event);
            continue;
        }


        add_into_decide_file_queue(event);
        free(event);
    }

}

bool is_target_mime(const char *mime) {
    const char *target_mimes[] = {"text/", "application/json", "application/x-ndjson"};
    for (int i = 0; i < sizeof(target_mimes) / sizeof(target_mimes[0]); i++) {
        if (strstr(mime, target_mimes[i]) != NULL) {
            return true;
        }
    }
    return false;
}

bool is_target_charset(const char *mime) {
    const char *target_charsets[] = {"charset=utf-8", "charset=us-ascii"};
    for (int i = 0; i < sizeof(target_charsets) / sizeof(target_charsets[0]); i++) {
        if (strstr(mime, target_charsets[i]) != NULL) {
            return true;
        }
    }
    return false;
}

bool is_text_file(char *filename) {
    magic_t magic_cookie; // This library should install on android so can use
    const char *mime;

    magic_cookie = magic_open(MAGIC_MIME);
    if (magic_cookie == NULL) {
        return false;
    }

    char program_dir[1024];
    get_program_directory(program_dir, sizeof(program_dir));
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", program_dir, MAGIC_DB_PATH);

    if (magic_load(magic_cookie, path) != 0) {
        magic_close(magic_cookie);
        return false;
    }

    mime = magic_file(magic_cookie, filename);
    if (mime == NULL) {
        magic_close(magic_cookie);
        return false;
    }

    if(is_trace) {
        printf("The MIME type and encoding of '%s' is: %s\n", filename, mime);
    }

    bool is_text_or_json = is_target_mime(mime);
    bool is_valid_charset = is_target_charset(mime);

    magic_close(magic_cookie);

    return is_text_or_json && is_valid_charset;
}

bool is_binary_content(const char *str, size_t len) {
    const unsigned char *data = (const unsigned char *)str;
    size_t binary_threshold = len / 100;  // Assume binary if more than 1% non-printable characters
    size_t binary_count = 0;

    for (size_t i = 0; i < len; i++) {
        if(data[i] == '\0')
            break;
        // Exclude common non-printable characters that can appear in text files
        if (data[i] != '\n' && data[i] != '\r' && data[i] != '\t' && !isprint(data[i])) {
            binary_count++;
            if (binary_count > binary_threshold) {
                return true;
            }
        }
    }
    if (binary_count > binary_threshold) {
        return true;
    }
    return false;
}

ino_t get_inode_number(const char *path) {
    struct stat buf;
    if (stat(path, &buf) != 0) {
        return -1;
    }
    return buf.st_ino;
}

const char *get_filename_from_path(const char *filepath) {
    const char *last_slash = strrchr(filepath, '/');
    if (last_slash) {
        return last_slash + 1;
    }
    return filepath;
}

bool might_be_log_file(const FILE *file,char *filepath) {

    if(!is_text_file(filepath)){
        return false;
    }

    char *log = "log";
    char *filepath_lower = strdup(filepath);
    if(strstr(filepath_lower, log)){
        return true;
    }

    return false;
}

void* decide_file_type(void* arg) {
    int pid = getpid();
    skel->bss->decide_file_type_pid = pid;
    while(true) {
        if (g_queue_is_empty(decide_file_queue)) {
            sleep(1);
            continue;
        }
        struct ready_decide_file *decide_file =(struct ready_decide_file *)g_queue_pop_head(decide_file_queue);

        if(is_trace) {
            printf("Decide_File_Queue Receive %s\n", decide_file->filepath);
        }

        off_t file_size= get_file_size(decide_file->filepath);
        FILE *file = fopen(decide_file->filepath, "rb");
        if (!file) {
            g_hash_table_remove(inode_in_process, GINT_TO_POINTER(decide_file->i_ino));
            free(decide_file);
            continue;
        }

        if(might_be_log_file(file,decide_file->filepath)){
            struct target_file *target_file_to_queue= malloc(sizeof(struct target_file));
            struct target_file *target_file_in_map= (struct target_file *)g_malloc(sizeof(struct target_file));
            target_file_in_map->read_start_pos=0;
            target_file_in_map->i_ino=decide_file->i_ino;
            strcpy(target_file_in_map->filepath, decide_file->filepath);

            target_file_to_queue->read_start_pos=0;
            target_file_to_queue->i_ino=decide_file->i_ino;
            strcpy(target_file_to_queue->filepath, decide_file->filepath);

            if(is_trace) {
                printf("Decide_File_Queue Add target_inode inode:%lu  path:%s\n",decide_file->i_ino,target_file_in_map->filepath);
            }
            add_target_inode_with_cache(decide_file->i_ino,target_file_in_map);

            if(is_trace) {
                printf("Decide_File_Queue Send To Handle_File_Queue %s\n", target_file_in_map->filepath);
            }
            g_queue_push_tail(handle_target_file_queue, target_file_to_queue);
        } else{
            if(is_trace) {
                printf("Decide_File_Queue Add To excluded_inode %s\n", decide_file->filepath);
            }
            add_excluded_inode_with_cache(decide_file->i_ino,decide_file->filepath);
            g_hash_table_remove(inode_in_process, GINT_TO_POINTER(decide_file->i_ino));
        }

        fclose(file);
        free(decide_file);
    }
}

int create_directory_recursive(const char *path) {
    struct stat st = {0};
    char temp_path[256] = {0};
    const char *delimiter = "/";
    char *p;

    strncpy(temp_path, path, sizeof(temp_path));


    for (p = strchr(temp_path + 1, *delimiter); p; p = strchr(p + 1, *delimiter)) {
        *p = '\0';


        if (stat(temp_path, &st) == -1) {
            if (mkdir(temp_path, 0700) == -1) {
                perror("mkdir");
                return -1;
            }
        }

        *p = *delimiter;
    }

    if (stat(temp_path, &st) == -1) {
        if (mkdir(temp_path, 0700) == -1) {
            perror("mkdir");
            return -1;
        }
    }

    return 0;
}

int write_log_to_file(const char *buffer, const char *filepath){

    char program_dir[1024];
    get_program_directory(program_dir, sizeof(program_dir));

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s%s%s", program_dir, "/logs_files/",filepath);
    if(is_trace) {
        printf("Save content to %s\n", file_path);
    }
    char dir_path[512] = {0};
    char* last_slash = strrchr(file_path, '/');
    if (last_slash) {
        strncpy(dir_path, file_path, last_slash - file_path);
    }

    if (create_directory_recursive(dir_path) != 0) {
        return 2;
    }

    FILE *file = fopen(file_path, "a");
    if (!file) {
        return 3;
    }

    fputs(buffer, file);
    fclose(file);

    return 0; // Success
}

/***
#######################################################
########## ANALYZER
#######################################################
***/

typedef struct {
    gchar *key;
    gchar *value;
} KeyValuePair;

GArray *rules_config;

GArray* init_rules_config() {
    GError *error = NULL;
    gchar *contents;
    gsize length;

    char program_dir[1024];
    get_program_directory(program_dir, sizeof(program_dir));
    char config_path[1024];
    snprintf(config_path, sizeof(config_path), "%s/rules.config", program_dir);
    GArray *rules_config_temp = g_array_new(FALSE, FALSE, sizeof(KeyValuePair));

    if (!g_file_get_contents(config_path, &contents, &length, &error)) {
        fprintf(stderr, "Error loading file: %s\n", error->message);
        g_error_free(error);
        return NULL;
    }

    gchar **lines = g_strsplit(contents, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        gchar *line = g_strstrip(lines[i]);

        if (strlen(line) == 0) {
            continue;
        }

        gchar **key_value = g_strsplit(line, "=", 2);
        if (key_value[0] != NULL && key_value[1] != NULL) {
            gchar *key = g_strstrip(key_value[0]);
            gchar *value = g_strstrip(key_value[1]);

            KeyValuePair kv;
            kv.key = g_strdup(key);
            kv.value = g_strdup(value);
            g_array_append_val(rules_config_temp, kv);
        }
        g_strfreev(key_value);
    }

    for (guint i = 0; i < rules_config_temp->len; i++) {
        KeyValuePair kv = g_array_index(rules_config_temp, KeyValuePair, i);
        printf("Update Rule: %s=%s\n", kv.key, kv.value);
    }

    g_strfreev(lines);
    g_free(contents);

    return rules_config_temp;
}

void* rules_config_update(void* arg) {
    int pid = getpid();
    skel->bss->rules_config_update_pid = pid;

    while (1) {
        pthread_mutex_lock(&rule_lock);
        if (rules_config != NULL) {
            for (guint i = 0; i < rules_config->len; i++) {
                KeyValuePair rule = g_array_index(rules_config, KeyValuePair, i);
                g_free(rule.key);
                g_free(rule.value);
            }
            g_array_free(rules_config, TRUE);
        }
        rules_config = init_rules_config();

        pthread_mutex_unlock(&rule_lock);
        //sleep(10);
        return 0;
    }
}

char* get_logcat_pid(const char *log_line) {
    char temp[10000];
    strncpy(temp, log_line, 10000);

    const char *delimiter = " ";
    char *pid;
    int count = 0;

    pid = strtok(temp, delimiter);
    while (pid != NULL) {
        count++;
        if (count == 3) {
            char *result = (char*)malloc(strlen(pid) + 1);
            if (result != NULL) {
                strcpy(result, pid);
            }
            return result;
        }
        pid = strtok(NULL, delimiter);
    }
    return NULL;
}

char* get_app_info_by_pid(const char *pid) {
    char command[256];
    snprintf(command, sizeof(command), "top -b -n 1 | awk '{if ($1 == %s) print $0}'", pid);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        return NULL;
    }

    char buffer[1024];
    char *result = NULL;

    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        char *process_name = strrchr(buffer, ' ');
        if (process_name) {
            process_name++;
            size_t len = strlen(process_name);
            result = (char *)malloc(len + 1);
            if (result) {
                strncpy(result, process_name, len);
                result[len] = '\0';
            }
        }
    }

    pclose(fp);
    return result;
}

void generate_uuid(char *uuid_str) {
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, uuid_str);
}

bool file_exists(const char *filename) {
    return access(filename, F_OK) != -1;
}

void save_result(const char *type, const char *value, const char *log_line_id, const char *log_line, const char *filepath) {
    static sqlite3 *db = NULL;
    static sqlite3_stmt *stmt = NULL;
    static int initialized = 0;
    char *err_msg = 0;

    char program_dir[1024];
    get_program_directory(program_dir, sizeof(program_dir));
    char db_file_path[PATH_MAX];
    snprintf(db_file_path, sizeof(db_file_path), "%s/%s", program_dir, "violations.db");

    struct stat buffer;
    int db_exists = (stat(db_file_path, &buffer) == 0);

    if (!initialized || !db_exists) {
        if (db) {
            sqlite3_close(db);
        }

        int rc = sqlite3_open(db_file_path, &db);

        if (rc != SQLITE_OK) {
            fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(EXIT_FAILURE);
        }

        const char *sql_create_table =
            "CREATE TABLE IF NOT EXISTS violations ("
            "log_line_id TEXT, "
            "violation_id TEXT, "
            "content TEXT, "
            "mark_type TEXT, "
            "found_by TEXT, "
            "client_id TEXT, "
            "filepath TEXT, "
            "log_line TEXT, "
            "remark TEXT, "
            "detected_time TEXT, "
            "PRIMARY KEY (log_line_id, violation_id));";

        rc = sqlite3_exec(db, sql_create_table, 0, 0, &err_msg);

        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", err_msg);
            sqlite3_free(err_msg);
            sqlite3_close(db);
            exit(EXIT_FAILURE);
        }

        const char *sql_insert =
            "INSERT INTO violations (log_line_id, violation_id, content, mark_type, found_by, client_id, filepath, log_line, remark, detected_time) "
            "VALUES (?, ?, ?, ?, 'search', ?, ?, ?, ?, ?);";

        rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, 0);

        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(EXIT_FAILURE);
        }

        initialized = 1;
    }

    char violation_id[37];
    generate_uuid(violation_id);

    time_t detected_time = time(NULL);

    char *appinfo = NULL;
    char *pid = NULL;
    if(strcmp(filepath, "logcat") == 0)
    {
        pid = get_logcat_pid(log_line);
        if (pid) {
            appinfo = get_app_info_by_pid(pid);
        }
    }

    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, log_line_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, violation_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, value, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, CLIENT_ID, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, filepath, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, log_line, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, appinfo !=NULL ? appinfo : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 9, detected_time);

    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
    }

    if (pid) {
        free(pid);
    }
    if (appinfo) {
        free(appinfo);
    }
}


int match_time_string(const char* log_line, const char* sec) {
    regex_t regex;
    char pattern[50];
    snprintf(pattern, sizeof(pattern), "[0-9][0-9]:[0-9][0-9]:%s", sec);

    if (regcomp(&regex, pattern, REG_EXTENDED)) {
        fprintf(stderr, "Could not compile regex\n");
        return 0;
    }

    int result = regexec(&regex, log_line, 0, NULL, 0);
    regfree(&regex);

    return !result;
}

void gps_analyzer(const char* gps,  const char *log_line_id, const char* log_line, const char *filepath) {
    char* gps_copy = strdup(gps);
    char* token = strtok(gps_copy, ",");
    char* longitude = NULL;
    char* latitude = NULL;

    if (token != NULL) {
        longitude = token;
        token = strtok(NULL, ",");
        if (token != NULL) {
            latitude = token;
        }
    }

    if (longitude && latitude) {

        if (strstr(log_line, longitude) || strstr(log_line, latitude)) {

            char gps_str[250] = {0};

            if (strstr(log_line, longitude) && match_time_string(log_line, longitude)) {
                free(gps_copy);
                return;
            }

            if (strstr(log_line, latitude) && match_time_string(log_line, latitude)) {
                free(gps_copy);
                strncat(gps_str, latitude, sizeof(gps_str) - strlen(gps_str) - 1);
                return;
            }

            if (strstr(log_line, longitude)) {
                strncpy(gps_str, longitude, sizeof(gps_str) - 1);
            }
            if( strstr(log_line, latitude)) {
                strncat(gps_str, "\n", sizeof(gps_str) - strlen(gps_str) - 1);
                strncat(gps_str, latitude, sizeof(gps_str) - strlen(gps_str) - 1);
            }

            save_result("gps", gps_str, log_line_id, log_line, filepath);
        }
    }


    free(gps_copy);
}

int case_insensitive_strstr(const char *haystack, const char *needle) {
    if (!*needle) {
        return 1;
    }
    for (; *haystack; ++haystack) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char *h, *n;
            for (h = haystack, n = needle; *h && *n; ++h, ++n) {
                if (tolower((unsigned char)*h) != tolower((unsigned char)*n)) {
                    break;
                }
            }
            if (!*n) {
                return 1;
            }
        }
    }
    return 0;
}

void analyzer(char *line, char *filepath) {
    //pthread_mutex_lock(&rule_lock);
    for (guint i = 0; i < rules_config->len; i++) {
        KeyValuePair rule = g_array_index(rules_config, KeyValuePair, i);

        char log_line_id[37];
        generate_uuid(log_line_id);

        if (strcmp("gps", rule.key) == 0) {
            gps_analyzer(rule.value,log_line_id,line,filepath);
        } else{
            if (case_insensitive_strstr(line, rule.value)) {
                printf("Find violations:%s\n", rule.key);
                save_result(rule.key, rule.value,log_line_id,line,filepath);
            }
        }

    }
    //pthread_mutex_unlock(&rule_lock);
}

bool splite_log_and_analyze(char *buffer, char *filepath) {
    if (buffer == NULL || filepath == NULL) {
        return false;
    }

    char *buffer_copy = strdup(buffer);
    if (buffer_copy == NULL) {
        return false;
    }

    char *line_start = buffer_copy;
    char *line_end;

    while ((line_end = strchr(line_start, '\n')) != NULL) {
        *line_end = '\0';
        analyzer(line_start, filepath);
        line_start = line_end + 1;
    }

    if (*line_start != '\0') {
        analyzer(line_start, filepath);
    }

    free(buffer_copy);
    return true;
}

void send_to_analyzer_thread()
{
    int pid = getpid();
    skel->bss->send_to_analyzer_thread_pid = pid;

    while(TRUE)
    {

        bool is_empty_file= g_queue_is_empty(analyzer_file_queue);
        bool is_logcat_file= g_queue_is_empty(analyzer_logcat_queue);

        if(is_logcat_file & is_empty_file)
        {
            sleep(1);
            continue;
        }

        if (!is_empty_file) {
            struct log_content *log_content=(struct log_content *)g_queue_pop_head(analyzer_file_queue);
            splite_log_and_analyze(log_content->content,log_content->filepath);
            free(log_content);
        }

        if (!is_logcat_file) {
            struct log_content *log_content=(struct log_content *)g_queue_pop_head(analyzer_logcat_queue);
            splite_log_and_analyze(log_content->content,log_content->filepath);
            free(log_content);
        }

    }
}


bool send_to_analyzer(char *buffer, char *filepath) {
    if (buffer == NULL || filepath == NULL) {
        return false;
    }

    struct log_content *log_content = (struct log_content *)malloc(sizeof(struct log_content));
    if (log_content == NULL) {
        return 1;
    }

    strcpy(log_content->content, buffer);
    strcpy(log_content->filepath, filepath);

    if (strcmp(log_content->filepath, "logcat") == 0) {
        g_queue_push_tail(analyzer_logcat_queue, log_content);
    } else{
        g_queue_push_tail(analyzer_file_queue, log_content);
    }


    return true;
}
/***
#######################################################
########## ANALYZER END
#######################################################
***/

void* logcat_monitor(void *arg)  {
    FILE *fp;
    char path[1024];
    char buffer[50000];
    long long lines = 0;


    memset(buffer, 0, sizeof(buffer));


    fp = popen("su -c logcat", "r");
    if (fp == NULL) {
        return;
    }

    char logcat_filename[256];

    int pid = getpid();
    skel->bss->logcat_monitor_pid = pid;

    while (fgets(path, sizeof(path), fp) != NULL) {

        strncat(buffer, path, sizeof(path));
        lines++;

        if (lines % 10000 == 0 || lines == 0) {
            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            char timestamp[64];
            strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", t);
            sprintf(logcat_filename, "logcat/logcat%s", timestamp);
        }

        if (lines % 50 == 0 && lines != 0) {
            //write_log_to_file(buffer, logcat_filename);
            send_to_analyzer(buffer, "logcat");

            memset(buffer, 0, sizeof(buffer));
        }
    }

    pclose(fp);
}

void* handle_target_file(void *arg) {
    int pid = getpid();
    skel->bss->handle_target_pid = pid;
    while(true) {

        if (g_queue_is_empty(handle_target_file_queue)) {
            sleep(1);
            continue;
        }

        struct target_file *target_file=(struct target_file *)g_queue_pop_head(handle_target_file_queue);
        if(is_trace) {
            printf("Handle_File_Queue Receive %s\n", target_file->filepath);
        }


        off_t file_size = get_file_size(target_file->filepath);
        off_t more_file_size=file_size-target_file->read_start_pos;
        if(more_file_size<START_READING_LOG_THRESHOLD){
            if(is_trace) {
                printf("new content (%lu bytes) less than threshold, filepath: %s \n",more_file_size,target_file->filepath);
            }
            g_hash_table_remove(inode_in_process, GINT_TO_POINTER(target_file->i_ino));
            free(target_file);
            continue;
        }

        FILE *file = fopen(target_file->filepath, "rb");
        if (!file) {
            g_hash_table_remove(inode_in_process, GINT_TO_POINTER(target_file->i_ino));
            free(target_file);
            fclose(file);
            continue;
        }

        fseek(file, target_file->read_start_pos, SEEK_SET);
        long long size_to_read = file_size - target_file->read_start_pos-2;
        if(size_to_read>STOP_READING_LOG_SIZE) {
            size_to_read = STOP_READING_LOG_SIZE;
        }
        char *buffer = (char *)malloc(size_to_read);
        if (!buffer) {
            g_hash_table_remove(inode_in_process, GINT_TO_POINTER(target_file->i_ino));
            free(target_file);
            fclose(file);
            continue;
        }
        // the size that really reads
        size_t bytes_read = fread(buffer, 1, size_to_read, file);
        if(strlen(buffer)<START_READING_LOG_THRESHOLD){
            if(is_trace) {
                printf("new content (%lu bytes) less than threshold, filepath: %s \n",strlen(buffer),target_file->filepath);
            }
            g_hash_table_remove(inode_in_process, GINT_TO_POINTER(target_file->i_ino));
            free(target_file);
            free(buffer);
            continue;
        }
        if (bytes_read != size_to_read) {
            update_target_inode_read_pos(target_file,bytes_read);
        }else{
            update_target_inode_read_pos(target_file,size_to_read);
        }

        //write_log_to_file(buffer,target_file->filepath);
        send_to_analyzer(buffer,target_file->filepath);

        //record the newest target file info
        struct target_file *target_file_in_map = g_hash_table_lookup(target_inode, GINT_TO_POINTER(target_file->i_ino));
        target_file_in_map->read_start_pos=target_file->read_start_pos;
        if(is_trace) {
            printf("Update target_file:%s, read_start_pos:%lu\n", target_file_in_map->filepath,target_file_in_map->read_start_pos);
        }

        g_hash_table_remove(inode_in_process, GINT_TO_POINTER(target_file->i_ino));
        free(buffer);
        free(target_file);
        fclose(file);

    }
}

void init_thread(){
    pthread_create(&handle_thread, NULL, real_handler,NULL);
    pthread_create(&decide_file_thread, NULL, decide_file_type,NULL);
    pthread_create(&handle_target_file_thread, NULL, handle_target_file,NULL);
    pthread_create(&logcat_monitor_thread, NULL, logcat_monitor,NULL);
    pthread_create(&rule_update_thread, NULL, rules_config_update,NULL);
    pthread_create(&analyzer_thread, NULL, send_to_analyzer_thread,NULL);

    pthread_mutex_init(&rule_lock, NULL);
}

void init_ebpf_parameter(){
    int pid = getpid();
    skel->bss->ebpf_pid = pid;


    FILE *fp;
    char arch[100];
    char cmd[] = "uname -m";

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        exit(1);
    }

    fgets(arch, sizeof(arch), fp);
    arch[strcspn(arch, "\n")] = '\0';

    if (strcmp(arch, "x86_64") == 0) {
        skel->bss->syscall_openat_id = 257;
    } else if (strcmp(arch, "aarch64") == 0) {
        skel->bss->syscall_openat_id = 56;
    }

    pclose(fp);
}

static void handle_open(void *ctx,struct event *event, size_t data_sz,char *exe,char *cmdline){
    ino_t i_ino=get_inode_num_by_path(event->filepath);
    if(i_ino==-1){
        return;
    }

    if(g_hash_table_contains(inode_to_path_cache,GINT_TO_POINTER(i_ino))){
        char* path_in_cache = g_hash_table_lookup(inode_to_path_cache, GINT_TO_POINTER(i_ino));
        if (strcmp(event->filepath, path_in_cache) == 0) {
            if(is_trace) {
                printf("open hit the cache inode:%lu\n",i_ino);
            }
        }else{
            printf("open the cache expired:%lu\n",i_ino);
            delete_inode_with_cache(event->i_ino);
            add_inode_with_cache(event->i_ino,event->filepath);
        }
    }else {
        if (is_trace) {
            printf("open inode:%lu  path:%s \n", i_ino, event->filepath);
        }
        add_inode_with_cache(i_ino,event->filepath);
    }
}

static void handle_write(void *ctx,struct event *event, size_t data_sz,char *exe,char *cmdline){

    if(g_hash_table_contains(inode_in_process,GINT_TO_POINTER(event->i_ino))){
        if(is_trace) {
            printf("inode in process,tmp_ignored_inode %lu\n", event->i_ino);
        }
        return;
    }
    struct event *event_in_queue = malloc(sizeof(struct event));
    event_in_queue->i_ino = event->i_ino;
    strcpy(event_in_queue->filename, event->filename);

    g_hash_table_insert(inode_in_process, GINT_TO_POINTER(event->i_ino), NULL);

    g_queue_push_tail(event_queue, event_in_queue);

    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{

    struct event *event = (struct event *) data;

    if(is_excluded_task_name_by_config(event->task_name)) {
        return;
    }

    char exe[FILENAME_MAX];
    char cmdline[FILENAME_MAX];
    get_pid_info(event->pid,exe,1);
    get_pid_info(event->pid,cmdline,2);

    if(is_excluded_exe_path_by_config(exe)) {
        return;
    }

    if(event->type==OPEN)
    {
        if(is_excluded_filepath_by_config(event->filepath)){
            return;
        }

        if(!is_target_filepath_by_config(event->filename))
        {
            return;
        }

        handle_open(ctx,event,data_sz,exe,cmdline);
    } else if(event->type==WRITE){

        if(is_excluded_filename_by_config(event->filename))
        {
            return;
        }

        char *suffix=get_file_suffix(event->filename);
        if(!is_target_filepath_by_config(event->filename))
        {
            return;
        }

        if(is_binary_content(event->content,MAX_NAME_LEN)){
           return ;
        }

        handle_write(ctx,event,data_sz,exe,cmdline);
    }

    return 0;
}

int main(int argc, char **argv)
{

    init_config();
    init_data();
    init_database();
    init_table();
    load_table_data_to_cache();
    /* Load and verify BPF application */
    skel = logmonitor_bpf__open();
    if (!skel) {
        printf("Failed to open and load BPF skeleton\n");
        return 1;
    }

    init_thread();
    init_ebpf_parameter();
    /* Load & verify BPF programs */
	int err = logmonitor_bpf__load(skel);
	if (err) {
		printf("Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    /* Attach tracepoints */
    err = logmonitor_bpf__attach(skel);
    if (err) {
        printf("Failed to attach BPF skeleton\n");
        goto cleanup;
    }


    /* Set up ring buffer polling */
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		printf("Failed to create ring buffer\n");
		goto cleanup;
	}


	while(1) {
        err = ring_buffer__poll(rb, 1000);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            continue;
        }
        if (err < 0) {
            continue;
        }
    }



cleanup:
	ring_buffer__free(rb);
    logmonitor_bpf__destroy(skel);
	return -err;
}
