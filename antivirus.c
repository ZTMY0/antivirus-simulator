#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct FileRec {
    char *name;
    size_t size;
    int is_suspicious;
    struct FileRec *next;
};

struct Sig {
    char *pattern;
    struct Sig *next;
};

struct FileRec *clean_list = NULL;
struct FileRec *suspect_list = NULL;
struct FileRec *quarantine_list = NULL;
struct Sig *signature_list = NULL;

struct FileRec* create_file(const char *name, size_t size) {
    struct FileRec *file = malloc(sizeof(struct FileRec));
    if (file == NULL) {
        printf("Error: Memory allocation failed\n");
        return NULL;
    }
    
    file->name = malloc(strlen(name) + 1);
    if (file->name == NULL) {
        printf("Error: Memory allocation failed\n");
        free(file);
        return NULL;
    }
    
    strcpy(file->name, name);
    file->size = size;
    file->is_suspicious = 0;
    file->next = NULL;
    
    return file;
}

void insert_file(struct FileRec **head, struct FileRec *node) {
    node->next = *head;
    *head = node;
}

struct FileRec* find_file(struct FileRec *head, const char *name) {
    struct FileRec *current = head;
    while (current != NULL) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

struct FileRec* remove_file(struct FileRec **head, const char *name) {
    struct FileRec *current = *head;
    struct FileRec *prev = NULL;
    
    while (current != NULL) {
        if (strcmp(current->name, name) == 0) {
            if (prev == NULL) {
                *head = current->next;
            } else {
                prev->next = current->next;
            }
            current->next = NULL;
            return current;
        }
        prev = current;
        current = current->next;
    }
    return NULL;
}

void free_file(struct FileRec *file) {
    if (file == NULL) return;
    if (file->name) {
        free(file->name);
    }
    free(file);
}

void free_file_list(struct FileRec **head) {
    struct FileRec *current = *head;
    while (current != NULL) {
        struct FileRec *next = current->next;
        free_file(current);
        current = next;
    }
    *head = NULL;
}

int count_files(struct FileRec *head) {
    int count = 0;
    struct FileRec *current = head;
    while (current != NULL) {
        count++;
        current = current->next;
    }
    return count;
}

size_t total_bytes(struct FileRec *head) {
    size_t total = 0;
    struct FileRec *current = head;
    while (current != NULL) {
        total += current->size;
        current = current->next;
    }
    return total;
}

void print_file_list(struct FileRec *head, const char *list_name) {
    printf("\n%s:\n", list_name);
    if (head == NULL) {
        printf("  (empty)\n");
        return;
    }
    
    struct FileRec *current = head;
    int index = 1;
    while (current != NULL) {
        printf("  %d. %s (%zu bytes)", index++, current->name, current->size);
        if (current->is_suspicious) {
            printf(" [SUSPICIOUS]");
        }
        printf("\n");
        current = current->next;
    }
}

struct Sig* create_signature(const char *pattern) {
    struct Sig *sig = malloc(sizeof(struct Sig));
    if (sig == NULL) {
        printf("Error: Memory allocation failed\n");
        return NULL;
    }
    
    sig->pattern = malloc(strlen(pattern) + 1);
    if (sig->pattern == NULL) {
        printf("Error: Memory allocation failed\n");
        free(sig);
        return NULL;
    }
    
    strcpy(sig->pattern, pattern);
    sig->next = NULL;
    
    return sig;
}

void insert_signature(struct Sig **head, struct Sig *sig) {
    sig->next = *head;
    *head = sig;
}

struct Sig* find_signature(struct Sig *head, const char *pattern) {
    struct Sig *current = head;
    while (current != NULL) {
        if (strcmp(current->pattern, pattern) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

struct Sig* remove_signature(struct Sig **head, const char *pattern) {
    struct Sig *current = *head;
    struct Sig *prev = NULL;
    
    while (current != NULL) {
        if (strcmp(current->pattern, pattern) == 0) {
            if (prev == NULL) {
                *head = current->next;
            } else {
                prev->next = current->next;
            }
            current->next = NULL;
            return current;
        }
        prev = current;
        current = current->next;
    }
    return NULL;
}

void free_signature(struct Sig *sig) {
    if (sig == NULL) return;
    free(sig->pattern);
    free(sig);
}

void free_signature_list(struct Sig **head) {
    struct Sig *current = *head;
    while (current != NULL) {
        struct Sig *next = current->next;
        free_signature(current);
        current = next;
    }
    *head = NULL;
}

void print_signatures() {
    printf("\nSignature Database:\n");
    if (signature_list == NULL) {
        printf("  (empty)\n");
        return;
    }
    
    struct Sig *current = signature_list;
    int index = 1;
    while (current != NULL) {
        printf("  %d. \"%s\"\n", index++, current->pattern);
        current = current->next;
    }
}

void cmd_add_sig(const char *pattern) {
    if (find_signature(signature_list, pattern)) {
        printf("Signature '%s' already exists.\n", pattern);
        return;
    }
    
    struct Sig *sig = create_signature(pattern);
    if (sig) {
        insert_signature(&signature_list, sig);
        printf("Added signature: '%s'\n", pattern);
    }
}

void cmd_del_sig(const char *pattern) {
    struct Sig *sig = remove_signature(&signature_list, pattern);
    if (sig) {
        printf("Removed signature: '%s'\n", pattern);
        free_signature(sig);
    } else {
        printf("Signature '%s' not found.\n", pattern);
    }
}

void cmd_load(const char *name, size_t size) {
    //duplicates check
    if (find_file(clean_list, name) || 
        find_file(suspect_list, name) || 
        find_file(quarantine_list, name)) {
        printf("Error: File '%s' already exists.\n", name);
        return;
    }
    
    struct FileRec *file = create_file(name, size);
    if (file) {
        insert_file(&clean_list, file);
        printf("Loaded file: %s (%zu bytes)\n", name, size);
    }
}

void cmd_scan() {
    if (signature_list == NULL) {
        printf("No signatures loaded. Nothing to scan.\n");
        return;
    }
    
    printf("Scanning files...\n");
    
    struct FileRec *current = clean_list;
    int suspicious_count = 0;
    
    //mark sus files
    while (current != NULL) {
        struct Sig *sig = signature_list;
        while (sig != NULL) {
            if (strstr(current->name, sig->pattern) != NULL) {
                current->is_suspicious = 1;
                suspicious_count++;
                printf("  [!] %s matches pattern '%s'\n", 
                       current->name, sig->pattern);
                break;
            }
            sig = sig->next;
        }
        current = current->next;
    }
    
    //move sus files to suspect list
    current = clean_list;
    while (current != NULL) {
        struct FileRec *next = current->next;
        if (current->is_suspicious) {
            struct FileRec *removed = remove_file(&clean_list, current->name);
            insert_file(&suspect_list, removed);
        }
        current = next;
    }
    
    printf("Scan complete. Found %d suspicious file(s).\n", suspicious_count);
}

void cmd_quarantine(const char *name) {
    struct FileRec *file = remove_file(&suspect_list, name);
    if (file) {
        insert_file(&quarantine_list, file);
        printf("Quarantined: %s\n", name);
    } else {
        printf("Error: File '%s' not found in suspect list.\n", name);
    }
}

void cmd_restore(const char *name) {
    struct FileRec *file = remove_file(&quarantine_list, name);
    if (file) {
        file->is_suspicious = 0;
        insert_file(&clean_list, file);
        printf("Restored: %s\n", name);
    } else {
        printf("Error: File '%s' not found in quarantine.\n", name);
    }
}

void cmd_report() {
    printf("\n========== ANTIVIRUS REPORT ==========\n");
    
    printf("\nClean Files: %d (Total: %zu bytes)\n", 
           count_files(clean_list), total_bytes(clean_list));
    print_file_list(clean_list, "  Contents");
    
    printf("\nSuspect Files: %d (Total: %zu bytes)\n", 
           count_files(suspect_list), total_bytes(suspect_list));
    print_file_list(suspect_list, "  Contents");
    
    printf("\nQuarantined Files: %d (Total: %zu bytes)\n", 
           count_files(quarantine_list), total_bytes(quarantine_list));
    print_file_list(quarantine_list, "  Contents");
    
    print_signatures();
    
    printf("\n======================================\n");
}

void cmd_purge() {
    free_file_list(&clean_list);
    free_file_list(&suspect_list);
    free_file_list(&quarantine_list);
    free_signature_list(&signature_list);
    printf("All data purged.\n");
}

// ==================== CLI ====================

void print_help() {
    printf("\n=== TOY ANTIVIRUS COMMANDS ===\n");
    printf("  ADD_SIG <pattern>      - Add signature pattern\n");
    printf("  DEL_SIG <pattern>      - Delete signature pattern\n");
    printf("  LOAD <name> <size>     - Load a file (mock)\n");
    printf("  SCAN                   - Scan files for signatures\n");
    printf("  QUAR <name>            - Quarantine a suspect file\n");
    printf("  RESTORE <name>         - Restore from quarantine\n");
    printf("  REPORT                 - Display status report\n");
    printf("  PURGE                  - Delete all data\n");
    printf("  HELP                   - Show this help\n");
    printf("  EXIT                   - Exit program\n");
    printf("==============================\n\n");
}

int main() {
    char input[256];
    char command[64];
    char arg1[128];
    char arg2[128];
    
    printf("=== TOY ANTIVIRUS SIMULATOR ===\n");
    printf("Type HELP for commands\n");
    
    while (1) {
        printf("\n> ");
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
        }
        
        // Parse command
        int args = sscanf(input, "%s %s %s", command, arg1, arg2);
        
        if (args < 1) continue;
        
        // Convert to uppercase
        for (int i = 0; command[i]; i++) {
            command[i] = toupper(command[i]);
        }
        
        if (strcmp(command, "ADD_SIG") == 0) {
            if (args < 2) {
                printf("Usage: ADD_SIG <pattern>\n");
            } else {
                cmd_add_sig(arg1);
            }
        }
        else if (strcmp(command, "DEL_SIG") == 0) {
            if (args < 2) {
                printf("Usage: DEL_SIG <pattern>\n");
            } else {
                cmd_del_sig(arg1);
            }
        }
        else if (strcmp(command, "LOAD") == 0) {
            if (args < 3) {
                printf("Usage: LOAD <name> <size>\n");
            } else {
                size_t size = atoi(arg2);
                cmd_load(arg1, size);
            }
        }
        else if (strcmp(command, "SCAN") == 0) {
            cmd_scan();
        }
        else if (strcmp(command, "QUAR") == 0) {
            if (args < 2) {
                printf("Usage: QUAR <name>\n");
            } else {
                cmd_quarantine(arg1);
            }
        }
        else if (strcmp(command, "RESTORE") == 0) {
            if (args < 2) {
                printf("Usage: RESTORE <name>\n");
            } else {
                cmd_restore(arg1);
            }
        }
        else if (strcmp(command, "REPORT") == 0) {
            cmd_report();
        }
        else if (strcmp(command, "PURGE") == 0) {
            cmd_purge();
        }
        else if (strcmp(command, "HELP") == 0) {
            print_help();
        }
        else if (strcmp(command, "EXIT") == 0) {
            printf("Cleaning up and exiting...\n");
            cmd_purge();
            break;
        }
        else {
            printf("Unknown command: %s (type HELP for commands)\n", command);
        }
    }
    
    return 0;
}