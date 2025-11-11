# Toy Antivirus
---

## What I Built

I made a simple antivirus simulator that manages files using linked lists. The program can detect suspicious files by matching patterns in their names and move them between different lists (Clean, Suspect, and Quarantine).

It's not a real antivirus - I'm just working with fake files that have a name and size. But it uses the same ideas as real antivirus software: scanning files against signatures, isolating suspicious ones, and managing them in different categories.

---

## How My Program Works

I have four linked lists in my program:
- **Clean files** - Normal files that haven't been flagged yet
- **Suspect files** - Files that matched a malware signature when I scanned
- **Quarantine** - Suspicious files that I isolated
- **Signatures** - The patterns I use to detect malware (like "virus" or "trojan")

### What happens when you use it:

**Loading files:** When I load a file, it goes into the clean list. I check if the name already exists so there's no duplicates.

**Scanning:** The scan function goes through each clean file and checks if the filename contains any of the signature patterns. If it finds a match, it marks that file as suspicious and moves it to the suspect list.

**Quarantine:** I can manually quarantine suspect files. This moves them from the suspect list to quarantine.

**Restore:** If I made a mistake and quarantined a safe file, I can restore it back to clean.

---

## The Data Structures I Used

### File Node
```c
struct FileRec {
    char *name;              // The filename
    size_t size;             // How big the file is
    int is_suspicious;       // 0 or 1 flag
    struct FileRec *next;    // Points to next file in list
};
```

I used `char *name` instead of a fixed array because filenames can be different lengths. I allocate the exact amount of memory I need.

### Signature Node
```c
struct Sig {
    char *pattern;           // The pattern to look for
    struct Sig *next;        // Next signature
};
```

Same idea - I don't know how long the pattern will be, so I use a pointer and allocate memory dynamically.

---

## Important Functions I Wrote

### Creating Files
```c
struct FileRec* create_file(const char *name, size_t size)
```

This allocates memory for a new file node. I have to allocate memory twice - once for the struct itself, and once for the filename string. If either allocation fails, I clean up and return NULL.

I learned that when allocating for strings, I need to add 1 for the null terminator: `strlen(name) + 1`.

### Removing Files from Lists

This was the hardest function to get right:

```c
struct FileRec* remove_file(struct FileRec **head, const char *name)
```

I had to handle three different cases:
1. **Removing the first file** - I need to update the head pointer
2. **Removing a middle file** - Connect the previous node to the next one
3. **Removing the last file** - The previous node becomes the new tail

I keep track of both the current node and the previous node while looping through the list. The function returns the removed node instead of freeing it, because sometimes I want to reuse it in another list (like when quarantining).

### The Scan Function

```c
void cmd_scan()
```

I had some trouble with this one at first. My initial version tried to move files while I was looping through the list, which caused problems - sometimes files would get skipped.

My solution was to do it in two phases:
1. **Mark phase:** Go through the clean list and mark files as suspicious if they match any signature
2. **Move phase:** Go through again and move all the marked files to the suspect list

This way I'm not modifying the list while I'm iterating through it.

---

## Commands Available

Here's what you can do with my program:

| Command | Example | What it does |
|---------|---------|-------------|
| ADD_SIG | `ADD_SIG virus` | Adds a malware pattern |
| DEL_SIG | `DEL_SIG virus` | Removes a pattern |
| LOAD | `LOAD file.txt 1024` | Creates a mock file |
| SCAN | `SCAN` | Checks files for patterns |
| QUAR | `QUAR file.txt` | Moves file to quarantine |
| RESTORE | `RESTORE file.txt` | Moves file back to clean |
| REPORT | `REPORT` | Shows everything |
| PURGE | `PURGE` | Deletes all data |
| EXIT | `EXIT` | Quits the program |

---

## Example of Using It

```
> ADD_SIG virus
Added signature: 'virus'

> LOAD document.txt 1024
Loaded file: document.txt (1024 bytes)

> LOAD virus.exe 2048
Loaded file: virus.exe (2048 bytes)

> SCAN
Scanning files...
  [!] virus.exe matches pattern 'virus'
Scan complete. Found 1 suspicious file(s).

> QUAR virus.exe
Quarantined: virus.exe

> REPORT
Clean Files: 1 (Total: 1024 bytes)
  1. document.txt (1024 bytes)

Suspect Files: 0 (Total: 0 bytes)
  (empty)

Quarantined Files: 1 (Total: 2048 bytes)
  1. virus.exe (2048 bytes) [SUSPICIOUS]
```

---

## Problems I Ran Into

### 1. The remove_file function
At first I kept getting segmentation faults because I wasn't handling all the edge cases. I had to draw it out on paper to understand what happens when you remove the head vs the middle vs the tail of the list.

### 2. Scanning while modifying
Like I mentioned earlier, I tried to move files to the suspect list while scanning and it broke everything. Some files got skipped, some got lost. The two-phase approach fixed it.

### 3. Memory management
I kept forgetting to free the filename strings before freeing the file struct. Valgrind helped me find these leaks. Now I have helper functions like `free_file()` and `free_file_list()` that do cleanup properly.

### 4. Null terminators
I had a bug where filenames were getting corrupted. Turned out I wasn't allocating enough space - forgot about the null terminator at the end of C strings.

---

## How I Tested It

I tested these scenarios:
- Empty lists (scanning nothing, quarantining from empty list)
- Single file operations
- Multiple files (especially removing different positions)
- Duplicate names (program should reject them)
- Long filenames
- Running Valgrind to check for memory leaks

Valgrind showed no memory leaks, which I'm happy about.

---


## Things I Could Add Later

If I had more time or wanted to improve this, I could:

- **Scan actual files** instead of just mock ones with names and sizes
- **Add wildcards** like `*.exe` in the signatures
- **Save the signatures** to a file so they're not lost when I exit
- **Count statistics** like how many scans I've done or detection rate
- **Use a hash table** instead of linked lists for faster searching (right now searching is O(n))

These are all things we might learn more about later in the course.

---

## Conclusion

This project taught me a lot about pointers and memory management in C. The hardest part was getting `remove_file()` right for all the different cases. I'm satisfied that my program works correctly and doesn't leak memory.

The program does what it's supposed to do - it manages files in linked lists, scans them for patterns, and moves them around efficiently by rewiring pointers instead of copying data.

---

## How to Compile and Run

```bash
# Compile
gcc -Wall -Wextra -o antivirus antivirus.c

# Run
./antivirus

# Check for memory leaks
valgrind --leak-check=full ./antivirus
```
