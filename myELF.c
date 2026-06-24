#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>

// struct to save the state of each opened ELF file
typedef struct {
    int fd;
    void *map_start;
    off_t file_size;
    char file_name[128];
} ElfFileState;

// global variables
ElfFileState elf_files[2];
int num_open_files = 0;
int debug_mode = 0;

// declarations of menu functions
void toggle_debug();
void examine_elf_file();
void print_section_names();
void print_symbols();
void print_relocations();
void check_files_merge();
void merge_elf_files();
void quit();

// struct for menu items
struct fun_desc {
    char *name;
    void (*fun)();
};

struct fun_desc menu[] = {
    {"Toggle Debug Mode", toggle_debug},
    {"Examine ELF File", examine_elf_file},
    {"Print Section Names", print_section_names},
    {"Print Symbols", print_symbols},
    {"Print Relocations", print_relocations},
    {"Check Files for Merge", check_files_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit},
    {NULL, NULL}
};

int main() {
    int choice;
    int menu_size = 0;

    // calculate menu size
    while (menu[menu_size].name != NULL) {
        menu_size++;
    }

    // main loop
    while (1) {
        printf("\nChoose action:\n");
        for (int i = 0; i < menu_size; i++) {
            printf("%d- %s\n", i, menu[i].name);
        }
        printf("Option: ");
        
        if (scanf("%d", &choice) != 1) {
            break; // exit if input is not a number
        }

        if (choice >= 0 && choice < menu_size) {
            menu[choice].fun();
        } else {
            printf("Invalid choice\n");
        }
    }
    return 0;
}

// the menu functions
void toggle_debug() {
    debug_mode = !debug_mode;
    printf("Debug flag now %s\n", debug_mode ? "on" : "off");
}

// ---- part 1 - print section names ----
void print_section_names() {
    // make sure at least one file is open
    if (num_open_files == 0) {
        printf("Error: No ELF files currently opened.\n");
        return;
    }

    // run through all open files in our array
    for (int i = 0; i < num_open_files; i++) {
        ElfFileState current_file = elf_files[i];
        
        // get the header of the current file
        Elf32_Ehdr *header = (Elf32_Ehdr *)current_file.map_start;

        printf("\nFile %s sections:\n", current_file.file_name);
        printf("[index] section_name\tsection_address section_offset section_size\tsection_type\n");

        // section header table: find the location of the section header table and the number of entries
        // the header gives us the offset of the section header table (e_shoff) and the number of entries (e_shnum)
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)current_file.map_start + header->e_shoff);

        // find the string table (.shstrtab)
        // the header tells us which index in the table contains the string table (e_shstrndx)
        Elf32_Shdr *string_table_section = &section_headers[header->e_shstrndx];
        
        // calculate the exact address of the string table in memory
        char *string_table = (char *)current_file.map_start + string_table_section->sh_offset;

        if (debug_mode) {
            printf("DEBUG: shstrndx = %d\n", header->e_shstrndx);
            printf("DEBUG: section header table offset = %d\n", header->e_shoff);
        }

        // loop through all sections one by one
        for (int j = 0; j < header->e_shnum; j++) {
            Elf32_Shdr *current_section = &section_headers[j];
            
            // retrieving the name: we go to the "string table" and add the offset of the name (sh_name)
            char *section_name = string_table + current_section->sh_name;

            // printing all the data of the section in a single formatted line
            printf("[%2d]\t%-15s\t%08x\t%06x\t\t%06x\t\t%x\n",
                   j,
                   section_name,
                   current_section->sh_addr,
                   current_section->sh_offset,
                   current_section->sh_size,
                   current_section->sh_type);
        }
    }
}

// ---- end of part 1 ----

// ---- part 2a ---- ////
void print_symbols() {
    if (num_open_files == 0) {
        printf("Error: No ELF files currently opened.\n");
        return;
    }

    for (int i = 0; i < num_open_files; i++) {
        ElfFileState current_file = elf_files[i];
        Elf32_Ehdr *header = (Elf32_Ehdr *)current_file.map_start;
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)current_file.map_start + header->e_shoff);
        
        Elf32_Shdr *symtab = NULL;
        Elf32_Shdr *strtab = NULL;
        
        // table of section names (to print section_name)
        Elf32_Shdr *shstrtab = &section_headers[header->e_shstrndx];
        char *section_strings = (char *)current_file.map_start + shstrtab->sh_offset;

        // we need to find the symbol table (.symtab) and the string table (.strtab) associated with it
        for (int j = 0; j < header->e_shnum; j++) {
            if (section_headers[j].sh_type == SHT_SYMTAB) {
                symtab = &section_headers[j];
                // the symbol table section header's sh_link field gives us the index of the string table that contains the symbol names
                strtab = &section_headers[symtab->sh_link]; 
                break;
            }
        }

        if (symtab == NULL || strtab == NULL) {
            printf("File %s has no symbol table.\n", current_file.file_name);
            continue;
        }

        printf("\nFile %s symbols:\n", current_file.file_name);
        printf("[index] value\t\tsection_index\tsection_name\tsymbol_name\n");

        int num_symbols = symtab->sh_size / symtab->sh_entsize;
        Elf32_Sym *symbol_table = (Elf32_Sym *)((char *)current_file.map_start + symtab->sh_offset);
        char *symbol_strings = (char *)current_file.map_start + strtab->sh_offset;

        if (debug_mode) {
            printf("DEBUG: Symbol table size = %d, Number of symbols = %d\n", symtab->sh_size, num_symbols);
        }

        // run all the symbols in the symbol table one by one and print their data
        for (int j = 0; j < num_symbols; j++) {
            Elf32_Sym *sym = &symbol_table[j];

            // find the name of the symbol
            char *sym_name = symbol_strings + sym->st_name;
            
            char *sec_name = "";
            char index_str[16];
            
            // check the section index of the symbol and determine the appropriate string to print
            if (sym->st_shndx == SHN_UNDEF) {
                strcpy(index_str, "UND");
            } else if (sym->st_shndx == SHN_ABS) {
                strcpy(index_str, "ABS");
            } else if (sym->st_shndx < header->e_shnum) {
                sprintf(index_str, "%d", sym->st_shndx);
                // extract the section name from the .shstrtab using the section index (st_shndx) of the symbol
                sec_name = section_strings + section_headers[sym->st_shndx].sh_name;
            } else {
                strcpy(index_str, "UNKNOWN");
            }

            printf("[%2d]\t%08x\t%-10s\t%-15s\t%s\n",
                   j,
                   sym->st_value,
                   index_str,
                   sec_name,
                   sym_name);
        }
    }
}
// ---- end of part 2a ---- //

// ---- part 2b ---- //
void print_relocations() {
    if (num_open_files == 0) {
        printf("Error: No ELF files currently opened.\n");
        return;
    }

    for (int i = 0; i < num_open_files; i++) {
        ElfFileState current_file = elf_files[i];
        Elf32_Ehdr *header = (Elf32_Ehdr *)current_file.map_start;
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)current_file.map_start + header->e_shoff);
        
        int found_relocations = 0;
        printf("\nFile %s relocations:\n", current_file.file_name);
        
        // go over all sections and look for relocation sections (SHT_REL)
        for (int j = 0; j < header->e_shnum; j++) {
            if (section_headers[j].sh_type == SHT_REL) {
                found_relocations = 1;
                Elf32_Shdr *rel_section = &section_headers[j];
                
                // pointer to the symbol table associated with this relocation section
                Elf32_Shdr *symtab = &section_headers[rel_section->sh_link];
                Elf32_Sym *symbol_table = (Elf32_Sym *)((char *)current_file.map_start + symtab->sh_offset);
                
                // pointer to the string table associated with the symbol table
                Elf32_Shdr *strtab = &section_headers[symtab->sh_link];
                char *symbol_strings = (char *)current_file.map_start + strtab->sh_offset;

                int num_relocations = rel_section->sh_size / rel_section->sh_entsize;
                Elf32_Rel *reloc_table = (Elf32_Rel *)((char *)current_file.map_start + rel_section->sh_offset);

                printf(" Relocation section at offset 0x%x contains %d entries:\n", rel_section->sh_offset, num_relocations);
                printf("[index] offset\t\ttype\tsymbol_name\n");

                for (int k = 0; k < num_relocations; k++) {
                    Elf32_Rel *rel = &reloc_table[k];
                    
                    // extract the symbol index and the reloation type
                    int sym_index = ELF32_R_SYM(rel->r_info);
                    int rel_type = ELF32_R_TYPE(rel->r_info);
                    
                    char *sym_name = "";
                    if (sym_index != 0) { // demi symbol index 0 is reserved for undefined symbols
                        Elf32_Sym *sym = &symbol_table[sym_index];
                        sym_name = symbol_strings + sym->st_name;
                    }

                    printf("[%2d]\t%08x\t%d\t%s\n", k, rel->r_offset, rel_type, sym_name);
                }
                printf("\n");
            }
        }
        
        if (!found_relocations) {
            printf("No relocations found.\n");
        }
    }
}
// ---- end of part 2b ---- //

// ---- part 3a ---- //
void check_files_merge() {
    if (num_open_files != 2) {
        printf("Error: Exactly 2 ELF files must be opened for merge check.\n");
        return;
    }

    ElfFileState file1 = elf_files[0];
    ElfFileState file2 = elf_files[1];

    Elf32_Ehdr *header1 = (Elf32_Ehdr *)file1.map_start;
    Elf32_Ehdr *header2 = (Elf32_Ehdr *)file2.map_start;

    Elf32_Shdr *sec_headers1 = (Elf32_Shdr *)((char *)file1.map_start + header1->e_shoff);
    Elf32_Shdr *sec_headers2 = (Elf32_Shdr *)((char *)file2.map_start + header2->e_shoff);

    Elf32_Shdr *symtab1 = NULL, *strtab1 = NULL;
    Elf32_Shdr *symtab2 = NULL, *strtab2 = NULL;

    // find the symbol and string tables for both files
    for (int i = 0; i < header1->e_shnum; i++) {
        if (sec_headers1[i].sh_type == SHT_SYMTAB) {
            symtab1 = &sec_headers1[i];
            strtab1 = &sec_headers1[symtab1->sh_link];
        }
    }
    for (int i = 0; i < header2->e_shnum; i++) {
        if (sec_headers2[i].sh_type == SHT_SYMTAB) {
            symtab2 = &sec_headers2[i];
            strtab2 = &sec_headers2[symtab2->sh_link];
        }
    }

    if (!symtab1 || !symtab2) {
        printf("Error: Feature not supported (missing symbol table).\n");
        return;
    }

    Elf32_Sym *symbols1 = (Elf32_Sym *)((char *)file1.map_start + symtab1->sh_offset);
    char *strings1 = (char *)file1.map_start + strtab1->sh_offset;
    Elf32_Sym *symbols2 = (Elf32_Sym *)((char *)file2.map_start + symtab2->sh_offset);
    char *strings2 = (char *)file2.map_start + strtab2->sh_offset;

    int num_syms1 = symtab1->sh_size / symtab1->sh_entsize;
    int num_syms2 = symtab2->sh_size / symtab2->sh_entsize;

    printf("\nChecking merge compatibility...\n");

    for (int i = 1; i < num_syms1; i++) {
        Elf32_Sym *sym1 = &symbols1[i];
        char *name1 = strings1 + sym1->st_name;
        if (strlen(name1) == 0) continue;

        int found_in_2 = 0;
        Elf32_Sym *sym2_match = NULL;

        for (int j = 1; j < num_syms2; j++) {
            if (strcmp(name1, strings2 + symbols2[j].st_name) == 0) {
                found_in_2 = 1;
                sym2_match = &symbols2[j];
                break;
            }
        }

        // if the symbol is defined in file 1, it must not be defined in file 2 (or must not appear at all)
        if (sym1->st_shndx != SHN_UNDEF) {
            if (found_in_2 && sym2_match->st_shndx != SHN_UNDEF) {
                printf("Error: Symbol %s multiply defined\n", name1);
            }
        } 
        // if the symbol is not defined in file 1, it must be defined in file 2
        else {
            if (!found_in_2 || sym2_match->st_shndx == SHN_UNDEF) {
                printf("Error: Symbol %s undefined\n", name1);
            }
        }
    }

    // second direction: loop through file 2 and look in file 1
    for (int i = 1; i < num_syms2; i++) {
        Elf32_Sym *sym2 = &symbols2[i];
        char *name2 = strings2 + sym2->st_name;
        if (strlen(name2) == 0) continue;

        int found_in_1 = 0;
        Elf32_Sym *sym1_match = NULL;

        // search for the sign from file 2 in file 1
        for (int j = 1; j < num_syms1; j++) {
            if (strcmp(name2, strings1 + symbols1[j].st_name) == 0) {
                found_in_1 = 1;
                sym1_match = &symbols1[j];
                break;
            }
        }

        // if the sign is define in file 2 check if it is also defined in file 1 
        if (sym2->st_shndx != SHN_UNDEF) {
            if (found_in_1 && sym1_match->st_shndx != SHN_UNDEF) {
                printf("Error: Symbol %s multiply defined\n", name2);
            }
        } 
        // if it is not defined in file 2 and not in/ not defined in file 1
        else {
            if (!found_in_1 || sym1_match->st_shndx == SHN_UNDEF) {
                printf("Error: Symbol %s undefined\n", name2);
            }
        }
    }

    
    printf("Check completed.\n");
}
// ---- end of part 3a ---- //

// ---- part 3b ---- //
void merge_elf_files() {
    if (num_open_files != 2) {
        printf("Error: Need 2 open files to merge.\n");
        return;
    }

    FILE *out = fopen("out.ro", "wb");
    if (!out) {
        perror("Cannot create out.ro");
        return;
    }

    ElfFileState f1 = elf_files[0];
    ElfFileState f2 = elf_files[1];
    
    Elf32_Ehdr *h1 = (Elf32_Ehdr *)f1.map_start;
    Elf32_Shdr *s1 = (Elf32_Shdr *)((char *)f1.map_start + h1->e_shoff);
    Elf32_Shdr *s2 = (Elf32_Shdr *)((char *)f2.map_start + ((Elf32_Ehdr*)f2.map_start)->e_shoff);

    // copy header 
    Elf32_Ehdr out_hdr = *h1;
    fwrite(&out_hdr, sizeof(Elf32_Ehdr), 1, out);

    // section tables
    Elf32_Shdr new_shdrs[h1->e_shnum];
    memcpy(new_shdrs, s1, sizeof(Elf32_Shdr) * h1->e_shnum);

    // loop for merge and writing sections
    // the header of the first section starts after the offset
    //off_t current_offset = sizeof(Elf32_Ehdr);

    // Get the section string table of the first file
    char *str_table = (char *)f1.map_start + s1[h1->e_shstrndx].sh_offset;

    for (int i = 0; i < h1->e_shnum; i++) {
        char *name = str_table + s1[i].sh_name;
        
        // check if we need to merge the section
        if (strcmp(name, ".text") == 0 || strcmp(name, ".data") == 0 || strcmp(name, ".rodata") == 0) {
            // write the section from the first file
            new_shdrs[i].sh_offset = ftell(out);
            fwrite((char *)f1.map_start + s1[i].sh_offset, s1[i].sh_size, 1, out);
            
            // search for the section in the other file
            char *str_table2 = (char *)f2.map_start + s2[((Elf32_Ehdr*)f2.map_start)->e_shstrndx].sh_offset;
            for (int j = 0; j < ((Elf32_Ehdr*)f2.map_start)->e_shnum; j++) {
                if (strcmp(str_table2 + s2[j].sh_name, name) == 0) {
                    // write from the seconf file
                    fwrite((char *)f2.map_start + s2[j].sh_offset, s2[j].sh_size, 1, out);
                    // update the size of the new sections, the sum of sizes
                    new_shdrs[i].sh_size += s2[j].sh_size;
                    break;
                }
            }
        } 
        // if we dont need to merge this section, just copy it
        else if (s1[i].sh_type != SHT_NOBITS && s1[i].sh_offset != 0) {
            new_shdrs[i].sh_offset = ftell(out);
            fwrite((char *)f1.map_start + s1[i].sh_offset, s1[i].sh_size, 1, out);
        }
    }

    // write the updated table and updaye the header
    out_hdr.e_shoff = ftell(out);
    fwrite(new_shdrs, sizeof(Elf32_Shdr), h1->e_shnum, out);
    
    fseek(out, 0, SEEK_SET);
    fwrite(&out_hdr, sizeof(Elf32_Ehdr), 1, out);

    fclose(out);
    printf("Successfully created out.ro\n");
}
// ---- end of part 3b ---- //

// function to examine an ELF file
void examine_elf_file() {
    char filename[128];
    printf("Enter ELF file name: ");
    scanf("%127s", filename);

    if (num_open_files >= 2) {
        printf("Error: Maximum of 2 files can be opened.\n");
        return;
    }

    int current_idx = num_open_files;
    
    // open the file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error opening file");
        return;
    }

    // get the file size
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) != 0) {
        perror("Error stating file");
        close(fd);
        return;
    }

    // map the file into memory
    void *map_start = mmap(NULL, fd_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        return;
    }

    // check if it's an ELF file
    Elf32_Ehdr *header = (Elf32_Ehdr *)map_start;
    if (strncmp((char *)header->e_ident + 1, "ELF", 3) != 0) {
        printf("Error: Not an ELF file\n");
        munmap(map_start, fd_stat.st_size);
        close(fd);
        return;
    }

    // save the data in the global array
    elf_files[current_idx].fd = fd;
    elf_files[current_idx].map_start = map_start;
    elf_files[current_idx].file_size = fd_stat.st_size;
    strncpy(elf_files[current_idx].file_name, filename, 127);
    
    num_open_files++;

    // print the data from the ELF header
    printf("Magic bytes: %c %c %c\n", header->e_ident[1], header->e_ident[2], header->e_ident[3]);
    
    printf("Data encoding scheme: ");
    switch (header->e_ident[EI_DATA]) {
        case ELFDATA2LSB:
            printf("2's complement, little endian\n");
            break;
        case ELFDATA2MSB:
            printf("2's complement, big endian\n");
            break;
        default:
            printf("Unknown data format\n");
            break;
    }
    
    printf("Entry point (hexadecimal address): 0x%x\n", header->e_entry);
    printf("Section header table file offset: %d\n", header->e_shoff);
    printf("Number of section header entries: %d\n", header->e_shnum);
    printf("Size of each section header entry: %d\n", header->e_shentsize);
    printf("Program header table file offset: %d\n", header->e_phoff);
    printf("Number of program header entries: %d\n", header->e_phnum);
    printf("Size of each program header entry: %d\n", header->e_phentsize);
}

void quit() {
    // release resources for all open files
    for (int i = 0; i < num_open_files; i++) {
        if (elf_files[i].map_start != NULL) {
            munmap(elf_files[i].map_start, elf_files[i].file_size);
        }
        if (elf_files[i].fd >= 0) {
            close(elf_files[i].fd);
        }
    }
    if (debug_mode) {
        printf("Quitting... unmapped %d files.\n", num_open_files);
    }
    exit(0);
}

