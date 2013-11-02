#include "loader.h"
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

/* Wyrównuje offset przy mmap() do początku strony. */
#define align_off(offset) (offset & ~(sysconf(_SC_PAGE_SIZE)-1))
/* Wylicza długość obszaru do zamapowania. */
#define align_len(size, offset) (size + align_off(offset))
/* Wylicza o ile należy przesunąć wskaźnik względem początku zamapowanego
 * obszaru, żeby otrzymać wskaźnik do "właściwych" danych. */
#define move_off(offset) (offset - align_off(offset))

/* Skróty do pól z nagłówków sekcji. */
#define get_shdr(index)         (mod->shdr_array->array[index])
#define get_shdr_flags(index)   (get_shdr(index).sh_flags)
#define get_shdr_info(index)    (get_shdr(index).sh_info)
#define get_shdr_link(index)    (get_shdr(index).sh_link)
#define get_shdr_offset(index)  (get_shdr(index).sh_offset)
#define get_shdr_size(index)    (get_shdr(index).sh_size)
#define get_shdr_type(index)    (get_shdr(index).sh_type)
/* Skróty do pól tablicy symboli. */
#define get_symbol(index)       (mod->symtab->symtab[index])

/* Struktura dla pojedynczej sekcji pliku ELF. */
struct section {
    int idx;                /* Indeks w tablicy sekcji. */
    void *addr_mmap;        /* Wskaźnik do początku zamapowanej pamięci. */
    void *addr;             /* Wskaźnik do właściwych danych sekcji,
                             * bez wyrównania do początku strony. */
    struct section *next;   /* Wskaźnik do następnej sekcji w liście. */
};
/* Struktura dla pojedynczego symbolu. */
struct symbol {
    Elf32_Word idx;         /* Indeks w tablicy symboli. */
    Elf32_Sym *sym;         /* */
    void *addr;             /* Adres symbolu. */
    char *name;             /* Nazwa symbolu. */
    struct symbol *next;    /* Wskaźnik do następnego symbolu w liście. */
};
struct Elf32_Shdr_Wrap {
    Elf32_Shdr *array;      /* Tablica nagłówków sekcji. */
    void *mmap_ptr;         /* Wskaźnik do początku zamapowanej pamięci. */
    Elf32_Word size;        /* */
    Elf32_Off offset;       /* */
};
struct Elf32_Sym_Wrap {
    int idx;                /* Indeks w tablicy nagłówków sekcji. */
    Elf32_Sym *symtab;      /* Tablica symboli. */
    void *mmap_ptr;         /* Wskaźnik do początku zamapowanej pamięci. */
};
struct Elf32_Rel_Wrap {
    int idx;                /* Indeks w tablicy nagłówków sekcji. */
    Elf32_Rel *array;       /* Tablica relokacji. */
    void *mmap_ptr;         /* Wskaźnik do początku zaalokowanej pamięci. */
};
/* Struktura dla modułu. */
struct module {
    int fd;                         /* Deskryptor pliku ELF. */
    Elf32_Ehdr *file_hdr;           /* Nagłówek pliku ELF. */
    struct Elf32_Shdr_Wrap *shdr_array;
    struct section *sections_list;  /* */
    struct section *strtab;         /* */
    struct Elf32_Sym_Wrap *symtab;  /* */
    struct symbol *symbols_list;    /* */
    struct Elf32_Rel_Wrap *rel;     /* */
};

static void add_section(struct section *sec, struct module *mod) {
    sec->next = mod->sections_list;
    mod->sections_list = sec;
}
static void add_symbol(struct symbol *sym, struct module *mod) {
    sym->next = mod->symbols_list;
    mod->symbols_list = sym;
}
static struct section *get_section(int index, struct module *mod) {
    struct section *result = mod->sections_list;
    while (result != NULL) {
        if (result->idx == index) return result;
        result = result->next;
    }
    return result;
}
static struct symbol *get_symbol2(Elf32_Word idx, struct module *mod) {
    struct symbol *result = mod->symbols_list;
    while (result != NULL) {
        if (idx == result->idx) return result;
        result = result->next;
    }
    return result;
}
/*
 * Funkcje do czyszczenia pamięci po unload lub po błędzie w load.
 */
static void unmap_relocation(struct module *mod) {
    if(mod->rel != NULL && mod->rel->mmap_ptr > 0)
        munmap(mod->rel->mmap_ptr,
                align_len(get_shdr_size(mod->rel->idx),
                        get_shdr_offset(mod->rel->idx)));
}
static void free_relocation_table(struct module *mod) { 
    if (mod->rel != NULL)
        free(mod->rel);
}
static void free_symbols(struct module *mod) {
    struct symbol *sym_it = mod->symbols_list;
    struct symbol *sym_tmp = NULL;
    while (sym_it != NULL) {
        sym_tmp = sym_it->next;
        free(sym_it);
        sym_it = sym_tmp;
    }
}
static void unmap_free_symbol_table(struct module *mod) {
    if (mod->symtab->mmap_ptr > 0) 
        munmap(mod->symtab->mmap_ptr,
                align_len(get_shdr_size(mod->symtab->idx),
                        get_shdr_offset(mod->symtab->idx)));
    free(mod->symtab);
}
static void unmap_free_string_table(struct module *mod) {
        if (mod->strtab->addr_mmap > 0)
        munmap(mod->strtab->addr_mmap,
                align_len(get_shdr_size(mod->strtab->idx),
                        get_shdr_offset(mod->strtab->idx)));
    free(mod->strtab);
}
static void unmap_free_sections(struct module *mod) {
    struct section *sec_it = mod->sections_list;
    struct section *sec_tmp = NULL;
    while (sec_it != NULL) {
        sec_tmp = sec_it->next;
        if (sec_it->addr_mmap > 0)
            munmap(sec_it->addr_mmap,
                    align_len(get_shdr_size(sec_it->idx), 
                            get_shdr_offset(sec_it->idx)));
        free(sec_it);
        sec_it = sec_tmp;
    }
}
static void unmap_free_section_headers(struct module *mod) {
    if (mod->shdr_array->mmap_ptr > 0)
        munmap(mod->shdr_array->mmap_ptr,
                align_len(mod->shdr_array->size, mod->shdr_array->offset));
    free(mod->shdr_array);
}
static void unmap_file_header(struct module *mod) {
    munmap(mod->file_hdr, sizeof(Elf32_Ehdr));
}
static void close_file(struct module *mod) { close(mod->fd); }
static void free_module(struct module *mod) { if (mod != NULL) free(mod); }

/* Funkcja biblioteczna. */
struct module *module_load(const char *filename, getsym_t getsym_fun,
		void *getsym_arg) {
	int i, j;
	
	struct module *mod = (struct module *) malloc(sizeof(struct module));
	if (mod == NULL)
	    return NULL;
    mod->symbols_list = NULL;  /* Jak poniżej. */ 
    mod->sections_list = NULL; /* Żeby valgrind nie krzyczał. */
	
    /* Otwieranie pliku modułu. */
	mod->fd = open(filename, O_RDONLY);
	if (mod->fd == 0)
	    goto error_open;
	
	/* Ładowanie nagłówka pliku do pamięci. */
	mod->file_hdr = (Elf32_Ehdr *) mmap(NULL, sizeof(Elf32_Ehdr), 
            PROT_READ | PROT_WRITE, MAP_PRIVATE, mod->fd, 0);
	if (mod->file_hdr < 0)
	    goto error_file_hdr_mmap;
	    
	/* Sprawdzanie poprawności pól nagłówka. */
	if (mod->file_hdr->e_ident[EI_MAG0] != ELFMAG0 ||     /* ELF Magic Number [0]. */
	    mod->file_hdr->e_ident[EI_MAG1] != ELFMAG1 ||     /* ELF Magic Number [1]. */
	    mod->file_hdr->e_ident[EI_MAG2] != ELFMAG2 ||     /* ELF Magic Number [2]. */
	    mod->file_hdr->e_ident[EI_MAG3] != ELFMAG3 ||     /* ELF Magic Number [3]. */
	    mod->file_hdr->e_ident[EI_CLASS] != ELFCLASS32 || /* ELF File Class. */
	    mod->file_hdr->e_ident[EI_VERSION] != EV_CURRENT  /* ELF header version number. */
	)    
	    goto error_invalid_file_hdr;
    
    /* Nagłówki sekcji. */    
    mod->shdr_array = 
        (struct Elf32_Shdr_Wrap *) malloc(sizeof(struct Elf32_Shdr_Wrap)); 
    if (mod->shdr_array == NULL)
        goto error_shdr_array_malloc;

	Elf32_Off array_offset = mod->file_hdr->e_shoff;
	Elf32_Half e_count = mod->file_hdr->e_shnum;
	Elf32_Half e_size = mod->file_hdr->e_shentsize;
	
    mod->shdr_array->size = align_len(e_count * e_size, array_offset);
    mod->shdr_array->offset = array_offset;   
	
    /* Mapowanie tablicy nagłówków sekcji. */   
	mod->shdr_array->mmap_ptr = mmap(NULL, 
            align_len(mod->shdr_array->size, array_offset),
            PROT_READ | PROT_WRITE, MAP_PRIVATE, mod->fd, 
            align_off(array_offset));
    if (mod->shdr_array->mmap_ptr < 0)
	    goto error_section_headers_array_mmap; 
    mod->shdr_array->array = 
        (Elf32_Shdr *) (mod->shdr_array->mmap_ptr + move_off(array_offset));

	/* Mapowanie sekcji. */
	for (i = 0; i < e_count; ++i) {
	    if (get_shdr_size(i) == 0) /* Puste sekcje są nieciekawe. */
            continue;
        /* Nie trzeba alokować sekcji w pamięci. */
        if (!(get_shdr_flags(i) & SHF_ALLOC))
            continue;
        /* Te typy sekcji obsługujemy później. */
        if (get_shdr_type(i) == SHT_SYMTAB ||
            get_shdr_type(i) == SHT_STRTAB ||
            get_shdr_type(i) == SHT_REL)
            continue;
        
        /* Sekcja PROGBITS lub NOBITS o niezerowej wielkości i z flagą ALLOC. */
	    struct section *sec =
            (struct section *) malloc(sizeof(struct section));
	    if (sec == NULL)
	        goto error_section_mapping;
	    sec->next = sec->addr = sec->addr_mmap = NULL;
        sec->idx = i;
        add_section(sec, mod);
        
        if (get_shdr_type(i) == SHT_NOBITS) {
            /* Mapujemy pamięć wypełnioną zerami (gwarancja z flagą ANON). */
            sec->addr_mmap = sec->addr = mmap(NULL, get_shdr_size(sec->idx),
                    PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0); 
            if (sec->addr_mmap < 0)
                goto error_section_mapping;
        }
        else { /* Zakładamy, że każda inna sekcja jest PROGBITS. */        
            Elf32_Off offset = get_shdr_offset(i);
	        sec->addr_mmap = mmap(NULL, 
                    align_len(get_shdr_size(sec->idx), offset),
                    PROT_READ | PROT_WRITE, MAP_PRIVATE, mod->fd,
                    align_off(offset));
	        if (sec->addr_mmap < 0)
	            goto error_section_mapping;
            sec->addr = (sec->addr_mmap + move_off(offset));
        }
	}

    /* Znajdowanie tablicy symboli i jej sekcji STRTAB. */
    Elf32_Word symtab_idx = -1;
    Elf32_Word strtab_idx = -1;
    for (i = 0; i < e_count; ++i) {
        if (get_shdr_type(i) == SHT_SYMTAB) {
            symtab_idx = i;
            strtab_idx = get_shdr_link(i);
            break;
        }
    }
    /* Jeśli nie ma tablicy symboli (i powiązanej tablicy napisów,
     * to zwracamy błąd. */
    if (symtab_idx == -1 || strtab_idx < 0 || strtab_idx >= e_count ||
        get_shdr_type(symtab_idx) != SHT_SYMTAB ||
        get_shdr_type(strtab_idx) != SHT_STRTAB)
        goto error_no_symtab_or_and_strtab;

	/* Wczytywanie sekcji STRTAB. */
    mod->strtab = (struct section *) malloc(sizeof(struct section));
    if (mod->strtab == NULL)
        goto error_strtab_section_malloc;

    Elf32_Off offset = get_shdr_offset(strtab_idx);
	mod->strtab->addr_mmap = mmap(NULL, 
            align_len(get_shdr_size(strtab_idx), offset),
            PROT_READ | PROT_WRITE, MAP_PRIVATE, mod->fd, align_off(offset));
	if (mod->strtab->addr_mmap < 0)
	    goto error_strtab_mapping;
    mod->strtab->addr = (mod->strtab->addr_mmap + move_off(offset)); 
    mod->strtab->idx = strtab_idx;
        
	/* Mapowanie tablicy symboli i symboli. */
    mod->symtab = (struct Elf32_Sym_Wrap *)
         malloc(sizeof(struct Elf32_Sym_Wrap));
    if (mod->symtab == NULL)
        goto error_symtab_malloc;
    mod->symtab->idx = symtab_idx;

    offset = get_shdr_offset(symtab_idx);
	mod->symtab->mmap_ptr = mmap(NULL, 
            align_len(get_shdr_size(symtab_idx), offset), 
            PROT_READ | PROT_WRITE, MAP_PRIVATE, mod->fd, align_off(offset));
	if (mod->symtab->mmap_ptr < 0)
	    goto error_symbol_table_section_mmap;

    mod->symtab->symtab = 
        (Elf32_Sym *) (mod->symtab->mmap_ptr + move_off(offset));
	int sh_entries = get_shdr_size(i) / sizeof(Elf32_Sym);
    /* Przetwarzanie symboli. */
	for (j = 1; j < sh_entries; ++j) {
        unsigned char s_type = ELF32_ST_TYPE(get_symbol(j).st_info);
        /* Ignorujemy pozostałe typy symboli. */
        if (!(s_type == STT_NOTYPE || s_type == STT_OBJECT ||
              s_type == STT_FUNC   || s_type == STT_SECTION))
            continue;

	    struct symbol *sym = malloc(sizeof(struct symbol));
	    if (sym == NULL)
	        goto error_sym_malloc;
        add_symbol(sym, mod);
	    sym->name = mod->strtab->addr + get_symbol(j).st_name;
        sym->sym = (Elf32_Sym *) &get_symbol(j);
        sym->idx = j;
        /* Symbol niezdefiniowany. Pytamy na zewnątrz. */
        if (sym->sym->st_shndx == 0) {
            sym->addr = getsym_fun(getsym_arg, sym->name);
            if (sym->addr == NULL && sym->sym->st_info == STB_GLOBAL)
                goto error_symbol_not_found;
        } else { 
            struct section *symbol_sec = get_section(sym->sym->st_shndx, mod);
            if (symbol_sec != NULL) /* Symbol w sekcji, której nie alokujemy. */
                sym->addr = sym->sym->st_value + symbol_sec->addr;
        } 
    }

    mod->rel = (struct Elf32_Rel_Wrap *) malloc(sizeof(struct Elf32_Rel_Wrap));
    if (mod->rel == NULL)
        goto error_relocation_struct_malloc;
    
    /* Relokacje. */	
    for (i = 0; i < e_count; ++i) {
        if (get_shdr_type(i) == SHT_REL) {
            Elf32_Word sec_idx = get_shdr_info(i);
            struct section *sec_to_mod = get_section(sec_idx, mod);
            /* Jeśli sekcja jest NULL, to znaczy, że nie ma ALLOC, lub jest
             * specjalna (STRTAB, SYMTAB,...). */
            if (sec_to_mod == NULL) 
                continue;
            Elf32_Word sec_size = get_shdr_size(i);
            Elf32_Off sec_offset = get_shdr_offset(i);
            int items_count = sec_size / sizeof(Elf32_Rel);
            
            mod->rel->mmap_ptr = mmap(NULL, align_len(sec_size, sec_offset),
                        PROT_READ | PROT_WRITE, MAP_PRIVATE, mod->fd,
                        align_off(sec_offset));
            if (mod->rel->mmap_ptr < 0)
                goto error_relocation_table_mmap;
            
            mod->rel->array =
                (Elf32_Rel *) (mod->rel->mmap_ptr + move_off(sec_offset));
            mod->rel->idx = i;

            for (j = 0; j < items_count; ++j) {
                Elf32_Rel rel = mod->rel->array[j];
                unsigned char r_type = ELF32_R_TYPE(rel.r_info);
                struct symbol *sym = get_symbol2(ELF32_R_SYM(rel.r_info), mod);
                if (sym == NULL) /*Jeśli NULL, to jest nieobsługiwanego typu.*/
                    continue;
                Elf32_Word *tmp = 
                    (Elf32_Word *) (sec_to_mod->addr + rel.r_offset);
                Elf32_Word val = (Elf32_Word) (*tmp + sym->addr);
                if (r_type == R_386_32)
                    *tmp = val;
                else if (r_type == R_386_PC32) {
                    Elf32_Word val2 = 
                        (Elf32_Word) sec_to_mod->addr + rel.r_offset;
                    *tmp = val - val2; 
                }
                else
                    goto error_unexpected_relocation_type;
            }

            if(mod->rel->mmap_ptr > 0)
                munmap(mod->rel->mmap_ptr,
                        align_len(get_shdr_size(mod->rel->idx),
                        get_shdr_offset(mod->rel->idx)));
        }
    }
    free(mod->rel);
    mod->rel = NULL;

    /* Ustawienie odpowiednich flag sekcji. */
    struct section *section_it = mod->sections_list;
    while (section_it != NULL) {
        int prot = PROT_READ;
        if (get_shdr_flags(section_it->idx) & SHF_WRITE)
            prot |= PROT_WRITE;
        if (get_shdr_flags(section_it->idx) & SHF_EXECINSTR)
            prot |= PROT_EXEC;
        /* Pozostałe flagi ignorujemy. */
        int mp_res = mprotect(section_it->addr_mmap, 
                    align_len(get_shdr_size(section_it->idx),
                    get_shdr_offset(section_it->idx)), prot);
        if (mp_res < 0)
            goto error_mprotect;
        section_it = section_it->next;
    }
    
/* SUKCES. */
	return mod;
	
/* Error handlers. */
error_mprotect:
error_unexpected_relocation_type:
    unmap_relocation(mod);
error_relocation_table_mmap:
    free_relocation_table(mod);
error_relocation_struct_malloc:
error_symbol_not_found:
error_sym_malloc:
    free_symbols(mod);
error_symbol_table_section_mmap:
    unmap_free_symbol_table(mod);
error_symtab_malloc:
error_strtab_mapping:
    unmap_free_string_table(mod);
error_strtab_section_malloc:
error_no_symtab_or_and_strtab:
error_section_mapping:
    unmap_free_sections(mod);
error_section_headers_array_mmap:
    unmap_free_section_headers(mod);
error_shdr_array_malloc:
error_invalid_file_hdr:
    unmap_file_header(mod); 
error_file_hdr_mmap:
    close_file(mod); 
error_open:
    free_module(mod);    
    return NULL;
}

void *module_getsym(struct module *mod, const char *name) {
    struct symbol *sym = mod->symbols_list;
    while (sym != NULL) {
        if (strcmp(sym->name, name) == 0) {
            if (ELF32_ST_BIND(get_symbol(sym->idx).st_info) == STB_LOCAL)
                return NULL;
            return sym->addr; 
        }
        sym = sym->next;
    }
    return NULL;
}

void module_unload(struct module *mod) {
    unmap_relocation(mod);
    free_relocation_table(mod);
    free_symbols(mod);
    unmap_free_symbol_table(mod);
    unmap_free_string_table(mod);
    unmap_free_sections(mod);
    unmap_free_section_headers(mod);
    unmap_file_header(mod);
    close_file(mod);
    free_module(mod);
}
