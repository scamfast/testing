#include "fishhook.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEP LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEP LC_SEGMENT
#endif

struct rebindings_entry { struct rebinding *rebindings; size_t n; struct rebindings_entry *next; };
static struct rebindings_entry *_rebindings_head;

static bool protect_range(const void *addr, size_t size) {
    vm_address_t page = (vm_address_t)addr & ~(vm_page_size - 1);
    size_t len = size + ((vm_address_t)addr - page);
    return vm_protect(mach_task_self(), page, len, false,
                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS;
}

static void do_rebind(struct rebindings_entry *reb, section_t *section, intptr_t slide,
                      nlist_t *symtab, char *strtab, uint32_t *indirect_symtab) {
    uint32_t *indices = indirect_symtab + section->reserved1;
    void **bindings = (void **)((uintptr_t)slide + section->addr);
    if (!protect_range(bindings, section->size)) return;

    for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t idx = indices[i];
        if (idx == INDIRECT_SYMBOL_ABS || idx == INDIRECT_SYMBOL_LOCAL ||
            idx == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;

        char *sym = strtab + symtab[idx].n_un.n_strx;
        const char *clean = (sym[0] == '_') ? sym + 1 : sym;

        for (struct rebindings_entry *cur = reb; cur; cur = cur->next) {
            for (size_t j = 0; j < cur->n; j++) {
                if (strcmp(clean, cur->rebindings[j].name)) continue;
                void *repl = cur->rebindings[j].replacement;
                if (bindings[i] == repl) continue;
                void *slot = (void *)&bindings[i];
                if (cur->rebindings[j].replaced) {
#if __has_feature(ptrauth_calls)
                    *(cur->rebindings[j].replaced) = ptrauth_strip(bindings[i], ptrauth_key_asia);
#else
                    *(cur->rebindings[j].replaced) = bindings[i];
#endif
                }
#if __has_feature(ptrauth_calls)
                bindings[i] = ptrauth_sign_unauthenticated(repl, ptrauth_key_asia, (uintptr_t)slot);
#else
                bindings[i] = repl;
#endif
            }
        }
    }
}

int rebind_symbols_image(void *header, intptr_t slide,
                         struct rebinding rebindings[], size_t n) {
    struct rebindings_entry *ne = calloc(1, sizeof(*ne));
    if (!ne) return -1;
    ne->rebindings = malloc(sizeof(struct rebinding) * n);
    if (!ne->rebindings) { free(ne); return -1; }
    memcpy(ne->rebindings, rebindings, sizeof(struct rebinding) * n);
    ne->n = n;
    ne->next = _rebindings_head;
    _rebindings_head = ne;

    const mach_header_t *mh = (const mach_header_t *)header;
    const segment_command_t *linkedit = NULL;
    const struct symtab_command *symcmd = NULL;

    uintptr_t cur = (uintptr_t)mh + sizeof(mach_header_t);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_ARCH_DEP) {
            segment_command_t *s = (segment_command_t *)lc;
            if (!strcmp(s->segname, SEG_LINKEDIT)) linkedit = s;
        } else if (lc->cmd == LC_SYMTAB) {
            symcmd = (const struct symtab_command *)lc;
        }
        cur += lc->cmdsize;
    }
    if (!linkedit || !symcmd) return -1;

    uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    nlist_t *symtab = (nlist_t *)(base + symcmd->symoff);
    char *strtab = (char *)(base + symcmd->stroff);
    uint32_t *indirect = (uint32_t *)(base + symcmd->indirectsymoff);

    cur = (uintptr_t)mh + sizeof(mach_header_t);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_ARCH_DEP) {
            segment_command_t *s = (segment_command_t *)lc;
            if (!strcmp(s->segname, "__DATA") || !strcmp(s->segname, "__DATA_CONST") ||
                !strcmp(s->segname, "__DATA_DIRTY")) {
                section_t *sect = (section_t *)((uintptr_t)s + sizeof(segment_command_t));
                for (uint32_t j = 0; j < s->nsects; j++) {
                    uint32_t t = sect[j].flags & SECTION_TYPE;
                    if (t == S_LAZY_SYMBOL_POINTERS || t == S_NON_LAZY_SYMBOL_POINTERS)
                        do_rebind(ne, &sect[j], slide, symtab, strtab, indirect);
                }
            }
        }
        cur += lc->cmdsize;
    }
    return 0;
}

int rebind_symbols(struct rebinding rebindings[], size_t n) {
    void *hdr = (void *)_dyld_get_image_header(0);
    if (!hdr) return -1;
    return rebind_symbols_image(hdr, _dyld_get_image_vmaddr_slide(0), rebindings, n);
}
