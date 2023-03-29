#ifndef HOOK_H
#define HOOK_H

void* get_function_addr_elf_pie(const char* func_name, char* err_msg);

#endif
