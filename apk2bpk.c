#ifdef __MINGW32__
#define __USE_MINGW_ANSI_STDIO 0
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

// ========== 跨平台 mmap/munmap 隔离 ==========
#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #define PROT_READ  PAGE_READONLY
    #define MAP_SHARED FILE_MAP_READ
    #define MAP_FAILED ((void*)NULL)
    #define off_t      int64_t
    #define ssize_t    int64_t

    static void* mmap(void* addr, off_t len, int prot, int flags, int fd, off_t offset) {
        HANDLE hFile = (HANDLE)_get_osfhandle(fd);
        DWORD flProtect = PAGE_READONLY;
        HANDLE hMap = CreateFileMappingW(hFile, NULL, flProtect, (DWORD)(len >> 32), (DWORD)len, NULL);
        if (hMap == NULL) return MAP_FAILED;
        void* ptr = MapViewOfFile(hMap, FILE_MAP_READ, (DWORD)(offset >> 32), (DWORD)offset, (SIZE_T)len);
        CloseHandle(hMap);
        return ptr;
    }
    static int munmap(void* addr, off_t len) {
        return UnmapViewOfFile(addr) ? 0 : -1;
    }

    static ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
        if (_lseeki64(fd, offset, SEEK_SET) == -1)
            return -1;
        return _write(fd, buf, (unsigned int)count);
    }
#else
    #include <sys/mman.h>
#endif
// =============================================

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef PATH_MAX
#if defined(_WIN32) || defined(__CYGWIN__)
#define PATH_MAX 256
#elif defined(__linux__)
#define PATH_MAX 4096
#else
#define PATH_MAX 1024
#endif
#endif

#define pk2bpk(pk) (((pk%0x1000000)<<8)+0x42)
#define bpk2pk(bpk) ((((bpk >> 8) & 0xFFFFFF) << 24) | ((bpk >> 24) & 0xFF))

const uint8_t *xorCodeEOCD = (uint8_t *)"END_OF_CENTRAL_DIRECTORY_XOR_CODE_OF_BBK_APK_ENCRYPTION";
const uint8_t *xorCodeCD = (uint8_t *)"CENTRAL_DIRECTORY_XOR_CODE_OF_BBK_APK_ENCRYPTION";
const uint8_t *xorCodeLOCAL = (uint8_t *)"LOCAL_FILE_HEADER_XOR_CODE_OF_BBK_APK_ENCRYPTION";

#define local_file_magic 0x04034b50
#define bbk_local_file_magic pk2bpk(local_file_magic)
#pragma pack(push, 1)
struct local_file_header {
    uint32_t magic;
    uint16_t version;
    uint16_t flag;
    uint16_t method;
    uint16_t last_modified_time;
    uint16_t last_modified_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
};
#pragma pack(pop)

#define data_descriptor_magic 0x08074b50
#define bbk_data_descriptor_magic pk2bpk(data_descriptor_magic)
#pragma pack(push, 1)
struct data_descriptor {
    uint32_t magic;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
};
#pragma pack(pop)

#define central_directory_file_header_magic 0x02014b50
#define bbk_central_directory_file_header_magic pk2bpk(central_directory_file_header_magic)
#pragma pack(push, 1)
struct directory_source {
    uint32_t magic;
    uint16_t cver;
    uint16_t dver;
    uint16_t flag;
    uint16_t compress_method;
    uint16_t last_modified_time;
    uint16_t last_modifiled_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_length;
    uint16_t annotation_length;
    uint16_t subsection;
    uint16_t attrib_inside;
    uint32_t attrib_outside;
    uint32_t offset;
};
#pragma pack(pop)

#define end_of_central_magic 0x06054b50
#define bbk_end_of_central_magic pk2bpk(end_of_central_magic)
#pragma pack(push, 1)
struct end_of_central_directory {
    uint32_t magic;
    uint16_t disk_num;
    uint16_t central_start_offset_disk_num;
    uint16_t record_central_num;
    uint16_t total_central_directory_num;
    uint32_t central_size;
    uint32_t central_start_offset;
    uint16_t extra_length;
};
#pragma pack(pop)

struct apk_signature_v2 {
    uint64_t size;
    uint8_t *data;
};

enum {
    CFG_ENCODE,
    CFG_DECODE,
};

static struct config {
    int verbose;
    int mode;
    char *input;
    char *output;
} cfg;

static int xor(uint8_t* val, uint32_t size, const uint8_t *xorCode) {
    if (size == 0 || val == NULL || xorCode == NULL)
        return -1;
    int xlen = strlen((const char*)xorCode);
    if (xlen == 0) return -1;
    for (uint32_t i = 0; i < size; i++)
        val[i] = xorCode[(i) % xlen] ^ val[i];
    return 0;
}

static inline off_t get_eocd_offset(uint8_t *mem, off_t size) {
    uint32_t magic;
    int flag = 0;
    if (size < 22) return 0;
    off_t pos = size - 4;
    while (pos >= 0) {
        memcpy(&magic, mem + pos, sizeof(magic));
        if (magic == end_of_central_magic || magic == bbk_end_of_central_magic) {
            flag = 1;
            break;
        }
        pos--;
    }
    return flag ? pos : 0;
}

static inline void parse_magic(uint32_t *magic) {
    if (cfg.mode == CFG_ENCODE)
        *magic = pk2bpk(*magic);
    else
        *magic = bpk2pk(*magic);
}

static int full_copy_file(int fd_in, int fd_out, off_t file_size) {
    const size_t BUF_SZ = 4096;
    uint8_t* buf = malloc(BUF_SZ);
    if (!buf) return -ENOMEM;
    lseek(fd_in, 0, SEEK_SET);
    ssize_t rd;
    while ((rd = read(fd_in, buf, BUF_SZ)) > 0) {
        ssize_t wret = write(fd_out, buf, (size_t)rd);
        (void)wret;
    }
    free(buf);
    if (rd < 0) return -errno;
    return 0;
}

static int parse_zip(char* input, char* output, int mode, int verbose) {
    int ret = 0;
    int fdi, fdo;
    struct local_file_header hl;
    struct data_descriptor hdd;
    struct end_of_central_directory heo;
    struct directory_source hds;
    struct apk_signature_v2 sig;
    off_t offset = 0, local_offset = 0, sig_offset = 0;
    uint8_t *buf = NULL;

    if (access(output, F_OK) == 0) {
        if (remove(output)) {
            printf("Error: Cannot remove file %s, errno=%d\n", output, errno);
            return EIO;
        }
    }

    fdi = open(input, O_RDONLY | O_BINARY);
    if (fdi < 0) {
        printf("Error open input %s errno=%d\n", input, errno);
        return EIO;
    }
    fdo = open(output, O_CREAT | O_RDWR | O_BINARY, 0644);
    if (fdo < 0) {
        printf("Error create output %s errno=%d\n", output, errno);
        close(fdi);
        return EIO;
    }

    struct stat st;
    if (stat(input, &st) < 0) {
        printf("stat input failed errno=%d\n", errno);
        ret = EIO;
        goto clean_fd;
    }
    off_t file_size = st.st_size;

    ret = full_copy_file(fdi, fdo, file_size);
    if (ret != 0) {
        printf("Full copy file failed err=%d\n", ret);
        goto clean_fd;
    }

    uint8_t *mem = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fdi, 0);
    if (mem == MAP_FAILED) {
        printf("mmap source file failed\n");
        ret = EIO;
        goto clean_mmap;
    }

    lseek(fdi, 0, SEEK_SET);
    ssize_t rd_head = read(fdi, &hl, sizeof(hl));
    (void)rd_head;
    if ((hl.magic != local_file_magic) && (hl.magic != bbk_local_file_magic)) {
        fprintf(stderr, "File does not seems like a apk or bpk file.\n");
        ret = EBADF;
        goto clean_mmap;
    }
    if (hl.magic == bbk_local_file_magic && mode != CFG_DECODE) {
        fprintf(stderr, "File seems already encrypted.\n");
        ret = EINVAL;
        goto clean_mmap;
    }

    printf("Converting [%s] -> [%s] ... \n", input, output);

    offset = get_eocd_offset(mem, file_size);
    if (offset == 0) {
        printf("Error: Cannot find eocd magic\n");
        ret = EBADF;
        goto clean_mmap;
    }
    if (verbose) {
        printf("Find EOCD at              :\t%lld\n", (long long)offset);
    }

    uint8_t *ptr = mem + offset;
    memcpy(&heo, ptr, sizeof(heo));
    parse_magic(&heo.magic);
    xor((uint8_t*)&heo + sizeof(heo.magic), sizeof(heo) - sizeof(heo.magic), xorCodeEOCD);
    ssize_t w_eocd = pwrite(fdo, &heo, sizeof(heo), offset);
    (void)w_eocd;

    if (mode == CFG_ENCODE) {
        xor((uint8_t*)&heo + sizeof(heo.magic), sizeof(heo) - sizeof(heo.magic), xorCodeEOCD);
    }

    if (heo.extra_length != 0U) {
        off_t extra_off = offset + sizeof(heo);
        ptr = mem + extra_off;
        ssize_t w_extra = pwrite(fdo, ptr, heo.extra_length, extra_off);
        (void)w_extra;
        if (verbose)
            printf("Find End Extra at         :\t%lld\n", (long long)extra_off);
    }

    if (verbose) {
        printf("Find Central Directory Num: \t%u\n"
               "Find Central Total size   : \t%u\n"
               "Find Central Offset at dec: \t%u | hex %08x\n",
               heo.total_central_directory_num, heo.central_size,
               heo.central_start_offset, heo.central_start_offset);
    }
    offset = heo.central_start_offset;

    uint16_t total = heo.total_central_directory_num;
    for (uint16_t i = 1; i <= total; i++) {
        if (verbose) {
            printf("[ %06u / %06u ] Parsing ... \r", i, total);
            fflush(stdout);
            if (i == total) {
                printf("[ %06u / %06u ] Parsing ... Done!\n", i, total);
            }
        }

        ptr = mem + offset;
        memcpy(&hds, ptr, sizeof(hds));
        uint16_t flag = hds.flag;
        uint32_t meta_len = sizeof(hds) - sizeof(hds.magic);
        uint32_t data_len = meta_len + hds.file_name_length + hds.extra_length + hds.annotation_length;

        buf = malloc(data_len);
        if (!buf) {
            printf("\nWarning: Malloc fail entry %u size %u, skip this file\n", i, data_len);
            offset += sizeof(hds) + hds.file_name_length + hds.extra_length + hds.annotation_length;
            continue;
        }
        memcpy(buf, ptr + sizeof(hds.magic), meta_len);
        memcpy(buf + meta_len, ptr + sizeof(hds), hds.file_name_length + hds.extra_length + hds.annotation_length);

        xor(buf, data_len, xorCodeCD);

        parse_magic(&hds.magic);
        ssize_t w1 = pwrite(fdo, &hds.magic, sizeof(hds.magic), offset);
        (void)w1;
        ssize_t w2 = pwrite(fdo, buf, data_len, offset + sizeof(hds.magic));
        (void)w2;
        free(buf);
        buf = NULL;

        offset += sizeof(hds) + hds.file_name_length + hds.extra_length + hds.annotation_length;
        local_offset = hds.offset;

        // 偏移合法性校验，防止越界崩溃
        if (local_offset >= file_size) {
            printf("\nWarning entry %u: local offset %lld out of file range, skip\n", i, (long long)local_offset);
            continue;
        }

        sig_offset = local_offset + sizeof(hl) + hds.file_name_length + hl.extra_field_length + hds.compressed_size;
        if (flag & 0x8) sig_offset += sizeof(hdd);

        ptr = mem + local_offset;
        memcpy(&hl, ptr, sizeof(hl));
        // 修复：完整header除magic全部参与xor，不再减extra_field_length
        uint32_t local_xor_len = sizeof(hl) - sizeof(hl.magic);

        if (mode == CFG_DECODE) {
            xor((uint8_t*)&hl + sizeof(hl.magic), local_xor_len, xorCodeLOCAL);
        }

        uint8_t* fname_buf = malloc(hds.file_name_length);
        if (fname_buf) {
            memcpy(fname_buf, ptr + sizeof(hl), hds.file_name_length);
            xor(fname_buf, hds.file_name_length, xorCodeLOCAL);
            ssize_t w_fname = pwrite(fdo, fname_buf, hds.file_name_length, local_offset + sizeof(hl));
            (void)w_fname;
            free(fname_buf);
        }

        ssize_t w_extra_f = pwrite(fdo, ptr + sizeof(hl) + hds.file_name_length, hl.extra_field_length,
               local_offset + sizeof(hl) + hds.file_name_length);
        (void)w_extra_f;

        if ((flag & 0x8)) {
            off_t dd_off = local_offset + sizeof(hl) + hds.file_name_length + hl.extra_field_length + hds.compressed_size;
            memcpy(&hdd, ptr + (dd_off - local_offset), sizeof(hdd));
            xor((uint8_t*)&hdd + sizeof(hdd.magic), sizeof(hdd) - sizeof(hdd.magic), xorCodeLOCAL);
            parse_magic(&hdd.magic);
            ssize_t w_dd = pwrite(fdo, &hdd, sizeof(hdd), dd_off);
            (void)w_dd;
        }

        if (mode == CFG_ENCODE) {
            xor((uint8_t*)&hl + sizeof(hl.magic), local_xor_len, xorCodeLOCAL);
        }

        if (!(flag & 0x8)) {
            hl.crc32 = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.crc32;
            hl.compressed_size = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.compressed_size;
            hl.uncompressed_size = (mode == CFG_ENCODE) ? (uint32_t)-1 : hds.uncompressed_size;
        } else {
            hl.crc32 = (mode == CFG_ENCODE) ? 0U : hds.crc32;
            hl.compressed_size = (mode == CFG_ENCODE) ? 0U : hds.compressed_size;
            hl.uncompressed_size = (mode == CFG_ENCODE) ? 0U : hds.uncompressed_size;
        }
        parse_magic(&hl.magic);
        ssize_t w_local = pwrite(fdo, &hl, sizeof(hl), local_offset);
        (void)w_local;
    }

    sig_offset++;
    if (sig_offset < heo.central_start_offset) {
        ptr = mem + sig_offset;
        memcpy(&sig.size, ptr, sizeof(sig.size));
        if (verbose) {
            printf("Find apk signature at     :\t%lld\n"
                   "Find apk signature Size   :\t%llu\n",
                   (long long)sig_offset, (unsigned long long)sig.size);
        }
        ssize_t w_sig = pwrite(fdo, ptr, sizeof(sig.size) + sig.size, sig_offset);
        (void)w_sig;
    } else {
        printf("Warning: This apk file have no signature.\n\tSkip write signature.\n");
    }

clean_mmap:
    munmap(mem, file_size);
clean_fd:
    if (buf) free(buf);
    close(fdi);
    close(fdo);

#ifdef _WIN32
    _chmod(output, _S_IRUSR | _S_IWUSR | _S_IXUSR);
#else
    chmod(output, 0755);
#endif
    if (ret == 0)
        printf("Done!\n");
    return ret;
}

static void usage() {
    printf(
        "apk2bpk -i [file] -o [file] -d\n"
        "Usage: \n"
        "\t-i [file]\tInput apk/bpk file (required)\n"
        "\t-o [file]\tOutput file (auto .bpk/.apk if omit)\n"
        "\t-d       \tDecode mode (bpk -> apk)\n"
        "\t-v       \tVerbose detailed log\n"
        "\t-h       \tShow this help\n"
        "Convert apk <-> bpk with header XOR encrypt\n"
    );
}

static void parse_arg(int argc, char** argv) {
    int opt;
    const char *optstr = "i:o:dvh";
    cfg.mode = CFG_ENCODE;
    cfg.verbose = 0;
    cfg.input = NULL;
    cfg.output = NULL;
    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
            case 'i':
                if (cfg.input) free(cfg.input);
                cfg.input = strdup(optarg);
                break;
            case 'o':
                if (cfg.output) free(cfg.output);
                cfg.output = strdup(optarg);
                break;
            case 'd':
                cfg.mode = CFG_DECODE;
                break;
            case 'v':
                cfg.verbose = 1;
                break;
            case 'h':
                usage();
                exit(0);
                break;
            default:
                break;
        }
    }
}

int main(int argc, char** argv) {
    char output_buf[PATH_MAX];
    int ret = 0;
    if (argc < 2) {
        usage();
        return 1;
    }
    parse_arg(argc, argv);

    if (cfg.input == NULL) {
        fprintf(stderr, "Error: Input file not defined.\n");
        ret = 1;
        goto main_clean;
    }
    if (access(cfg.input, F_OK) != 0) {
        fprintf(stderr, "Error: Input file [%s] does not exist.\n", cfg.input);
        ret = EEXIST;
        goto main_clean;
    }

    if (cfg.output == NULL) {
        memset(output_buf, 0, sizeof(output_buf));
        snprintf(output_buf, PATH_MAX - 8, "%s", cfg.input);
        if (cfg.mode == CFG_ENCODE)
            strcat(output_buf, ".bpk");
        else
            strcat(output_buf, ".apk");
        cfg.output = output_buf;
    }

    ret = parse_zip(cfg.input, cfg.output, cfg.mode, cfg.verbose);
main_clean:
    if (cfg.input) free(cfg.input);
    if (cfg.output && cfg.output != output_buf) free(cfg.output);
    return ret;
}
