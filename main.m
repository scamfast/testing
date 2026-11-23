#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Security/Security.h>
#import <Security/SecCode.h>
#import <Security/SecStaticCode.h>
#import <Security/SecRequirement.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdio.h>
#import <unistd.h>
#import <errno.h>
#import <dirent.h>
#import <string.h>
#import <sys/stat.h>
#import "fishhook.h"
#import "api.h"

#define LOG(...) NSLog(@"[inject] " __VA_ARGS__)

static NSString *const kDir = @"/var/mobile/Documents/inject";
static NSDictionary *cfg;
static UIImage *fakeImg;
static NSMutableArray<UIImage*> *variants;
static NSMutableDictionary<NSString*, NSValue*> *origIMPs;
static CMVideoFormatDescriptionRef sharedFmt;
static NSUInteger frameIdx;

static BOOL opt(NSString *k, BOOL d) { id v = cfg[k]; return v ? [v boolValue] : d; }

static void loadConfig(void) {
    cfg = [NSDictionary dictionaryWithContentsOfFile:
           [kDir stringByAppendingPathComponent:@"config.plist"]];
    NSString *p = cfg[@"fakeImage"] ?: [kDir stringByAppendingPathComponent:@"fake.jpg"];
    fakeImg = [UIImage imageWithContentsOfFile:p];
    LOG("cfg=%@ img=%@ (%@)", cfg, fakeImg ? @"OK" : @"MISSING", p);
}

static uint32_t (*o_imgCount)(void);
static const char *(*o_imgName)(uint32_t);
static const struct mach_header *(*o_imgHeader)(uint32_t);
static uint32_t hiddenIdx = UINT32_MAX;

static uint32_t my_imgCount(void) { uint32_t c = o_imgCount(); return hiddenIdx != UINT32_MAX ? c - 1 : c; }
static const char *my_imgName(uint32_t i) { if (hiddenIdx != UINT32_MAX && i >= hiddenIdx) i++; return o_imgName(i); }
static const struct mach_header *my_imgHeader(uint32_t i) { if (hiddenIdx != UINT32_MAX && i >= hiddenIdx) i++; return o_imgHeader(i); }

static const char **(*o_copyNames)(unsigned int *);
static const char **my_copyNames(unsigned int *out) {
    unsigned int n = 0;
    const char **l = o_copyNames(&n);
    if (hiddenIdx == UINT32_MAX) { *out = n; return l; }
    unsigned int m = n - 1;
    const char **r = malloc(sizeof(char*) * m);
    unsigned int k = 0;
    for (unsigned int i = 0; i < n; i++) if (i != hiddenIdx) r[k++] = l[i];
    free((void*)l);
    *out = m;
    return r;
}

static void installDyldHooks(void) {
    Dl_info info;
    const char *selfName = NULL;
    if (dladdr((const void *)&installDyldHooks, &info) && info.dli_fname)
        selfName = strrchr(info.dli_fname, '/') + 1;

    if (selfName) {
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++)
            if (strstr(_dyld_get_image_name(i), selfName)) { hiddenIdx = i; break; }
    }
    LOG("hiddenIdx=%u self=%s", hiddenIdx, selfName ?: "?");

    struct rebinding r[] = {
        {"_dyld_image_count",     (void*)my_imgCount,  (void**)&o_imgCount},
        {"_dyld_get_image_name",  (void*)my_imgName,   (void**)&o_imgName},
        {"_dyld_get_image_header",(void*)my_imgHeader, (void**)&o_imgHeader},
        {"objc_copyImageNames",   (void*)my_copyNames, (void**)&o_copyNames},
    };
    LOG("dyld rebind rc=%d", rebind_symbols(r, sizeof(r)/sizeof(*r)));
}

static BOOL jbPath(const char *p) {
    if (!p) return NO;
    static const char *L[] = {
        "/var/jb", ".jbroot-", "/var/containers/Bundle/tweaksupport",
        "/usr/lib/libsubstrate", "/usr/lib/libhooker", "/usr/lib/libellekit",
        "/usr/lib/libjailbreak", "/usr/lib/TweakInject", "/usr/lib/frida",
        "/Library/MobileSubstrate", "/Library/dpkg", "/var/lib/dpkg", "/etc/apt",
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/usr/libexec/cydia", "/usr/sbin/sshd", "/bin/bash",
        "/usr/bin/frida-server", "/usr/bin/cycript", "/var/stash", "/private/var/stash",
        "/usr/libexec/substrate", "/usr/share/substrate", "/var/cache/apt",
    };
    for (size_t i = 0; i < sizeof(L)/sizeof(*L); i++)
        if (strstr(p, L[i])) return YES;
    return NO;
}

static int (*o_access)(const char*, int);
static int (*o_stat)(const char*, struct stat*);
static int (*o_lstat)(const char*, struct stat*);
static FILE *(*o_fopen)(const char*, const char*);
static DIR *(*o_opendir)(const char*);
static ssize_t (*o_readlink)(const char*, char*, size_t);
static char *(*o_realpath)(const char*, char*);
static pid_t (*o_fork)(void);
static OSStatus (*o_sscv)(SecStaticCodeRef, SecCSFlags, SecRequirementRef);
static OSStatus (*o_scv)(SecCodeRef, SecCSFlags, SecRequirementRef);

static int my_access(const char *p, int m) { if (jbPath(p)) { errno = ENOENT; return -1; } return o_access(p, m); }
static int my_stat(const char *p, struct stat *s) { if (jbPath(p)) { errno = ENOENT; return -1; } return o_stat(p, s); }
static int my_lstat(const char *p, struct stat *s) { if (jbPath(p)) { errno = ENOENT; return -1; } return o_lstat(p, s); }
static FILE *my_fopen(const char *p, const char *m) { if (jbPath(p)) { errno = ENOENT; return NULL; } return o_fopen(p, m); }
static DIR *my_opendir(const char *p) { if (jbPath(p)) { errno = ENOENT; return NULL; } return o_opendir(p); }
static ssize_t my_readlink(const char *p, char *b, size_t n) { if (jbPath(p)) return -1; return o_readlink(p, b, n); }
static char *my_realpath(const char *p, char *r) { if (jbPath(p)) return NULL; return o_realpath(p, r); }
static pid_t my_fork(void) { return opt(@"fakeFork", YES) ? -1 : o_fork(); }
static OSStatus my_sscv(SecStaticCodeRef c, SecCSFlags f, SecRequirementRef r) { return opt(@"fakeCodeSign", YES) ? 0 : o_sscv(c, f, r); }
static OSStatus my_scv(SecCodeRef c, SecCSFlags f, SecRequirementRef r) { return opt(@"fakeCodeSign", YES) ? 0 : o_scv(c, f, r); }

static void installSysHooks(void) {
    struct rebinding r[] = {
        {"access", (void*)my_access, (void**)&o_access},
        {"stat", (void*)my_stat, (void**)&o_stat},
        {"stat64", (void*)my_stat, (void**)&o_stat},
        {"__stat64", (void*)my_stat, (void**)&o_stat},
        {"lstat", (void*)my_lstat, (void**)&o_lstat},
        {"fopen", (void*)my_fopen, (void**)&o_fopen},
        {"opendir", (void*)my_opendir, (void**)&o_opendir},
        {"readlink", (void*)my_readlink, (void**)&o_readlink},
        {"realpath", (void*)my_realpath, (void**)&o_realpath},
        {"fork", (void*)my_fork, (void**)&o_fork},
        {"SecStaticCodeCheckValidity", (void*)my_sscv, (void**)&o_sscv},
        {"SecCodeCheckValidity", (void*)my_scv, (void**)&o_scv},
    };
    LOG("sys rebind rc=%d", rebind_symbols(r, sizeof(r)/sizeof(*r)));
}

static void sw(Class c, SEL a, SEL b) {
    Method x = class_getInstanceMethod(c, a), y = class_getInstanceMethod(c, b);
    if (x && y) method_exchangeImplementations(x, y);
}

static BOOL hookObj(id obj, SEL sel, IMP repl) {
    Class c = object_getClass(obj);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return NO;
    NSString *key = [NSString stringWithFormat:@"%s/%s", class_getName(c), sel_getName(sel)];
    if (origIMPs[key]) return YES;
    origIMPs[key] = [NSValue valueWithPointer:method_getImplementation(m)];
    method_setImplementation(m, repl);
    return YES;
}
static IMP origFor(id obj, SEL sel) {
    NSString *key = [NSString stringWithFormat:@"%s/%s", class_getName(object_getClass(obj)), sel_getName(sel)];
    return origIMPs[key].pointerValue;
}

static CVPixelBufferRef makePB(UIImage *img) {
    CGImageRef cg = img.CGImage;
    if (!cg) return NULL;
    size_t w = CGImageGetWidth(cg), h = CGImageGetHeight(cg);
    CVPixelBufferRef pb = NULL;
    NSDictionary *at = @{(id)kCVPixelBufferIOSurfacePropertiesKey: @{}};
    if (CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32BGRA,
                            (__bridge CFDictionaryRef)at, &pb) != kCVReturnSuccess) return NULL;
    CVPixelBufferLockBaseAddress(pb, 0);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(CVPixelBufferGetBaseAddress(pb), w, h, 8,
        CVPixelBufferGetBytesPerRow(pb), cs,
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), cg);
    CGContextRelease(ctx); CGColorSpaceRelease(cs);
    CVPixelBufferUnlockBaseAddress(pb, 0);
    return pb;
}

static CMSampleBufferRef makeSB(UIImage *img) {
    CVPixelBufferRef pb = makePB(img);
    if (!pb) return NULL;
    if (!sharedFmt) CMVideoFormatDescriptionCreateForImageBuffer(kCFAllocatorDefault, pb, &sharedFmt);
    CMSampleTimingInfo t; memset(&t, 0, sizeof t);
    t.duration = CMTimeMake(1, 30);
    t.presentationTimeStamp = CMClockGetTime(CMClockGetHostTimeClock());
    t.decodeTimeStamp = kCMTimeInvalid;
    CMSampleBufferRef sb = NULL;
    CMSampleBufferCreateReadyWithImageBuffer(kCFAllocatorDefault, pb, sharedFmt, &t, &sb);
    CVPixelBufferRelease(pb);
    return sb;
}

static UIImage *variantAt(NSUInteger i) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableArray *a = [NSMutableArray array];
        for (int k = 0; k < 6; k++) {
            CGFloat ang = ((k % 2) ? 1 : -1) * 0.03 * ((k / 2) + 1);
            CGFloat sc = 1.0 + ((k % 2) ? 0.02 : -0.02) * ((k / 2) + 1);
            CGSize s = fakeImg.size;
            UIGraphicsImageRenderer *r = [[UIGraphicsImageRenderer alloc] initWithSize:s];
            [a addObject:[r imageWithActions:^(UIGraphicsImageRendererContext *c) {
                CGContextTranslateCTM(c.CGContext, s.width / 2, s.height / 2);
                CGContextRotateCTM(c.CGContext, ang);
                CGContextScaleCTM(c.CGContext, sc, sc);
                [fakeImg drawInRect:CGRectMake(-s.width / 2, -s.height / 2, s.width, s.height)];
            }]];
        }
        variants = a;
    });
    return variants[i % variants.count];
}

@interface AVCapturePhoto (X)
@end
@implementation AVCapturePhoto (X)
- (NSData *)x_fdr { return fakeImg ? UIImageJPEGRepresentation(fakeImg, 0.95) : [self x_fdr]; }
- (NSData *)x_fdrc:(id)c { return fakeImg ? UIImageJPEGRepresentation(fakeImg, 0.95) : [self x_fdrc:c]; }
- (CGImageRef)x_cgr { return fakeImg ? CGImageRetain(fakeImg.CGImage) : [self x_cgr]; }
- (CGImageRef)x_pcgr { return fakeImg ? CGImageRetain(fakeImg.CGImage) : [self x_pcgr]; }
- (CVPixelBufferRef)x_pb { return fakeImg ? makePB(fakeImg) : [self x_pb]; }
- (AVDepthData *)x_dd { return (fakeImg && opt(@"fakeDepthNil", NO)) ? nil : [self x_dd]; }
@end

static void hookVideoDelegate(id d) {
    SEL s = @selector(captureOutput:didOutputSampleBuffer:fromConnection:);
    static NSMutableSet *seen;
    if (!seen) seen = [NSMutableSet new];
    Class c = object_getClass(d);
    if ([seen containsObject:NSStringFromClass(c)]) return;
    [seen addObject:NSStringFromClass(c)];

    IMP repl = imp_implementationWithBlock(^(id self, AVCaptureOutput *out, CMSampleBufferRef sb, AVCaptureConnection *conn) {
        IMP o = origFor(self, s);
        void (*call)(id, SEL, id, CMSampleBufferRef, id) = (void*)o;
        if (!o || !fakeImg || ![out isKindOfClass:NSClassFromString(@"AVCaptureVideoDataOutput")]) {
            if (o) call(self, s, out, sb, conn);
            return;
        }
        CMSampleBufferRef mine = makeSB(variantAt(frameIdx++));
        if (mine) { call(self, s, out, mine, conn); CFRelease(mine); }
        else call(self, s, out, sb, conn);
    });
    hookObj(d, s, repl);
}

@interface AVCaptureVideoDataOutput (X)
@end
@implementation AVCaptureVideoDataOutput (X)
- (void)x_ssd:(id)d queue:(dispatch_queue_t)q {
    [self x_ssd:d queue:q];
    if (d) hookVideoDelegate(d);
}
@end

static void hookPicker(id d) {
    SEL s = @selector(imagePickerController:didFinishPickingMediaWithInfo:);
    IMP repl = imp_implementationWithBlock(^(id self, UIImagePickerController *p, NSDictionary *info) {
        IMP o = origFor(self, s);
        if (!o) return;
        NSMutableDictionary *m = [info mutableCopy];
        if (fakeImg) {
            m[UIImagePickerControllerOriginalImage] = fakeImg;
            if (m[UIImagePickerControllerEditedImage]) m[UIImagePickerControllerEditedImage] = fakeImg;
        }
        ((void(*)(id, SEL, id, id))o)(self, s, p, m);
    });
    hookObj(d, s, repl);
}

@interface UIImagePickerController (X)
@end
@implementation UIImagePickerController (X)
- (void)x_sd:(id)d { [self x_sd:d]; if (d) hookPicker(d); }
@end

@interface NSFileManager (X)
@end
@implementation NSFileManager (X)
- (BOOL)x_fea:(NSString *)p { return jbPath(p.UTF8String) ? NO : [self x_fea:p]; }
- (BOOL)x_feai:(NSString *)p isDirectory:(BOOL *)d {
    if (jbPath(p.UTF8String)) { if (d) *d = NO; return NO; }
    return [self x_feai:p isDirectory:d];
}
@end

@interface UIApplication (X)
@end
@implementation UIApplication (X)
- (BOOL)x_cou:(NSURL *)u {
    static NSSet *bad; static dispatch_once_t o;
    dispatch_once(&o, ^{ bad = [NSSet setWithObjects:@"cydia", @"sileo", @"zbra", @"filza",
                                       @"undecimus", @"installer", @"apt", @"newterm",
                                       @"trollstore", @"procursus", nil]; });
    if ([bad containsObject:u.scheme.lowercaseString]) return NO;
    return [self x_cou:u];
}
@end

__attribute__((constructor)) static void init(void) {
    @autoreleasepool {
        origIMPs = [NSMutableDictionary new];
        loadConfig();
        if (!opt(@"enabled", YES)) { LOG("disabled"); return; }

        if (opt(@"hideDyld", YES)) installDyldHooks();
        if (opt(@"hideSys", YES)) installSysHooks();

        Class fm = NSClassFromString(@"NSFileManager");
        if (fm && opt(@"hideSys", YES)) {
            sw(fm, @selector(fileExistsAtPath:), @selector(x_fea:));
            sw(fm, @selector(fileExistsAtPath:isDirectory:), @selector(x_feai:isDirectory:));
        }
        Class app = NSClassFromString(@"UIApplication");
        if (app && opt(@"hideURL", YES)) sw(app, @selector(canOpenURL:), @selector(x_cou:));

        if (fakeImg && opt(@"spoofImage", YES)) {
            Class ph = NSClassFromString(@"AVCapturePhoto");
            if (ph) {
                sw(ph, @selector(fileDataRepresentation), @selector(x_fdr));
                sw(ph, @selector(fileDataRepresentationWithCustomizer:), @selector(x_fdrc:));
                sw(ph, @selector(CGImageRepresentation), @selector(x_cgr));
                sw(ph, @selector(previewCGImageRepresentation), @selector(x_pcgr));
                sw(ph, @selector(pixelBuffer), @selector(x_pb));
                sw(ph, @selector(depthData), @selector(x_dd));
            }
            Class vo = NSClassFromString(@"AVCaptureVideoDataOutput");
            if (vo) sw(vo, @selector(setSampleBufferDelegate:queue:), @selector(x_ssd:queue:));
            Class pk = NSClassFromString(@"UIImagePickerController");
            if (pk) sw(pk, @selector(setDelegate:), @selector(x_sd:));
            LOG("spoof armed");
        }
    }
}
