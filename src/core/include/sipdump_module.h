#ifndef SIPDUMP_MODULE_H__
#define SIPDUMP_MODULE_H__

#include <apr.h>
#include <apr_errno.h>
#include <apr_pools.h>

APR_BEGIN_DECLS

#ifdef DOXYGEN
# define SIPDUMP_DECLARE_STATIC
# define SIPDUMP_DECLARE_EXPORT
#endif /* def DOXYGEN */
#if !defined(WIN32)
#define SIPDUMP_DECLARE(type)            type
#define SIPDUMP_DECLARE_NONSTD(type)     type
#define SIPDUMP_DECLARE_DATA
#elif defined(SIPDUMP_DECLARE_STATIC)
#define SIPDUMP_DECLARE(type)            type __stdcall
#define SIPDUMP_DECLARE_NONSTD(type)     type
#define SIPDUMP_DECLARE_DATA
#elif defined(SIPDUMP_DECLARE_EXPORT)
#define SIPDUMP_DECLARE(type)            __declspec(dllexport) type __stdcall
#define SIPDUMP_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define SIPDUMP_DECLARE_DATA             __declspec(dllexport)
#else
#define SIPDUMP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define SIPDUMP_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define SIPDUMP_DECLARE_DATA             __declspec(dllimport)
#endif

#if !defined(WIN32) || defined(SIPDUMP_MODULE_DECLARE_STATIC)
#if defined(WIN32)
#define SIPDUMP_MODULE_DECLARE(type)            type __stdcall
#else
#define SIPDUMP_MODULE_DECLARE(type)            type
#endif
#define SIPDUMP_MODULE_DECLARE_NONSTD(type)     type
#define SIPDUMP_MODULE_DECLARE_DATA
#else
#define SIPDUMP_MODULE_DECLARE_EXPORT
#define SIPDUMP_MODULE_DECLARE(type)          __declspec(dllexport) type __stdcall
#define SIPDUMP_MODULE_DECLARE_NONSTD(type)   __declspec(dllexport) type
#define SIPDUMP_MODULE_DECLARE_DATA           __declspec(dllexport)
#endif

struct sipdump_module_t {
    void *module;
    apr_uint64_t magic;
    const char *name;
    apr_status_t (*load) (apr_pool_t *pool, struct sipdump_module_t *module);
    apr_status_t (*unload) ();
    int flags;
};
typedef struct sipdump_module_t sipdump_module_t;

#define SIPDUMP_MODULE_MAGIC_COOKIE 0x41503234UL

#define SIPDUMP_MODULE_STUFF \
    NULL,\
    SIPDUMP_MODULE_MAGIC_COOKIE

#define SIPDUMP_DECLARE_MODULE(foo) \
    extern sipdump_module_t SIPDUMP_MODULE_DECLARE_DATA foo##_module; \
    sipdump_module_t SIPDUMP_MODULE_DECLARE_DATA foo##_module

APR_END_DECLS

#endif