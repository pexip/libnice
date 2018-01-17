#ifndef _NICE_CONFIG_H_
#define _NICE_CONFIG_H_

#if defined(_MSC_VER)
#  ifdef NICE_EXPORTS
#    define NICE_EXPORT __declspec(dllexport)
#  else
#    define NICE_EXPORT __declspec(dllimport) extern
#  endif
#else
#  define NICE_EXPORT extern
#endif

#endif /* _NICE_CONFIG_H_ */
