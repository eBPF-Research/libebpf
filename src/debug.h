#ifndef _DEBUG_LOG_H_
#define _DEBUG_LOG_H_

#define DEBUG 1

// Add a log function using DEBUG and printf
#define LOG_DEBUG(...) do { if (DEBUG) printf(__VA_ARGS__); } while (0)

#endif
