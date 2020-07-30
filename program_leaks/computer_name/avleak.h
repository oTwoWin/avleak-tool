#ifndef AVLEAK
#define AVLEAK

#include <wtypes.h>
#include <Winbase.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

void leak(unsigned char* data, int length);
void endLeak();
void drop(const unsigned char c, int i);
#endif