#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* Ignore, just colors */
#define RED(s)     ("\x1b[31m\x1b[1m"s"\x1b[0m")
#define GREEN(s)   ("\x1b[32m\x1b[1m"s"\x1b[0m")
#define YELLOW(s)  ("\x1b[33m\x1b[1m"s"\x1b[0m")
#define BLUE(s)    ("\x1b[34m\x1b[1m"s"\x1b[0m")
#define MAGENTA(s) ("\x1b[35m\x1b[1m"s"\x1b[0m")
#define CYAN(s)    ("\x1b[36m\x1b[1m"s"\x1b[0m")
/* Ingore, just colors */

/* define page size */
unsigned long pagesize = 4096;

/* ignore, macros for selecting the page "P" belongs to */
#define PAGE_START(P) ((unsigned long)(P) & ~(pagesize-1))
#define PAGE_END(P)   (((unsigned long)(P) + pagesize - 1) & ~(pagesize-1))

/* just a big buffer */
unsigned char big_boy_buffer[1024];

/* set STDOUT to unbuffered */
void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    fflush(stdout);    
}

/* Look here, just here*/
void vuln() {

    /* Hmmm.... What could possibly go wrong...? */
    char buffer[100] = {0};

    printf(BLUE("You only get one chance... make it count!!\n"));
    printf(BLUE("What do you want to say to me: "));

    /* Nothing, right? RIGHT?! */
    gets(buffer);

    memcpy(big_boy_buffer, buffer, 100);

    /* Oh well, YOLO!*/
    printf(GREEN("\nYou said: %s \n"), buffer);
    
    return;
}

int main(int argc, char **argv) {

    setup();

    /* set set "big_boy_buffer" to rwx */
    mprotect((void *) PAGE_START(big_boy_buffer), 
            PAGE_END(big_boy_buffer + 1024) - PAGE_START(big_boy_buffer), 
            PROT_READ | PROT_WRITE | PROT_EXEC);

    printf(RED("GREETINGS FELLOW TRAVELER!\n\n"));
    printf(CYAN("My job is to repeat everything you say to me, just to annoy you!!\n"));
    printf(CYAN(":)\n\n"));

    vuln();
}
