//this program creates a file who's contents are a string of random characters of specified length
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char* argv[])
{
    srand(time(0));

    if(argc != 2)
    {
        //error statement
        printf("Please provide the length argument\n");
    }
    else
    {
        //convert argv[1] to an int
        int n = atoi(argv[1]);

        for(int i = 0; i < n; i++) //for however long the user specified
        {
            //generate a random upper-case letter
            int randNum = rand() % 27 + 65;
            if(randNum == 91) //if '[', set to ' ' (space)
            {
                randNum = 32;
            }
            printf("%c", randNum);
        }
        printf("\n"); //end with newline
    }
    
    return 0;
}