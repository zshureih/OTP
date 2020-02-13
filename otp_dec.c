#define _GNU_SOURCE //used to include getline() in stdio.h
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

void error(const char *msg)
{
    perror(msg);
    exit(0);
} // Error function used for reporting issues

void checkFiles(char *file1, char *file2)
{
    // If otp_dev receives key or plaintext files with ANY bad characters in them, or the key file is shorter than the plaintext,
    // then it should terminate, send appropriate error text to stderr, and set the exit value to 1
    FILE *plainFp = fopen(file1, "r");
    FILE *keyFp = fopen(file2, "r");
    char *fcontent;

    if (plainFp == NULL)
    {
        printf("%s is not a valid file\n", file1);
        exit(1);
    }
    if (keyFp == NULL)
    {
        printf("%s is not a valid file\n", file2);
        exit(1);
    }

    //compare file lengths first
    fseek(plainFp, 0, SEEK_END);
    int byteCount1 = ftell(plainFp); //length of plaintext file

    fseek(keyFp, 0, SEEK_END);
    int byteCount2 = ftell(keyFp); //length of key file

    if (byteCount2 < byteCount1)
    {
        perror("The key file is shorter than the plaintext file\n");
        exit(1);
    }

    //rewind the filepointers back to the beginning of the files
    rewind(plainFp);
    rewind(keyFp);

    //read content from plaintext file
    fcontent = (char *)malloc(sizeof(char) * byteCount1);
    fread(fcontent, 1, byteCount1, plainFp);
    //check each character to make sure it is valid, excluding the newline at the end
    for (int i = 0; i < byteCount1 - 1; i++)
    {
        int currChar = fcontent[i];

        if (currChar < 65 && currChar != 32) //if character is less than A and not ' ' on ascii table
        {
            perror("Invalid character in plaintext file (less than A)\n");
            exit(1);
        }
        else if (currChar > 90) //if character is greater than Z
        {
            perror("Invalid character in plaintext file (Greater than Z) \n");
            exit(1);
        }
    }

    free(fcontent); // free fcontent so we can read key file text

    //read content from key file
    fcontent = (char *)malloc(sizeof(char) * byteCount2);
    fread(fcontent, 1, byteCount2, keyFp);
    //check each character to make sure it is valid
    for (int i = 0; fcontent[i] != '\n'; i++)
    {
        int currChar = fcontent[i];

        if (currChar < 65 && currChar != 32) //if character is less than A and not ' ' on ascii table
        {
            perror("Invalid character in key file (less than A)\n");
            exit(1);
        }
        else if (currChar > 90) //if character is greater than Z
        {
            perror("Invalid character in key file (greater than Z)\n");
            exit(1);
        }
    }
    // free memory
    free(fcontent);
    memset(fcontent, '\0', sizeof(fcontent));
    //close files
    fclose(plainFp);
    fclose(keyFp);
}

int main(int argc, char *argv[])
{
    int socketFD, portNumber, charsWritten, charsRead;
    struct sockaddr_in serverAddress;
    struct hostent *serverHostInfo;
    char handshakeText[5];
    char *plaintext;   //this will hold the plaintext
    char *key;         //this will hold the generated key
    char *msg;         //this will hold the message sent to the server
    char *cipher_text; //this will hold the data received from the server

    FILE *plainFp;  //points to plaintext file
    FILE *keyFp;    //points to key file
    char *fcontent; //stores text of file
    int filesize1, filesize2;

    if (argc < 4)
    {
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]);
        exit(0);
    } // Check usage & args

    //before any networking shenanigans, check to make sure files are valid
    checkFiles(argv[1], argv[2]);

    // Set up the server address struct
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    portNumber = atoi(argv[3]);                                  // Get the port number, convert to an integer from a string
    serverAddress.sin_family = AF_INET; // Create a network-capable socket

    serverAddress.sin_port = htons(portNumber);  // Store the port number
    serverHostInfo = gethostbyname("localhost"); // always going to be localhost for this program
    if (serverHostInfo == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(0);
    }

    // Copy in the address
    memcpy((char *)&serverAddress.sin_addr.s_addr, (char *)serverHostInfo->h_addr_list[0], serverHostInfo->h_length);

    // Set up the socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    // Create the socket
    if (socketFD < 0)
    {
        error("CLIENT: ERROR opening socket\n");
    }

    // Connect to server
    // Connect socket to address
    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        error("CLIENT: ERROR connecting");
    }

    //perform handshake
    charsWritten = send(socketFD, "d", strlen("d"), 0); //send "d" to server
    if (charsWritten < 0)
    {
        error("CLIENT: ERROR writing to socket\n");
    }
    if (charsWritten < strlen("d"))
    {
        fprintf(stderr, "CLIENT: WARNING: Not all data written to socket!\n");
    }

    memset(handshakeText, '\0', sizeof(handshakeText));
    //expect to get "d*" back from server (opt_enc_d)
    charsRead = recv(socketFD, handshakeText, sizeof(handshakeText) - 1, 0);
    if (charsRead < 0)
    {
        error("CLIENT: ERROR reading from socket");
    }

    if (strcmp("d*", handshakeText) != 0)
    {
        fprintf(stderr, "OTP_DEC: handshake failed at port %d, exiting now\n", portNumber);
        exit(2);
    }

    //if handshake is goes through, send message

    //open the plaintext file
    plainFp = fopen(argv[1], "r");

    ssize_t buffSize = 0;                               //have getline allocate a buffer
    filesize1 = getline(&fcontent, &buffSize, plainFp); //every plaintext file is a single line ending with a '\n'
    fcontent[filesize1 - 1] = '\0';

    plaintext = malloc(sizeof(char) * filesize1);
    strcpy(plaintext, fcontent); //copy the content to another array

    fclose(plainFp); //close the plaintext file

    //do the process again for the key file
    keyFp = fopen(argv[2], "r");

    filesize2 = getline(&fcontent, &buffSize, keyFp); //every key file is a single line ending with a '\n'
    fcontent[filesize2 - 1] = '\0';

    key = malloc(sizeof(char) * filesize2);
    strcpy(key, fcontent); //copy the content to another array

    fclose(keyFp); //close the plaintext file

    msg = malloc(sizeof(char) * (filesize1 + filesize2 + 2));
    memset(msg, '\0', sizeof(msg));

    //format data to be sent to enc_d in a single string
    strcpy(msg, plaintext);
    strcat(msg, "#");
    strcat(msg, key);
    strcat(msg, "#");

    //send size of the string to be sent
    int msgSize = strlen(msg);

    charsWritten = send(socketFD, &msgSize, sizeof(msgSize), 0); //will send at most a 10-digit long number
    if (charsWritten < 0)
    {
        error("CLIENT: ERROR writing to socket\n");
    }

    //send string
    int i = 0;
    while (i < msgSize)
    {
        charsWritten = send(socketFD, msg + i, 999, 0); //send 1000 chars of msg to server
        if (charsWritten < 0)
        {
            error("CLIENT: ERROR writing to socket\n");
        }

        i += charsWritten;
    }

    // Get return message from server
    cipher_text = malloc(sizeof(char) * strlen(plaintext)); //the cipher will only be as long as the plaintext
    memset(cipher_text, '\0', sizeof(cipher_text));

    char buffer[1000];
    i = 0;
    while (i < strlen(plaintext)) //get the msg 1000 characters at a time
    {
        // Get the message from the client and display it
        memset(buffer, '\0', sizeof(buffer));
        charsRead = recv(socketFD, buffer, 1000, 0); // Read the client's message from the socket, excluding the last char cause it keeps corrupting for some reason
        if (charsRead < 0)
        {
            error("ERROR reading from socket");
        }

        strcat(cipher_text, buffer);
        i += charsRead;
    }

    printf("%s\n", cipher_text);

    close(socketFD); // Close the socket
    return 0;
}
