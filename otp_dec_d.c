#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <wait.h>

void error(const char *msg)
{
    perror(msg);
    exit(1);
} // Error function used for reporting issues

int main(int argc, char *argv[])
{
    int listenSocketFD, establishedConnectionFD, portNumber, charsRead, charsWritten;
    int numChildren = 0; //current number of child processes
    int status;          //status of process
    socklen_t sizeOfClientInfo;
    struct sockaddr_in serverAddress, clientAddress;
    char *token;                                //used when tokenizing the buffer
    char **tokens = malloc(2 * sizeof(char *)); //file names sent from client
    char buffer[1000];
    char *msg;
    char handshakeText[5];
    pid_t pid; //used when forking

    if (argc < 2)
    {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    } // Check usage & args

    // Set up the address struct for this process (the server)
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct

    portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string

    serverAddress.sin_family = AF_INET;         // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber); // Store the port number
    serverAddress.sin_addr.s_addr = INADDR_ANY; // Specify type allowance of any message

    // Set up the socket
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if (listenSocketFD < 0)
    {
        error("ERROR opening socket");
    }

    // Enable the socket to begin listening
    if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
    {
        error("ERROR on binding");
    }
    listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

    //main loop, forks each new connection
    while (1)
    {
        // Accept a connection, blocking if one is not available until one connects

        // Get the size of the address for the client that will connect
        sizeOfClientInfo = sizeof(clientAddress);
        establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept the connection
        if (establishedConnectionFD < 0)
        {
            error("ERROR on accept");
        }

        pid = fork();

        if (pid < 0) //error
        {
            error("Error forking, exiting\n");
        }
        else if (pid == 0) //child
        {
            // perform the handshake, expect e, send back e*
            memset(handshakeText, '\0', sizeof(handshakeText));

            charsRead = recv(establishedConnectionFD, handshakeText, sizeof(handshakeText) - 1, 0);
            if (charsRead < 0)
            {
                error("CLIENT: ERROR reading from socket");
            }

            if (strcmp("d", handshakeText) == 0)
            {
                strcat(handshakeText, "*"); //make the string d*

                charsWritten = send(establishedConnectionFD, handshakeText, sizeof(handshakeText) - 1, 0);
                if (charsWritten < 0)
                {
                    error("CLIENT: ERROR writing to socket\n");
                }
                if (charsWritten < strlen("d"))
                {
                    fprintf(stderr, "CLIENT: WARNING: Not all data written to socket!\n");
                }
            }
            else
            {
                fprintf(stderr, "OTP_DEC_D: handshake failed, accepting new connections\n");
                close(establishedConnectionFD); //close connection so that error is thrown in child
            }
            //get the size of the message from the client and display it
            int msgSize = 0;
            charsRead = recv(establishedConnectionFD, &msgSize, sizeof(msgSize), 0); // Read the client's message from the socket
            if (charsRead < 0)
            {
                error("ERROR reading from socket");
            }
            msg = malloc(sizeof(char) * msgSize);
            memset(msg, '\0', sizeof(msg));

            int i = 0;
            while (i < msgSize) //get the msg 1000 characters at a time
            {
                memset(buffer, '\0', sizeof(buffer));
                // Get the message from the client and display it
                charsRead = recv(establishedConnectionFD, buffer, 999, 0); // Read the client's message from the socket, excluding the last char cause it keeps corrupting for some reason
                if (charsRead < 0)
                {
                    error("ERROR reading from socket");
                }

                strcat(msg, buffer);
                i += charsRead;
            }

            //tokenize the received string
            token = strtok(msg, "#");
            tokens[0] = token; //plaintext
            token = strtok(NULL, "#");
            tokens[1] = token; //key

            //encode
            char cipherChar;
            char cipherStr[msgSize];

            memset(cipherStr, '\0', sizeof(cipherStr));
            //for every character in the plaintext
            for (int i = 0; i < strlen(tokens[0]); i++)
            {
                int ptextChar = tokens[0][i]; //get ptext character
                int keyChar = tokens[1][i];   //get keyt character

                if (ptextChar == '\n') // if a newline is encounterd, break the loop
                {
                    break;
                }

                //if a space is found, turn it to '[' (char after Z)
                if (ptextChar == ' ')
                {
                    ptextChar = '[';
                }
                if (keyChar == ' ')
                {
                    keyChar = '[';
                }

                //calc cipher char
                cipherChar = (ptextChar - keyChar);
                if(cipherChar < 0)
                {
                    cipherChar += 27;
                }
                cipherChar = cipherChar % 27 + 65;


                if (cipherChar == '[')
                {
                    cipherStr[i] = ' ';
                }
                else
                {
                    cipherStr[i] = cipherChar;
                }
            }
            cipherStr[strlen(cipherStr)] = '\0'; //null terminate the cipher string

            i = 0;
            while (i < strlen(cipherStr))
            {
                charsWritten = send(establishedConnectionFD, cipherStr + i, 1000, 0); //send 1000 chars of msg to server
                if (charsWritten < 0)
                {
                    error("CLIENT: ERROR writing to socket\n");
                }
                if (charsWritten < 1000)
                {
                    printf("CLIENT: WARNING: Not all data written to socket!\n");
                }

                i += charsWritten;
            }

            close(establishedConnectionFD);
            exit(0); //exit the forked process
        }
        else //parent
        {
            close(establishedConnectionFD); //close the socket connected to the client
        }
    }
    close(listenSocketFD); //close the listening socket
    return 0;
}
