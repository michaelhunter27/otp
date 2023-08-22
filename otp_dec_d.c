/* Name: Michael Hunter
 * Class: CS 344
 * Assignment 4 - OTP (one time pad)
 * Program: otp_dec_d
 * Usage: ./otp_dec_d <port> &
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define PACKET_SIZE 256

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues
char* resize(char* message, int size, int more);
char* decrypt(char* ciphertext, char* key);
int ctoi(char c);
char itoc(int i);


int main(int argc, char *argv[])
{
	//declarations and initializations
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	char buffer[PACKET_SIZE + 1];
	
	//process and fork() variables
	int num_children;
	int child_pid;
	int child_exit_method;
	int spawn_pid;

	int message_length = 0;
	int message_size = 0;
	char* message = NULL; //string to store message from otp_enc
	
	char* ciphertext = NULL; //stores ciphertext
	char* plaintext = NULL; //stores plaintext
	char* key = NULL; //stores key
	
	int total_chars_sent = 0;

	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) { perror("OTP_DEC_D: ERROR opening socket\n"); exit(2); }

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){ // Connect socket to port
		perror("OTP_DEC_D: ERROR on binding");
		exit(2);
	}
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections


	//LOOP!
	while(1){

		//clean up terminated children
		if(num_children > 0){
			do{
				child_pid = 0;
				child_pid = waitpid(-1, &child_exit_method, WNOHANG);
				if(child_pid != 0){
					num_children--;
				}
			}while(child_pid);
		}


		//if there are already 5 children, wait for one to terminate
		//before accepting another job
		if(num_children == 5){
			child_pid = wait(&child_exit_method);
			num_children--;
		}


		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("OTP_DEC_D: ERROR on accept\n");


		//FORK!
		spawn_pid = fork();
		
		switch(spawn_pid){
			case 0: //child

				//allocate memory for message
				message = resize(message, 0, 256);
				message_size = 256;

				// Get the message from the otp_enc
				do{
					memset(buffer, '\0', sizeof(buffer));
					charsRead = recv(establishedConnectionFD, buffer, PACKET_SIZE, 0); // Read the client's message from the socket
					if (charsRead < 0) error("OTP_DEC_D: ERROR reading from socket");

					if(message_length + charsRead > message_size){
						message = resize(message, message_size, 256);
						message_size += 256;
					}
					strcat(message, buffer);
					message_length += charsRead;
				}while(strstr(message, "$") == NULL && charsRead > 0);


				//message not intended for decryption
				if(message[0] == 'e'){
					//send a message back to break connection ("~")
					do{
						charsRead = send(establishedConnectionFD, "~", 1, 0);
					}while(charsRead < 1);
					error("OTP_DEC_D: ERROR connected to otp_enc");
				}


				//extract ciphertext from message
				ciphertext = strtok(message, "ed@$");
				//extract key from message
				key = strtok(NULL, "ed@$");


				//DECRYPT MESSAGE WITH KEY
				plaintext = decrypt(ciphertext, key);


				//SEND DECRYPTED MESSAGE BACK
				do{
					memset(buffer, '\0', sizeof(buffer));
					//copy plaintext characters into a buffer
					strncpy(buffer, &plaintext[total_chars_sent], PACKET_SIZE);
					//Send characters stored in buffer
					charsRead = send(establishedConnectionFD, buffer, PACKET_SIZE, 0); 
					if (charsRead < 0) error("OTP_DEC_D: ERROR writing to socket\n");
					total_chars_sent += charsRead;
				}while(total_chars_sent < strlen(plaintext));


				//clean up
				close(establishedConnectionFD); // Close the existing socket which is connected to the client
				close(listenSocketFD); // Close the listening socket
				return 0;
				break; //ending switch case (not needed)
				//end child

			default: //parent
				//increment number of children
				num_children++;
				break;
		}
		//end of while loop
	}
}
//end of main



//allocates and returns a string of (size + more) characters
//frees the old message string if not NULL
char* resize(char* message, int size, int more){
	char* new_message = malloc((size + more) * sizeof(char));
	memset(new_message, '\0', (size + more) * sizeof(char));
	if(message != NULL){
		strcpy(new_message, message);
	}
	if(message != NULL){
		free(message);
	}
	return new_message;
}



//decrypts ciphertext with key
//length of key is assumed to be greater than length of message
//returns containing the decrypted message with a $ at the end
//$ is appended for sending over the network, signals end of message
char* decrypt(char* ciphertext, char* key){
	char* plaintext = malloc(sizeof(char) * (strlen(ciphertext) + 2));
	memset(plaintext, '\0', sizeof(char) * (strlen(ciphertext) + 2));
	
	int i, num;
	for(i = 0; i < strlen(ciphertext); i++){
		num = ctoi(ciphertext[i]) - ctoi(key[i]);
		num += 27;
		num %= 27;
		plaintext[i] = itoc(num);
	}

	plaintext[strlen(ciphertext)] = '$';

	return plaintext;
}



//char to integer
int ctoi(char c){
	if(c >= 'A' && c <= 'Z'){
		return (int) c - 65;
	}
	else if (c == ' '){
		return 26;
	}
	else{
		return -1;
	}
}



//int to char
char itoc(int i){
	if(i >= 0 && i <= 25){
		return (char) i + 'A';
	}
	else if ( i == 26){
		return ' ';
	}
	else{
		return '\t';
	}
}
