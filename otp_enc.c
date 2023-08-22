/* Name: Michael Hunter
 * Class: CS 344
 * Assignment 4 - OTP (one time pad)
 * Program: otp_enc
 * Usage: otp_enc <plaintext> <key> <port>
*/



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>

#define PACKET_SIZE 256

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues
char* resize(char* message, int size, int more);
int validChars(char* text);

int main(int argc, char *argv[])
{
	//declarations and initializations
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[PACKET_SIZE + 1];
   
	int chars_read = 0;

	//message is the string that is sent to otp_enc_d
	char* message = NULL;
	int message_length = 0;
	int message_size = 0;
	
	int key_length;
	int plaintext_length;

	int total_chars_written = 0;
	
	char* ciphertext = NULL;
	int ciphertext_length = 0;
	int ciphertext_size = 0;


	// Check usage & args
	if (argc < 4) { 
		fprintf(stderr,"USAGE: %s plaintext key port", argv[0]); 
		exit(0); 
	}

	//open plaintext file
	int plaintext_fd = open(argv[1], O_RDONLY);
	if(plaintext_fd < 0){
		error("OTP_ENC: ERROR opening plaintext file");
	}

	//open key file
	int key_fd = open(argv[2], O_RDONLY);
	if(key_fd < 0){
		error("OTP_ENC: ERROR opening plaintext file");
	}

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	//serverHostInfo = gethostbyname(argv[1]); // Convert the machine name into a special form of address
	serverHostInfo = gethostbyname("localhost"); // convert localhost into special address
	if (serverHostInfo == NULL) { fprintf(stderr, "OTP_ENC: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("OTP_ENC: ERROR opening socket");
	
	// Connect to server (otp_enc_d)
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("OTP_ENC: ERROR connecting");

	//FORMAT MESSAGE
	//message format: "ePLAINTEXT@KEY$"
	
	//allocate memory for message
	message = resize(message, 0, 256);
	message_size = 256;
	message_length = 0;

	//set first character of message to 'e'
	//signals the receiver that the message is for encryption
	message[0] = 'e';
	message_length = 1;

	//GET PLAINTEXT FROM FILE
	do{
		memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
		chars_read = read(plaintext_fd, buffer, PACKET_SIZE);
		if(chars_read < 0){
			error("OTP_ENC: ERROR reading from plaintext file");
		}
		else{
			if((message_length + chars_read) > message_size){
				//resize string if needed
				message = resize(message, message_size, 256);
				message_size += 256;
			}
			strcat(message, buffer);
			message_length += chars_read;
		}
	}while(chars_read > 0);

	//overwrite trailing newline character if needed
	if(strstr(message, "\n") != NULL){
		strstr(message, "\n")[0] = '\0';
	}

	//validate plaintext characters (plaintext starts after initial 'e')
	if(!validChars(message + 1)){
		error("OTP_ENC: ERROR invalid plaintext characters");
	}

	//store length of plaintext
	plaintext_length = strlen(message) - 1;

	//append "@"
	if(message_length + 1 > message_size){
		message = resize(message, message_size, 256);
		message_size += 256;
	}
	strcat(message, "@");
	message_length++;


	//append KEY
	do{
		memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
		chars_read = read(key_fd, buffer, PACKET_SIZE);
		if(chars_read < 0){
			error("OTP_ENC: ERROR reading from key file");
		}
		else{
			if((message_length + chars_read) > message_size){
				message = resize(message, message_size, 256);
				message_size += 256;
			}
			strcat(message, buffer);
			message_length += chars_read;
		}
	}while(chars_read > 0);
	
	//overwrite trailing newline character if needed
	if(strstr(message, "\n") != NULL){
		strstr(message, "\n")[0] = '\0';
	}
	
	//pointer to the start of the key
	char* key = strstr(message, "@") + 1;

	//validate key characters
	if(!validChars(key)){
		error("OTP_ENC: ERROR invalid key characters");
	}

	//check if key is long enough to encrypt plaintext
	key_length = strlen(key);
	if(key_length < plaintext_length){
		error("OTP_ENC: ERROR key too short for plaintext");
	}

	//append "$"
	if(message_length + 1 > message_size){
		message = resize(message, message_size, 256);
		message_size += 256;
	}
	strcat(message, "$");


	//SEND MESSAGE
	// Send message to server
	while(total_chars_written < message_length){
		memset(buffer, '\0', sizeof(buffer));
		strncpy(buffer, &message[total_chars_written], PACKET_SIZE);
		charsWritten = send(socketFD, buffer, PACKET_SIZE, 0); // Write to the server
		if (charsWritten < 0) error("OTP_ENC: ERROR writing to socket");
		if (charsWritten <  256) printf("OTP_ENC: WARNING: Not all data written to socket!\n");
		total_chars_written += charsWritten;
	}


	//allocate memory for ciphertext string
	ciphertext = resize(ciphertext, 0, 256);
	ciphertext_length = 0;
	ciphertext_size = 256;
	
	
	//check that we're connected to otp_enc_d NOT otp_dec_d
	//otp_dec_d will send "~"
	do{
		//get one character
		charsRead = recv(socketFD, buffer, 1, 0);
	}while(charsRead < 0);
	//report error and quit
	if(buffer[0] == '~'){
		error("OTP_ENC: ERROR connected to otp_dec_d");
	}
	else{
		//store the first character
		ciphertext[0] = buffer[0];
	}


	//RECEIVE CIPHERTEXT
	do{
		memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
		charsRead = recv(socketFD, buffer, PACKET_SIZE, 0); // Read data from the socket, leaving \0 at end
		if (charsRead < 0) error("OTP_ENC: ERROR reading from socket");
		if(ciphertext_length + charsRead > ciphertext_size){
			ciphertext = resize(ciphertext, ciphertext_size, 256);
			ciphertext_size += 256;
		}
		strcat(ciphertext, buffer);
		ciphertext_length += charsRead;
	}while(strstr(ciphertext, "$") == NULL && charsRead > 0); //read from socket until "$" is read
	
	//overwrite trailing '$'
	strstr(ciphertext, "$")[0] = '\0';

	//print plaintext to user
	printf("%s\n", ciphertext);

	close(socketFD); // Close the socket
	return 0;
}



//Returns a string with (size + more) bytes allocated
//frees the old string if not NULL
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


//checks that all of the characters in text are 'A' - 'Z' or ' '
//returns 1 (true) if all characters are valid
//returns 0 (false) if there is an invalid character
int validChars(char* text){
	int i;
	for(i = 0; i < strlen(text); i++){
		if((text[i] < 'A' || text[i] > 'Z') && text[i] != ' '){
			return 0;
		}
	}
	return 1;
}
