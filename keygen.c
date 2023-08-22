#include<stdio.h>
#include<stdlib.h>
#include<time.h>

int main(int argc, char* argv[]){
	//check for correct number of arguments
	if(argc != 2){
		printf("./keygen keylength\n");
		//wrong number of arguments, quit
		return 1;
	}

	//string to number
	int keylen = atoi(argv[1]);
	
	//seed random number generator
	srand(time(NULL));

	int i, num;
	char c;

	for(i = 0; i < keylen; i++){
		//get a random number
		num = rand() % 27;	
		
		//turn number into a character A-Z or ' '
		if(num == 26){
			c = ' ';
		}
		else{
			c = 'A' + num;
		}

		//write to stdout
		write(1, &c, 1);		

	}
	
	write(1, "\n", 1);		

	return 0;
}
