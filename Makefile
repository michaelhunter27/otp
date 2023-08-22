CC=gcc
#CFILES=smallsh.c
#HFILES=smallsh.h
#OFILES=smallsh.o
BACKUPDIR=otp-backups/otp-$(shell date +'%Y.%b.%d-%H:%M')


default:
	$(CC) -o keygen keygen.c
	$(CC) -o otp_enc otp_enc.c
	$(CC) -o otp_enc_d otp_enc_d.c
	$(CC) -o otp_dec otp_dec.c
	$(CC) -o otp_dec_d otp_dec_d.c

../otp-backups/:
	mkdir ../otp-backups/

backup: ../otp-backups/
	cp -fr . ../$(BACKUPDIR)

