/*THIS FILE IS RESPOSIBLE FOR ARTCHIVING THE FILE STRUCTURE OF A USER AND THEN PASSWORD PROTECTING/ENCRYPTING IT*/

/*TAKES IN A USERNAME, PASSWORD PAIR... GIVES A ENCRYPTED ARCHIVE AND VICE VERSA*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdlib.h>
#include "aes.h"

void make_plain_archive(char *user_name)
{

	/*a folder is assumed to be present with the name of the user, returns -1 if the folder is nonexistent*/
	//TODO: Check that the no folder exists does not exist... should not in any case :P

	char make_tar[200];
	sprintf(make_tar,"tar -c %s > %s.tar; rm -Rf %s",user_name,user_name,user_name);
	system(make_tar);
}

void encrypt_archive(char *user_name, char *pass){

	char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
	char *password,*archive_name,rm_tar[100];

	make_plain_archive(user_name);

	archive_name=(char *)malloc((strlen(user_name)+10)*sizeof(char));
	sprintf(archive_name,"%s.tar",user_name);

	password=(char *)malloc((strlen(pass)+1)*sizeof(char));
	strcpy(password,pass);

	aescrypt(0, archive_name, user_name, password, rand_key);
	sprintf(rm_tar,"rm -f %s",archive_name);


	system(rm_tar);

}

void decrypt_archive(char *user_name, char *pass)
{
	char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
	char *password,*tar_name,extract[100];

	tar_name=(char *)malloc((strlen(user_name)+10)*sizeof(char));
	sprintf(tar_name,"%s.tar",user_name);

	password=(char *)malloc((strlen(pass)+1)*sizeof(char));
	strcpy(password,pass);

	aescrypt(1,user_name,tar_name,password,rand_key);
	sprintf(extract,"tar xvf %s; rm -f %s",tar_name,tar_name);
	system(extract);
}
	
	

void main()
{
  //make_plain_archive("test");
  //encrypt_archive("sanket","sanket");
  decrypt_archive("sanket","sanket");
}
	 
