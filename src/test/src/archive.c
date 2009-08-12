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

	char make_tar_and_zip[200];
	sprintf(make_tar_and_zip,"tar -c %s > %s.tar; rm -Rf %s; zip %s.zip %s.tar; rm -f %s.tar",user_name,user_name,user_name,user_name,user_name,user_name);
	system(make_tar_and_zip);
}

void encrypt_archive(char *user_name, char *pass){

	char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
	char *password,*archive_name,rm_zip[100];

	archive_name=(char *)malloc((strlen(user_name)+10)*sizeof(char));
	sprintf(archive_name,"%s.zip",user_name);
	aescrypt(0, archive_name, user_name, pass, rand_key);
	sprintf(rm_zip,"rm -f %s",archive_name);
	system(rm_zip);

}

void decrypt_archive(char *user_name, char *pass)
{
	char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
	char *zip_name,*tar_name,extract[100];

	zip_name=(char *)malloc((strlen(user_name)+10)*sizeof(char));
	sprintf(zip_name,"%s.zip",user_name);

	tar_name=(char *)malloc((strlen(user_name)+10)*sizeof(char));
	sprintf(zip_name,"%s.tar",user_name);

	aescrypt(1,user_name,zip_name,rand_key);
	sprintf(extract,"unzip %s; rm -f %s; tar xvf %s; rm -f %s",zip_name,zip_name,tar_name,tar_name);
}
	
	

void main()
{

  decrypt_archive("opensoft","sanket");
}
	 
