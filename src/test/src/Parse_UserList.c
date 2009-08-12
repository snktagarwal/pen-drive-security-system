#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include "Parse_UserList.h"


int check_authentication(char *username,char *passwd){

	unsigned char sha[20];	
	int a,i;

	FILE *users_pass=fopen("users.pass","r");     

	char ch,user[20];
	int len;
	int flag; 
    
	while(1)
	{    
		len = 0;
		flag=1;
		fscanf(users_pass,"%c",&ch); 
		while(ch!=':') 
		{
			user[len++] = ch;
			fscanf(users_pass,"%c",&ch);	
			
			if( feof(users_pass) )
			{
				fclose(users_pass);
				return 0;
			}		
		}

		user[len]='\0';
    		printf("user : %s username : %s\n",user,username);

		if(!strcmp(user,username)) break;
	    
		while(ch!='\n')
		{		
			fscanf(users_pass,"%c",&ch);	
			if( feof(users_pass) )
			{
				fclose(users_pass);
				return 0;
			}	       	
		}	
	} 	

	getSHA(passwd,strlen(passwd),sha);
	
	for(i=0;i<20;i++){
		fscanf(users_pass,"%X",&a);
		if(!(a==sha[i])) {
			fclose(users_pass);		
			return 0;
		}
	}
    
    
	fclose(users_pass);
	return 1;
}

int does_exist (gchar *g_uname)
{
	int i;		
	//check for duplicate username
	//put the uname and passwords in users.pass

	FILE *users_pass;
	users_pass = fopen("users.pass","r");

		
	char ch,user[20];
	int len;
	int flag,flg=0; 
	while(1)
	{    
		len = 0;
		fscanf(users_pass,"%c",&ch); 
 	    
 		while(ch!=':') 
		{
			printf("%c \n",ch);
			user[len++] = ch;
			fscanf(users_pass,"%c",&ch);	
			
			if( feof(users_pass) )return 0;
		}
		
		
		user[len]='\0';
		if (!strcmp(user,g_uname)) return 1; 
	    
		while(ch!='\n')
		{		
			fscanf(users_pass,"%c",&ch);	
			if( feof(users_pass) )return 0;
		}
   	}
   	
	fclose(users_pass);
}

void change_password(char *g_uname,char *passwd){

	unsigned char sha[20];	
	int a,i;

	FILE *users_pass=fopen("users.pass","r+");     

	char ch,user[20];
	int flag; 
	int len;
    
	while(1)
	{    
		len = 0;
		flag=1;
		fscanf(users_pass,"%c",&ch); 
		while(ch!=':' &&  len<20 ) 
		{
			user[len++] = ch;
			fscanf(users_pass,"%c",&ch);	
			
			if( feof(users_pass) )
			{
				fclose(users_pass);
				return;
			}		
		}
		    
		user[len+1]='\0';
		
		if (strcmp(user,g_uname)!=1) break; 
				
		while(ch!='\n')
		{		
			fscanf(users_pass,"%c",&ch);	
			if( feof(users_pass) )
			{
				fclose(users_pass);
				return;
			}	       	
		}	
	} 	

	getSHA(passwd,strlen(passwd),sha);
	
	for(i=0;i<19;i++) fprintf(users_pass,"%2X ",(sha[i]));
	fprintf(users_pass,"%2X\n",(sha[i]));		
	fclose(users_pass);
}


/*
int main()
{

  if(check_authentication("sanket","sanket2"))printf("yes\n");
  else printf("no\n");
  return 0;	
}*/
