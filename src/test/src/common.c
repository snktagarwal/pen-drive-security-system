/*AUTHOR: SANKET
  You are advised not to TOUCH this file at all during development*/

#include<gtk/gtk.h>
#include "interface.h"

GtkWidget* window1 = NULL;
GtkProgressBar* pbar;
GtkTreeStore* file_list;
GtkTreeIter* global_parent = NULL;
gchar *name;
gchar *pass;
gchar *root_path;
GdkPixbuf *file_icon;
GdkPixbuf *dir_icon;

void create_top_level(){

   window1 = create_window1();

}

void set_uname(gchar *uname)
{
	name = uname;
}

void set_upass(gchar *upass)
{
	pass = upass;
}
