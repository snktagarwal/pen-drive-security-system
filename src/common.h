/*AUTHOR: SANKET
  You are advised not to TOUCH this file at all during development*/


extern GtkWidget *window1;
extern GtkProgressBar* pbar;
extern GtkTreeStore *file_list;
extern GtkTreeIter *global_parent;
extern gchar *name;
extern gchar *pass;
extern gchar *root_path;
extern GdkPixbuf *file_icon;
extern GdkPixbuf *dir_icon;
void create_top_level();
void set_uname(gchar *uname);
void set_upass(gchar *upass);
