#include "functions.h"
#include "common.h"

enum
{
  ICON = 0,
  NAME,
  ACTION,
  LOCATION,
  NUM_COLS
} ;

void recursive_clear(GtkTreeIter* parent)
{
	GtkTreeIter iter;
	gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &iter, parent);

	do {
		gtk_tree_store_set (file_list, &iter, ACTION, "", LOCATION, "", -1);

		GtkTreeIter subdir;
		if (gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &subdir, &iter) != FALSE)
			recursive_clear(&iter);
	}
	while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &iter) != FALSE);
}

void recursive_pass_change(GtkTreeIter* parent, gchar* current, gchar* new_pass)
{
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);

    if (gtk_tree_model_iter_children (model, &iter, parent) != FALSE) {

		do {
			gchar* path = get_address_of_selection(model, &iter);
			gchar* tmp;
			tmp = (gchar*)malloc(1000*sizeof(gchar));
			tmp = strcpy(tmp,root_path);
			tmp = strcat(tmp,"/");
			tmp = strcat(tmp,path);

			GtkTreeIter subdir;
			if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {
				change(tmp, current, new_pass);
			}
			else
				recursive_pass_change(&iter, current, new_pass);
		}
		while (gtk_tree_model_iter_next (model, &iter) != FALSE);
	}
}

void recursive_add(GtkTreeIter* parent)
{
	gchar *file_name;
	gchar *action;
	gchar *location;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);

	gtk_tree_model_iter_children (model, &iter, parent);

	do {
		gtk_tree_model_get (model, &iter, NAME, &file_name, ACTION, &action, LOCATION, &location, -1);
		
		GtkTreeIter subdir;
		gchar* get_path;
		gchar* put_path;
		get_path = (gchar*)malloc(1000*sizeof(gchar));
		put_path = (gchar*)malloc(1000*sizeof(gchar));

		gchar* path = get_address_of_selection(model, &iter);
		put_path = strcpy(put_path, root_path);
		put_path = strcat(put_path, "/");
		put_path = strcat(put_path, path);

		if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {

			get_path = strcpy(get_path, location);
			//g_print("Adding File : \nGet: %s \nPut: %s\n\n",get_path,put_path);
							
			//****************************************************************************//
			char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
			char *password = malloc(10);
			strcpy(password,pass);

			aescrypt(0, get_path, put_path, password, rand_key);
			//****************************************************************************//
		}
		else {
			//g_print("Make Folder : %s\n\n",put_path);
			g_mkdir (put_path, 0777);

			//recrsively add
			recursive_add(&iter);
		}
		gtk_progress_bar_pulse (pbar);
	}
	while (gtk_tree_model_iter_next (model, &iter) != FALSE);
}

void recursive_extract(GtkTreeIter* parent, gchar* location)
{
	gchar *file_name;
	gchar *action;
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);
	GtkTreeIter iter;

	gtk_tree_model_iter_children (model, &iter, parent);

	do {
		gtk_tree_model_get (model, &iter, NAME, &file_name, ACTION, &action, -1);
		
		GtkTreeIter subdir;
		gchar* get_path;
		gchar* put_path;
		get_path = (gchar*)malloc(1000*sizeof(gchar));
		put_path = (gchar*)malloc(1000*sizeof(gchar));

		gchar* path = get_address_of_selection(model, &iter);
		put_path = strcpy(put_path, root_path);
		put_path = strcat(put_path, "/");
		put_path = strcat(put_path, path);

		get_path = strcpy(get_path, location);
		get_path = strcat(get_path, "/");
		get_path = strcat(get_path, file_name);

		if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {

			//g_print("De-Encrypt File : \nGet: %s \nPut: %s\n\n",put_path, get_path);

			//****************************************************************************//
			char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
			char *password = malloc(10);
			strcpy(password,pass);

			aescrypt(1, put_path, get_path, password, rand_key);
			//****************************************************************************//
		}
		else {
			//g_print("Make Folder : %s\n\n",get_path);
			g_mkdir (get_path, 0777);

			//extact the contents recursively..
			recursive_extract(&iter, get_path);
		}
		gtk_progress_bar_pulse (pbar);
	}
	while (gtk_tree_model_iter_next (model, &iter) != FALSE);
}

void recursive_delete(GtkTreeIter* parent)
{
	gchar *name;
	gchar *action;
	gchar *location;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);

	gtk_tree_model_iter_children (model, &iter, parent);

	do {
		gtk_tree_model_get (model, &iter, NAME, &name, ACTION, &action, LOCATION, &location, -1);
		
		GtkTreeIter subdir;
		gchar* get_path;
		gchar* put_path;
		get_path = (gchar*)malloc(1000*sizeof(gchar));
		put_path = (gchar*)malloc(1000*sizeof(gchar));

		gchar* path = get_address_of_selection(model, &iter);
		put_path = strcpy(put_path, root_path);
		put_path = strcat(put_path, "/");
		put_path = strcat(put_path, path);

		if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {

			//g_print("Delete File : %s\n\n",put_path);
			g_remove(put_path);
		}
		else {

			//recursively delele inner contents
			recursive_delete(&iter);
			
			//g_print("Delete Folder : %s\n\n",put_path);
			g_rmdir(put_path);
		}
		gtk_progress_bar_pulse (pbar);
	}
	while (gtk_tree_model_iter_next (model, &iter) != FALSE);
}

void recursive_apply_changes(GtkTreeIter* parent)
{
	gchar *file_name;
	gchar *action;
	gchar *location;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);
	
	gtk_tree_model_iter_children (model, &iter, parent);

	do {
		gtk_tree_model_get (model, &iter, NAME, &file_name, ACTION, &action, LOCATION, &location, -1);
			
		GtkTreeIter subdir;
		gchar* get_path;
		gchar* put_path;
		get_path = (gchar*)malloc(1000*sizeof(gchar));
		put_path = (gchar*)malloc(1000*sizeof(gchar));

		gchar* path = (gchar*)get_address_of_selection(model, &iter);

		put_path = strcpy(put_path, root_path);
		put_path = strcat(put_path, "/");
		put_path = strcat(put_path, path);

		if (strcmp(action,"To be Added") == 0){

			if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {
				
				get_path = strcpy(get_path, location);

				//g_print("Encrypt File : \nGet: %s \nPut: %s\n\n",get_path, put_path);
						
				//****************************************************************************//
				char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
				char *password = malloc(10);
				strcpy(password,pass);

				aescrypt(0, get_path, put_path, password, rand_key);
				//****************************************************************************//
			}
			else {
				//g_print("Make Folder : %s\n\n",put_path);
				g_mkdir (put_path, 0777);
	
				//recrsively add
				recursive_add(&iter);
			}
		}
		else if (strcmp(action,"To be Deleted") == 0){

			if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {

				//g_print("Delete File : %s\n\n",put_path);
				g_remove(put_path);
			}
			else {

				//recursively delele inner contents
				recursive_delete(&iter);
				
				//g_print("Delete Folder : %s\n\n",put_path);
				g_rmdir(put_path);
			}
		}
		else if (strcmp(action,"To be Extracted") == 0){

			get_path = strcpy(get_path, location);
			get_path = strcat(get_path, "/");
			get_path = strcat(get_path, file_name);

			if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {

				//g_print("De-Encrypt File : \nGet: %s \nPut: %s\n\n",put_path, get_path);

				//****************************************************************************//
				char rand_key[15] = "123456789ABCDEF";                    //= get_rand_key();
				char *password = malloc(10);
				strcpy(password,pass);

				aescrypt(1, put_path, get_path, password, rand_key);
				//****************************************************************************//

			}
			else {
				//g_print("Make Folder : %s\n\n",get_path);
				g_mkdir (get_path, 0777);

				//extact the contents recursively..
				recursive_extract(&iter, get_path);
			}
		}
		else {
			if (gtk_tree_model_iter_children (model, &subdir, &iter) != FALSE)
				recursive_apply_changes(&iter);
		}
		gtk_progress_bar_pulse (pbar);
	}
	while (gtk_tree_model_iter_next (model, &iter) != FALSE);
}

void refresh_dir_view()
{
	GtkWidget *dir_view = (GtkWidget*)lookup_widget(window1,"dir_view");
	GtkTreeStore *dir_store = generate_dir_view_store();
	gtk_tree_view_set_model (GTK_TREE_VIEW (dir_view), GTK_TREE_MODEL(dir_store));
}

void refresh_file_view()
{
	find_parent_dir();
	GtkWidget *file_view = (GtkWidget*)lookup_widget(window1,"file_view");
	GtkTreeStore *file_store = generate_file_view_store();
	gtk_tree_view_set_model (GTK_TREE_VIEW (file_view), GTK_TREE_MODEL(file_store));
}

void to_be_added_files(GtkTreeIter* parent, gchar* path)
{
	GError** error = NULL;
	GDir* dir = g_dir_open (path, 0, error);
	GtkTreeIter iter;

	if (dir != NULL) {

		const gchar* file_name;
		gchar* location;
		location = (gchar*)malloc(1000*sizeof(gchar));

		file_name = g_dir_read_name (dir);
		
		while (file_name != NULL){

			location = strcpy(location,path);
			location = strcat(location,"/");
			location = strcat(location,file_name);

			gtk_tree_store_append (file_list, &iter, parent);
//Needs Amends
			gtk_tree_store_set (file_list, &iter, ICON, file_icon, NAME, file_name, ACTION, "To be Added", LOCATION, location, -1);

			to_be_added_files(&iter, location);

			file_name = g_dir_read_name (dir);
		}
		g_dir_close (dir);
	}
}

void to_be_deleted_files(GtkTreeIter* parent)
{
	GtkTreeIter iter;

	gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &iter, parent);
	do {
		gtk_tree_store_set (file_list, &iter, ACTION, "To be Deleted", -1);
		GtkTreeIter subdir;
		if (gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &subdir, &iter) != FALSE)
			to_be_deleted_files(&iter);
	}
	while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &iter) != FALSE);
}

void to_be_extracted_files(GtkTreeIter* parent, gchar *location)
{
	GtkTreeIter iter;
	gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &iter, parent);

	do {
		gchar* string;
		gtk_tree_model_get (GTK_TREE_MODEL(file_list), &iter, NAME, &string, -1);

		gtk_tree_store_set (file_list, &iter, ACTION, "To be Extracted", LOCATION, location, -1);

		GtkTreeIter subdir;
		gchar* new_location;
		new_location = (gchar*)malloc(1000*sizeof(gchar));
		if (gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &subdir, &iter) != FALSE){
			new_location = strcpy(new_location,location);
			new_location = strcat(new_location,"/");
			new_location = strcat(new_location,string);
			to_be_extracted_files(&iter, new_location);
		}
	}
	while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &iter) != FALSE);
}

void move_to_parent_dir(GtkTreeIter *parent, gchar* path)
{
	GtkTreeIter iter;
	gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &iter, parent);
	gchar* string;

	do {
		string = get_address_of_selection(GTK_TREE_MODEL(file_list), &iter);
		if(strcmp(string,path) == 0)
			*global_parent = iter;
			
		GtkTreeIter subdir;
		if (gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &subdir, &iter) != FALSE)
			move_to_parent_dir(&iter, path);
	}
	while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &iter) != FALSE);
}

void find_parent_dir()
{

	GtkTreeView *dir_view = GTK_TREE_VIEW((GtkWidget*)lookup_widget(window1,"dir_view"));
	GtkTreeSelection *select = gtk_tree_view_get_selection (dir_view);
	GtkTreeModel **model;
	GtkTreeIter iter;

	GtkTreeModel *dir_model = gtk_tree_view_get_model(dir_view);

	if (gtk_tree_selection_get_selected(select, model, &iter) == TRUE){

		global_parent = (GtkTreeIter*)malloc(sizeof(GtkTreeIter));
		gchar* path = get_address_of_selection(dir_model, &iter);
		if(strcmp(path, "...") == 0){
			global_parent = NULL;
			return;
		}
		gchar* string;
		GtkTreeIter parent;

		gtk_tree_model_get_iter_first (GTK_TREE_MODEL(file_list), &parent);
		
		do {
			string = get_address_of_selection(GTK_TREE_MODEL(file_list), &parent);
			if(strcmp(string,path) == 0){
				*global_parent = parent;
				return;
			}

			GtkTreeIter subdir;
			if (gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &subdir, &parent) != FALSE)
				move_to_parent_dir(&parent, path);
		}
		while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &parent) != FALSE);

	}
	else{
		global_parent = NULL;
		return;
	}
}

gchar* get_address_of_selection(GtkTreeModel *model, GtkTreeIter *iter)
{
	gchar* adres;
	adres = (gchar*)malloc(1000*sizeof(gchar));
	gchar* str;
	str = (gchar*)malloc(1000*sizeof(gchar));

	gtk_tree_model_get (model, iter, NAME, &str, -1);
	strcpy(adres,str);
	g_free(str);
	str = (gchar*)malloc(1000*sizeof(gchar));

	GtkTreeIter *child = iter;
	GtkTreeIter *parent;
	parent = (GtkTreeIter*)malloc(sizeof(GtkTreeIter));
	GtkTreeIter temp;

	while (gtk_tree_model_iter_parent (model, parent, child) != FALSE) {		
		gchar* tmp;
		tmp = (gchar*)malloc(1000*sizeof(gchar));
		str = (gchar*)malloc(1000*sizeof(gchar));

		gtk_tree_model_get (model, parent, NAME, &tmp, -1);
		strcpy(str,tmp);
		g_free (tmp);

		strcat(str,"/");
		adres = strcat(str,adres);
		
		child = parent;
		parent = (GtkTreeIter*)malloc(sizeof(GtkTreeIter));
	}

	return adres;
}

GtkTreeStore* generate_file_view_store()
{
	GtkTreeStore *file_store;
  	GtkTreeIter iter;
	GtkTreeIter subdir;
	GtkTreeIter file_iter;
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);
	gchar* string;
	gchar* action;

	file_store = gtk_tree_store_new (3, GDK_TYPE_PIXBUF, G_TYPE_STRING, G_TYPE_STRING);

	if (global_parent == NULL) {
		if (gtk_tree_model_get_iter_first (model, &iter) != FALSE) {
			do {
				gtk_tree_model_get (model, &iter, NAME, &string, ACTION, &action, -1);
				gtk_tree_store_append (file_store, &file_iter, NULL);
	
				if(gtk_tree_model_iter_children (model, &subdir, &iter) != FALSE)
					gtk_tree_store_set (file_store, &file_iter, ICON, dir_icon, NAME, string, ACTION, action, -1);
				else
					gtk_tree_store_set (file_store, &file_iter, ICON, file_icon, NAME, string, ACTION, action, -1);
			}
			while (gtk_tree_model_iter_next (model, &iter) != FALSE);
		}
	}
	else {
		if (gtk_tree_model_iter_children (model, &iter, global_parent) != FALSE) {
			do {
				gtk_tree_model_get (model, &iter, NAME, &string, ACTION, &action, -1);
				gtk_tree_store_append (file_store, &file_iter, NULL);

				if(gtk_tree_model_iter_children (model, &subdir, &iter) != FALSE)
					gtk_tree_store_set (file_store, &file_iter, ICON, dir_icon, NAME, string, ACTION, action, -1);
				else
					gtk_tree_store_set (file_store, &file_iter, ICON, file_icon, NAME, string, ACTION, action, -1);
			}
			while (gtk_tree_model_iter_next (model, &iter) != FALSE);
		}		
	}

	return file_store;
}

void recursive_generate_dir_store (GtkTreeStore *dir_store, GtkTreeIter *parent, GtkTreeIter *dir)
{
	gchar *string;
	GtkTreeIter iter;
	GtkTreeIter dir_iter;

	GtkTreeModel *model = GTK_TREE_MODEL (file_list);

	if (gtk_tree_model_iter_children (model, &iter, dir) != FALSE) {
		
		do {
			gtk_tree_model_get (model, &iter, NAME, &string, -1);
			GtkTreeIter subdir;
	
			if (gtk_tree_model_iter_children (model, &subdir, &iter) != FALSE){
				
				gtk_tree_store_append (dir_store, &dir_iter, parent);
				gtk_tree_store_set (dir_store, &dir_iter, ICON, dir_icon, NAME, string, -1);
	
				recursive_generate_dir_store (dir_store, &dir_iter, &iter);
			}
		}
		while (gtk_tree_model_iter_next (model, &iter) != FALSE);
	}
}

GtkTreeStore* generate_dir_view_store()
{
	GtkTreeStore *dir_store;
  	GtkTreeIter iter;
	GtkTreeIter dir_iter;
	gchar* string;
	
	dir_store = gtk_tree_store_new (2, GDK_TYPE_PIXBUF, G_TYPE_STRING);
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);

    if (gtk_tree_model_get_iter_first (model, &iter) != FALSE) {

		gtk_tree_store_append (dir_store, &dir_iter, NULL);
		gtk_tree_store_set (dir_store, &dir_iter, NAME, "...", -1);

		do {

			gtk_tree_model_get (model, &iter, NAME, &string, -1);
			GtkTreeIter subdir;

			if (gtk_tree_model_iter_children (model, &subdir, &iter) != FALSE){
				
				gtk_tree_store_append (dir_store, &dir_iter, NULL);
				gtk_tree_store_set (dir_store, &dir_iter, ICON, dir_icon, NAME, string, -1);

				recursive_generate_dir_store (dir_store, &dir_iter, &iter);
			}
		}
		while (gtk_tree_model_iter_next (model, &iter) != FALSE);
	}
	return dir_store;
}

void recursive_make_file_list(gchar* current_path, GtkTreeIter* parent)
{
	GError** error = NULL;
	GDir* dir = g_dir_open (current_path, 0, error);
	GtkTreeIter iter;

	if (dir != NULL) {

		const gchar* file_name;

		gchar *action;
		action = (gchar*)malloc(sizeof(gchar));
		action[0]='\0';
		gchar *location;
		location = (gchar*)malloc(sizeof(gchar));
		location[0]='\0';
	
		gchar* tmp;
		tmp = (gchar*)malloc(1000*sizeof(gchar));

		file_name = g_dir_read_name (dir);
		
		while (file_name != NULL){

			gtk_tree_store_append (file_list, &iter, parent);

			gtk_tree_store_set (file_list, &iter, NAME, file_name, ACTION, action, LOCATION, location, -1);

			tmp = strcpy(tmp,current_path);
			tmp = strcat(tmp,"/");
			tmp = strcat(tmp,file_name);

			recursive_make_file_list (tmp, &iter);
			file_name = g_dir_read_name (dir);
		}
		g_dir_close (dir);
	}
}

void make_file_list_from_scratch()
{
	root_path = (gchar*)malloc(1000*sizeof(gchar));
	gchar* tmp;
	tmp = g_get_current_dir ();

	root_path = strcpy(root_path,tmp);
	g_free(tmp);
	root_path = strcat(root_path,"/");
	root_path = strcat(root_path,name);

//	g_print("Making file list from : %s\n",root_path);

	GError** error = NULL;
	GDir* dir = g_dir_open (root_path, 0, error);

	GtkTreeIter iter;

	file_list = gtk_tree_store_new (NUM_COLS, GDK_TYPE_PIXBUF, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	if (dir != NULL) {

		const gchar* file_name;

		gchar *action;
		action = (gchar*)malloc(sizeof(gchar));
		action[0]='\0';
		gchar *location;
		location = (gchar*)malloc(sizeof(gchar));
		location[0]='\0';
	
		tmp = (gchar*)malloc(1000*sizeof(gchar));

		file_name = g_dir_read_name (dir);

		while (file_name != NULL){

			gtk_tree_store_append (file_list, &iter, NULL);

			gtk_tree_store_set (file_list, &iter, NAME, file_name, ACTION, action, LOCATION, location, -1);

			tmp = strcpy(tmp,root_path);
			tmp = strcat(tmp,"/");
			tmp = strcat(tmp,file_name);

			recursive_make_file_list (tmp, &iter);
			file_name = g_dir_read_name (dir);
		}
		g_dir_close (dir);
	}
}

void create_view_and_model_dir_view ()
{
	GtkWidget *dir_view = (GtkWidget*)lookup_widget(window1,"dir_view");
	GtkTreeStore *dir_store = generate_dir_view_store();

	GtkCellRenderer     *renderer;

    renderer = gtk_cell_renderer_pixbuf_new();
    gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (dir_view), -1, "", renderer, "pixbuf", ICON, NULL);

  	renderer = gtk_cell_renderer_text_new ();
  	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (dir_view), -1, "Directory", renderer, "text", NAME, NULL);

	gtk_tree_view_set_enable_tree_lines (GTK_TREE_VIEW(dir_view), TRUE);
  	gtk_tree_view_set_model (GTK_TREE_VIEW (dir_view), GTK_TREE_MODEL(dir_store));
}

void create_view_and_model_file_view ()
{
	GtkWidget *file_view = (GtkWidget*)lookup_widget(window1,"file_view");
	GtkTreeStore *file_store = generate_file_view_store();
	GtkCellRenderer     *renderer;

    renderer = gtk_cell_renderer_pixbuf_new();
    gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (file_view), -1, "", renderer, "pixbuf", ICON, NULL);

  	renderer = gtk_cell_renderer_text_new ();
  	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (file_view), -1, "File Name", renderer, "text", NAME, NULL);

  	renderer = gtk_cell_renderer_text_new ();
  	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (file_view), -1, "File Action", renderer, "text", ACTION, NULL);

  	gtk_tree_view_set_model (GTK_TREE_VIEW (file_view), GTK_TREE_MODEL(file_store));
}

