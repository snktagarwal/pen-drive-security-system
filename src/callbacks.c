#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>
#include "callbacks.h"
#include "interface.h"
#include "support.h"
#include "sha1.h"
#include "common.h"
#include "encrypt.h"

enum
{
  ICON = 0,
  NAME,
  ACTION,
  LOCATION,
  NUM_COLS
} ;

void
on_add_file_to_device_activate         (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	gtk_widget_show(create_filechooserdialog_file());
}


void
on_add_folder_to_device_activate       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	gtk_widget_show(create_filechooserdialog_dir());
}


void
on_extract_to_local_machine_activate   (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	gtk_widget_show(create_filechooserdialog_extract());
}

void
on_toolbutton6_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	gtk_widget_show(create_change_pass());
}

void
on_delete_from_device_activate         (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_quit_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_apply_changes_activate              (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_change_password_activate            (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	gtk_widget_show(create_change_pass());
}


void
on_usage_instructions_activate         (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_about_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_device_properties_activate          (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


//Add File Button Clicked..
void
on_toolbutton1_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
   gtk_widget_show(create_filechooserdialog_file());
}


//Add Directory Button Clicked..
void
on_toolbutton2_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	gtk_widget_show(create_filechooserdialog_dir());
}

//Extract Button Clicked..
void
on_toolbutton3_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	gtk_widget_show(create_filechooserdialog_extract());
}

//CLOSE button of add file dialog..
void
on_button3_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkFileChooserDialog *dialog=GTK_FILE_CHOOSER_DIALOG(button);
	gtk_widget_destroy(GTK_WIDGET(dialog));
	
}

//CLOSE button of add folder dialog..
void
on_button5_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkFileChooserDialog *dialog=GTK_FILE_CHOOSER_DIALOG(button);
	gtk_widget_destroy(GTK_WIDGET(dialog));
}

//CLOSE button of extract folder dialog..
void
on_button7_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkFileChooserDialog *dialog=GTK_FILE_CHOOSER_DIALOG(button);
	gtk_widget_destroy(GTK_WIDGET(dialog));
}


void
on_change_pass_cancelbutton_clicked    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *change_pass = GTK_WIDGET(button);
	gtk_widget_destroy(GTK_WIDGET(change_pass));
}

void
on_toolbar_add_user_clicked            (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	gtk_widget_show(GTK_WIDGET(create_add_user()));
}


void
on_cancelbutton1_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_widget_destroy(GTK_WIDGET(button));
}

void
on_dir_view_cursor_changed             (GtkTreeView     *treeview,
                                        gpointer         user_data)
{
	refresh_file_view();
}

//Password Button OK...
void
on_okbutton1_clicked                   (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *pass_dialog=GTK_WIDGET(button);
	
	GtkEntry *upass=GTK_ENTRY(lookup_widget(pass_dialog,"entry1"));
	GtkEntry *uname=GTK_ENTRY(lookup_widget(pass_dialog,"entry5"));
	
	GtkLabel *label=GTK_LABEL(lookup_widget(pass_dialog,"pass_status"));	
	
	gchar *name=(gchar *)gtk_entry_get_text(uname);
	gchar *passwd=(gchar *)gtk_entry_get_text(upass);
	
	if(compare_sha(passwd,name))
	{
		gtk_widget_hide(GTK_WIDGET(pass_dialog));
	
		//top level window..
		create_top_level();
		pbar = GTK_PROGRESS_BAR((GtkWidget*)lookup_widget(window1,"progressbar"));

		/*enable or disable the add user button based on Admin*/
		GtkWidget *add_user=lookup_widget(window1,"toolbar_add_user");
		if(!strcmp("admin",name)) gtk_widget_show(add_user);

		set_uname(name); set_upass(passwd);		

		//making filelist..
		make_file_list_from_scratch();
		GError *error = NULL;
		dir_icon = gdk_pixbuf_new_from_file("dir.png", &error);
		error = NULL;
		file_icon = gdk_pixbuf_new_from_file("file.png", &error);

		create_view_and_model_dir_view ();
		create_view_and_model_file_view ();

		gtk_widget_show_all(window1);
	}

	else
		gtk_label_set_text(label,"Incorrect Pass");
		
}


//Add File Button is Pressed and OK....
void
on_button4_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_widget_hide(GTK_WIDGET(button));
	gchar *file_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(button));
	gchar *file_name;

	file_name = file_path + strlen(file_path);
	while(*(file_name-1) != '/') file_name--;

	GtkTreeIter iter;

	gtk_tree_store_append (file_list, &iter, global_parent);
	gtk_tree_store_set (file_list, &iter, ICON, file_icon, NAME, file_name, ACTION, "To be Added", LOCATION, file_path, -1);

	refresh_dir_view();
	refresh_file_view();
	gtk_widget_show(GTK_WIDGET(window1));
}


//Add Folder Button Pressed and OK.....
void
on_button6_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_widget_hide(GTK_WIDGET(button));
	gchar* file_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(button));
	gchar* file_name;

	file_name = file_path + strlen(file_path);
	while(*(file_name-1) != '/') file_name--;

	GtkTreeIter iter;
	gtk_tree_store_append (file_list, &iter, global_parent);
	gtk_tree_store_set (file_list, &iter, ICON, dir_icon, NAME, file_name, ACTION, "To be Added", LOCATION, file_path, -1);

	to_be_added_files(&iter, file_path);

	refresh_file_view();
	refresh_dir_view();
	gtk_widget_show(GTK_WIDGET(window1));
}


// Delete Button is Pressed...
void
on_toolbutton4_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	GtkTreeView *file_view = GTK_TREE_VIEW((GtkWidget*)lookup_widget(window1,"file_view"));
	GtkTreeSelection *select = gtk_tree_view_get_selection (file_view);
	GtkTreeModel **model;
	GtkTreeIter selected;
	GtkTreeModel *file_model = gtk_tree_view_get_model(file_view);

	if (gtk_tree_selection_get_selected(select, model, &selected) == TRUE) {

		gchar* str;
		gtk_tree_model_get (file_model, &selected, NAME, &str, -1);

		GtkTreeIter iter;
		gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &iter, global_parent);

		do {
			gchar* string;
			gtk_tree_model_get (GTK_TREE_MODEL(file_list), &iter, NAME, &string, -1);

			if(strcmp(string,str) == 0) {
				gtk_tree_store_set (file_list, &iter, ACTION, "To be Deleted", -1);

				GtkTreeIter subdir;
				if (gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &subdir, &iter) != FALSE)
					to_be_deleted_files(&iter);
			}
		}
		while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &iter) != FALSE);
	}
	refresh_file_view();
	gtk_widget_show(GTK_WIDGET(window1));
}


//Extract To button clicked and Ok..
void
on_button8_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_widget_hide(GTK_WIDGET(button));
	gchar *location = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(button));

	GtkTreeView *file_view = GTK_TREE_VIEW((GtkWidget*)lookup_widget(window1,"file_view"));
	GtkTreeSelection *select = gtk_tree_view_get_selection (file_view);
	GtkTreeModel **model;
	GtkTreeIter selected;
	GtkTreeModel *file_model = gtk_tree_view_get_model(file_view);

	if (gtk_tree_selection_get_selected(select, model, &selected) == TRUE) {

		gchar* str;
		gtk_tree_model_get (file_model, &selected, NAME, &str, -1);

		GtkTreeIter iter;
		gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &iter, global_parent);

		do {
			gchar* string;
			gtk_tree_model_get (GTK_TREE_MODEL(file_list), &iter, NAME, &string, -1);

			if(strcmp(string,str) == 0) {
				gtk_tree_store_set (file_list, &iter, ACTION, "To be Extracted", LOCATION, location, -1);
				g_print("Location :%s, %s\n",string, location);
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
		}
		while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &iter) != FALSE);
	}
	refresh_file_view();	
	gtk_widget_show(GTK_WIDGET(window1));
}

//Apply Changes Button Pressed..
void
on_toolbutton5_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	gchar *file_name;
	gchar *action;
	gchar *location;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL (file_list);

    if (gtk_tree_model_get_iter_first (model, &iter) != FALSE) {

		gtk_progress_bar_set_fraction (pbar, 0.0);
		gtk_progress_bar_set_pulse_step(pbar,0.1);

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

	gtk_progress_bar_set_fraction (pbar, 1.0);
	make_file_list_from_scratch();
	refresh_dir_view();
	refresh_file_view();
	gtk_widget_show(GTK_WIDGET(window1));
}

void
on_add_user_ok_clicked                 (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkEntry *uname=GTK_ENTRY(lookup_widget(GTK_WIDGET(button),"add_user_name"));
	GtkEntry *pass=GTK_ENTRY(lookup_widget(GTK_WIDGET(button),"add_user_pass"));
	GtkEntry *conf_pass=GTK_ENTRY(lookup_widget(GTK_WIDGET(button),"add_user_conf_pass"));
	GtkLabel *info=GTK_LABEL(lookup_widget(GTK_WIDGET(button),"add_user_label"));
	
	gchar *g_uname=(gchar *)gtk_entry_get_text(uname);
	gchar *g_pass=(gchar *)gtk_entry_get_text(pass);
	gchar *g_conf_pass=(gchar *)gtk_entry_get_text(conf_pass);
	
	if(strcmp(g_pass,g_conf_pass)) gtk_label_set_text(GTK_LABEL(info),"Passwords Mismatch");
	else if(!strcmp(g_pass,"")) gtk_label_set_text(GTK_LABEL(info),"Empty Pass! Not allowed");
	else { 
		int i;

		gtk_label_set_text(GTK_LABEL(info),"");
		//check for duplicate username
		//put the uname and passwords in users.pass

		if(does_exist(g_uname) ) {
			gtk_label_set_text(GTK_LABEL(info),"Username exists");
			return;
		}
		
			
		FILE *fp;
		fp = fopen("users.pass","a");
			
		//printf("new username : %s\n",g_uname);
		//printf("new password : %s\n",g_pass);
			
		unsigned char sha[21];
		getSHA(g_pass,strlen(g_pass),sha);
		
		fprintf(fp,"%s:",g_uname);
		for(i=0;i<19;i++)
			fprintf(fp,"%2X ",(sha[i]));
		fprintf(fp,"%2X\n",(sha[i]));		
 		fclose(fp);
		
		g_mkdir (g_uname, 0777);
		gtk_widget_destroy(GTK_WIDGET(button));		
	}
}

//Change Pass Ok clicked...
void
on_okbutton2_clicked                   (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkEntry *current_pass = GTK_ENTRY(lookup_widget(GTK_WIDGET(button),"entry2"));
	GtkEntry *new_pass1 = GTK_ENTRY(lookup_widget(GTK_WIDGET(button),"entry3"));
	GtkEntry *new_pass2 = GTK_ENTRY(lookup_widget(GTK_WIDGET(button),"entry4"));

	gchar *c_pass = (gchar*)gtk_entry_get_text(current_pass);
	gchar *pass1 = (gchar*)gtk_entry_get_text(new_pass1);
	gchar *pass2 = (gchar*)gtk_entry_get_text(new_pass2);

	if (strcmp(c_pass, pass) == 0 && strcmp(pass1, pass2) == 0 && strcmp(pass1, "") != 0){

		gtk_widget_destroy(GTK_WIDGET(button));

		GtkTreeIter iter;
		GtkTreeModel *model = GTK_TREE_MODEL (file_list);

	    if (gtk_tree_model_get_iter_first (model, &iter) != FALSE) {
			do {
				gchar* path = (gchar*)get_address_of_selection(model, &iter);
				gchar* tmp;
				tmp = (gchar*)malloc(1000*sizeof(gchar));
				tmp = strcpy(tmp,root_path);
				tmp = strcat(tmp,"/");
				tmp = strcat(tmp,path);

				GtkTreeIter subdir;
				if (gtk_tree_model_iter_children (model, &subdir, &iter) == FALSE) {
					change(tmp, c_pass, pass1);
				}
				else
					recursive_pass_change(&iter,c_pass, pass1);
			}
			while (gtk_tree_model_iter_next (model, &iter) != FALSE);
		}

	change_password(name,pass1);	
	}
	make_file_list_from_scratch();
	refresh_dir_view();
	refresh_file_view();
	gtk_widget_show(GTK_WIDGET(window1));
}


void
on_clear_toolButton_clicked            (GtkToolButton   *toolbutton,
                                        gpointer         user_data)
{
	GtkTreeView *file_view = GTK_TREE_VIEW((GtkWidget*)lookup_widget(window1,"file_view"));
	GtkTreeSelection *select = gtk_tree_view_get_selection (file_view);
	GtkTreeModel **model;
	GtkTreeIter selected;
	GtkTreeModel *file_model = gtk_tree_view_get_model(file_view);

	if (gtk_tree_selection_get_selected(select, model, &selected) == TRUE) {

		gchar* str;
		gtk_tree_model_get (file_model, &selected, NAME, &str, -1);

		GtkTreeIter iter;
		gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &iter, global_parent);

		do {
			gchar* string;
			gtk_tree_model_get (GTK_TREE_MODEL(file_list), &iter, NAME, &string, -1);

			if(strcmp(string,str) == 0) {
				gtk_tree_store_set (file_list, &iter, ACTION, "", LOCATION, "", -1);

				GtkTreeIter subdir;
				if (gtk_tree_model_iter_children (GTK_TREE_MODEL(file_list), &subdir, &iter) != FALSE)
					recursive_clear(&iter);
			}
		}
		while (gtk_tree_model_iter_next (GTK_TREE_MODEL(file_list), &iter) != FALSE);
	}
	refresh_file_view();	
	gtk_widget_show(GTK_WIDGET(window1));
}

