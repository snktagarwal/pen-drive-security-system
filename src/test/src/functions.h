#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "interface.h"
#include "support.h"
#include "sha1.h"
#include "aes.h"
#include "encrypt.h"

void recursive_pass_change(GtkTreeIter* parent, gchar* c_pass, gchar* pass1);

void recursive_add(GtkTreeIter* parent);

void recursive_extract(GtkTreeIter* parent, gchar* location);

void recursive_delete(GtkTreeIter* parent);

void recursive_apply_changes(GtkTreeIter* parent);

void refresh_dir_view();

void refresh_file_view();

void to_be_deleted_files(GtkTreeIter* parent);

void to_be_extracted_files(GtkTreeIter* parent, gchar* location);

void to_be_added_files(GtkTreeIter* parent, gchar* path);

void move_to_parent_dir(GtkTreeIter *parent, gchar* path);

void find_parent_dir();

gchar* get_address_of_selection(GtkTreeModel *model, GtkTreeIter *iter);

GtkTreeStore* generate_file_view_store();

void recursive_generate_dir_store (GtkTreeStore *dir_store, GtkTreeIter *parent, GtkTreeIter *dir);

GtkTreeStore* generate_dir_view_store();

void recursive_make_file_list(gchar* current_path, GtkTreeIter* parent);

void make_file_list_from_scratch();

void create_view_and_model_dir_view ();

void create_view_and_model_file_view ();

