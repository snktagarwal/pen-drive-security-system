#include <gtk/gtk.h>
#include "aes.h"
#include "encrypt.h"

void
on_add_file_to_device_activate         (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_add_folder_to_device_activate       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_extract_to_local_machine_activate   (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_delete_from_device_activate         (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_quit_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_apply_changes_activate              (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_change_password_activate            (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_usage_instructions_activate         (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_about_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_device_properties_activate          (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_button3_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_toolbutton1_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_toolbutton2_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_toolbutton3_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_button5_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_button7_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_change_pass_cancelbutton_clicked    (GtkButton       *button,
                                        gpointer         user_data);

void
on_toolbutton6_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_okbutton1_clicked                   (GtkButton       *button,
                                        gpointer         user_data);
gboolean compare_sha1_hash(gchar *username,gchar *passwd);



void
on_button4_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_button6_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_toolbutton4_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_toolbutton5_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_button8_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_add_user_ok_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_toolbar_add_user_clicked            (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_cancelbutton1_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_toolbutton5_clicked                 (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_button8_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_dir_view_cursor_changed             (GtkTreeView     *treeview,
                                        gpointer         user_data);

void
on_okbutton2_clicked                   (GtkButton       *button,
                                        gpointer         user_data);

void
on_clear_toolButton_clicked            (GtkToolButton   *toolbutton,
                                        gpointer         user_data);
