package net.sourceforge.opencamera.UI;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.text.InputFilter;
import android.text.Spanned;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import net.sourceforge.opencamera.MyDebug;
import net.sourceforge.opencamera.PreferenceKeys;
import net.sourceforge.opencamera.R;
import net.sourceforge.opencamera.StorageUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Dialog to pick a folder. Also allows creating new folders. Used when not
 *  using the Storage Access Framework.
 */
public class FileChooserDialog extends DialogFragment {
	private static final String TAG = "FileChooserFragment";

	private File current_folder;
	private AlertDialog folder_dialog;
	private ListView list;
	private String chosen_file;

	private static class FileWrapper implements Comparable<FileWrapper> {
		private final File file;
		private final String override_name; // if non-null, use this as the display name instead
		private final int sort_order; // items are sorted first by sort_order, then alphabetically
		
		FileWrapper(File file, String override_name, int sort_order) {
			this.file = file;
			this.override_name = override_name;
			this.sort_order = sort_order;
		}
		
		@Override
		public String toString() {
			if( override_name != null )
				return override_name;
			return file.getName();
		}
		
		@Override
        public int compareTo(@NonNull FileWrapper o) {
			if( this.sort_order < o.sort_order )
				return -1;
			else if( this.sort_order > o.sort_order )
				return 1;
	        return this.file.getName().toLowerCase(Locale.US).compareTo(o.getFile().getName().toLowerCase(Locale.US));
        }
        
        @Override
        public boolean equals(Object o) {
        	// important to override equals(), since we're overriding compareTo()
			if( !(o instanceof FileWrapper) )
				return false;
			FileWrapper that = (FileWrapper)o;
			if( this.sort_order != that.sort_order )
				return false;
	        return this.file.getName().toLowerCase(Locale.US).equals(that.getFile().getName().toLowerCase(Locale.US));
        }

		@Override
		public int hashCode() {
			// must override this, as we override equals()
			return this.file.getName().toLowerCase(Locale.US).hashCode();
		}

		File getFile() {
			return file;
		}
	}

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
		if( MyDebug.LOG )
			Log.d(TAG, "onCreateDialog");
		SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this.getActivity());
		String folder_name = sharedPreferences.getString(PreferenceKeys.getSaveLocationPreferenceKey(), "OpenCamera");
		if( MyDebug.LOG )
			Log.d(TAG, "folder_name: " + folder_name);
		File new_folder = StorageUtils.getImageFolder(folder_name);
		if( MyDebug.LOG )
			Log.d(TAG, "start in folder: " + new_folder);

		list = new ListView(getActivity());
		list.setOnItemClickListener(new OnItemClickListener() {
			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				if( MyDebug.LOG )
					Log.d(TAG, "onItemClick: " + position);
				FileWrapper file_wrapper = (FileWrapper) parent.getItemAtPosition(position);
				if( MyDebug.LOG )
					Log.d(TAG, "clicked: " + file_wrapper.toString());
				File file = file_wrapper.getFile();
				if( MyDebug.LOG )
					Log.d(TAG, "file: " + file.toString());
				if (file.isDirectory()) {
					refreshList(file);
				} else {
					chosen_file = file.getAbsolutePath();
					folder_dialog.dismiss();
					Toast.makeText(getActivity(), chosen_file, Toast.LENGTH_SHORT).show();
				}
			}
		});
		// good to use as short a text as possible for the icons, to reduce chance that the three buttons will have to appear on top of each other rather than in a row, in portrait mode
		folder_dialog = new AlertDialog.Builder(getActivity())
	        //.setIcon(R.drawable.alert_dialog_icon)
	        .setView(list)
	        //.setPositiveButton(android.R.string.ok, null) // we set the listener in onShowListener, so we can prevent the dialog from closing (if chosen folder isn't writable)
			.setNeutralButton(R.string.new_folder, null) // we set the listener in onShowListener, so we can prevent the dialog from closing
	        .setNegativeButton(android.R.string.cancel, null)
	        .create();
		folder_dialog.setOnShowListener(new DialogInterface.OnShowListener() {
		    @Override
		    public void onShow(DialogInterface dialog_interface) {
		        Button b_neutral = folder_dialog.getButton(AlertDialog.BUTTON_NEUTRAL);
		        b_neutral.setOnClickListener(new View.OnClickListener() {
		            @Override
		            public void onClick(View view) {
	    				if( MyDebug.LOG )
	    					Log.d(TAG, "new folder in: " + current_folder.toString());
	    				newFolder();
		            }
		        });
		    }
		});

		if( !new_folder.exists() ) {
			if( MyDebug.LOG )
				Log.d(TAG, "create new folder" + new_folder);
			if( !new_folder.mkdirs() ) {
				if( MyDebug.LOG )
					Log.d(TAG, "failed to create new folder");
				// don't do anything yet, this is handled below
			}
		}
		refreshList(new_folder);
        return folder_dialog;
    }
    
    private void refreshList(File new_folder) {
		if( MyDebug.LOG )
			Log.d(TAG, "refreshList: " + new_folder);
    	if( new_folder == null ) {
    		if( MyDebug.LOG )
    			Log.d(TAG, "refreshList: null folder");
    		return;
    	}
		File [] files = null;
		// try/catch just in case?
		try {
			files = new_folder.listFiles();
		}
		catch(Exception e) {
    		if( MyDebug.LOG )
    			Log.d(TAG, "exception reading folder");
			e.printStackTrace();
		}
		// n.b., files may be null if no files could be found in the folder (or we can't read) - but should still allow the user
		// to view this folder (so the user can go to parent folders which might be readable again)
		List<FileWrapper> listed_files = new ArrayList<>();
		if( new_folder.getParentFile() != null )
			listed_files.add(new FileWrapper(new_folder.getParentFile(), getResources().getString(R.string.parent_folder), 0));
		File default_folder = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM);
		if( files != null ) {
			for(File file : files) {
				listed_files.add(new FileWrapper(file, null, 1));
			}
		}
		Collections.sort(listed_files);

		ArrayAdapter<FileWrapper> adapter = new ArrayAdapter<>(this.getActivity(), android.R.layout.simple_list_item_1, listed_files);
        list.setAdapter(adapter);

        this.current_folder = new_folder;
        //dialog.setTitle(current_folder.getName());
        folder_dialog.setTitle(current_folder.getAbsolutePath());
    }

	/** Returns the folder selected by the user. Returns null if the dialog was cancelled.
     */
	public String getChosenFile() {
		return this.chosen_file;
	}

    private static class NewFolderInputFilter implements InputFilter {
		// whilst Android seems to allow any characters on internal memory, SD cards are typically formatted with FAT32
		private final static String disallowed = "|\\?*<\":>";
		
		@Override
        public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) { 
            for(int i=start;i<end;i++) { 
            	if( disallowed.indexOf( source.charAt(i) ) != -1 ) {
                    return ""; 
            	}
            }
            return null;
        }
    }
    
	private void newFolder() {
		if( MyDebug.LOG )
			Log.d(TAG, "newFolder");
		if( current_folder == null )
			return;
		if( current_folder.canWrite() ) {
			final EditText edit_text = new EditText(getActivity());  
			edit_text.setSingleLine();
        	InputFilter filter = new NewFolderInputFilter();
        	edit_text.setFilters(new InputFilter[]{filter});         	

			Dialog dialog = new AlertDialog.Builder(getActivity())
		        //.setIcon(R.drawable.alert_dialog_icon)
				.setTitle(R.string.enter_new_folder)
		        .setView(edit_text)
		        .setPositiveButton(android.R.string.ok, new Dialog.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						if( edit_text.getText().length() == 0 ) {
							// do nothing
						}
						else {
							try {
								String new_folder_name = current_folder.getAbsolutePath() + File.separator + edit_text.getText().toString();
								if( MyDebug.LOG )
									Log.d(TAG, "create new folder: " + new_folder_name);
								File new_folder = new File(new_folder_name);
								if( new_folder.exists() ) {
									if( MyDebug.LOG )
										Log.d(TAG, "folder already exists");
									Toast.makeText(getActivity(), R.string.folder_exists, Toast.LENGTH_SHORT).show();
								}
								else if( new_folder.mkdirs() ) {
									if( MyDebug.LOG )
										Log.d(TAG, "created new folder");
							    	refreshList(current_folder);
								}
								else {
									if( MyDebug.LOG )
										Log.d(TAG, "failed to create new folder");
									Toast.makeText(getActivity(), R.string.failed_create_folder, Toast.LENGTH_SHORT).show();
								}
							}
							catch(Exception e) {
								if( MyDebug.LOG )
									Log.d(TAG, "exception trying to create new folder");
								e.printStackTrace();
								Toast.makeText(getActivity(), R.string.failed_create_folder, Toast.LENGTH_SHORT).show();
							}
						}
					}
		        })
		        .setNegativeButton(android.R.string.cancel, null)
		        .create();
			dialog.show();
		}
		else {
			Toast.makeText(getActivity(), R.string.cant_write_folder, Toast.LENGTH_SHORT).show();
		}
	}


    @Override
    public void onResume() {
    	super.onResume();
    	// refresh in case files have changed
    	refreshList(current_folder);
    }
    
    // for testing:

    public File getCurrentFolder() {
    	return current_folder;
    }
}