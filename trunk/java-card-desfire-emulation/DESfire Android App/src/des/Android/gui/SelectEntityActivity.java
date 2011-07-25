package des.Android.gui;


import utils.Utils;
import android.app.ListActivity;
import android.content.Intent;
import android.util.Log;
import android.view.View;
import android.widget.*;
import android.widget.AdapterView.OnItemClickListener;
import android.os.Bundle;
import des.Android.R;


public class SelectEntityActivity extends ListActivity{

	@Override
	public void onCreate(Bundle savedInstanceState) {
	  super.onCreate(savedInstanceState);
	  
	  
	  
	  setListAdapter(new ArrayAdapter<String>(this, R.layout.item_list, getIntent().getStringArrayExtra("entities")));

	  ListView lv = getListView();
	  lv.setTextFilterEnabled(true);
	  

	  lv.setOnItemClickListener(new OnItemClickListener() {
	    public void onItemClick(AdapterView<?> parent, View view,int position, long id) {
	      // When clicked, show a toast with the TextView text
	    	Log.e("LIST","POSITION: "+position);
	    	Log.e("LIST","Get extra int: "+ getIntent().getIntArrayExtra("balances")[position]);
	    	Toast.makeText(getApplicationContext(), String.valueOf(getIntent().getIntArrayExtra("balances")[position]), Toast.LENGTH_SHORT).show();
	    	setResult(position);
	    	finish();
	    }
	  });
	}
}
