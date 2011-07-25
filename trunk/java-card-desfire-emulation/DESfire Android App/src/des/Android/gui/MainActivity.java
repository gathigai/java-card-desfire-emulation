package des.Android.gui;

import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import utils.Utils;

import des.Android.engine.DESEngine;
import des.Android.*;
import android.app.Activity;
import android.os.Bundle;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.smartcard.CardException;
import android.smartcard.ICardChannel;
import android.smartcard.SmartcardClient;
import android.smartcard.SmartcardClient.ISmartcardConnectionListener;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup.LayoutParams;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {

	/** The AID of the HelloSmartcard applet on the smart card. */
	private static final byte[] APPLET_AID = new byte[] { (byte)0xD2,(byte)0x76,(byte)0x00,(byte)0x01,(byte)0x18,(byte)0x00,(byte)0x02,(byte)0xFF,(byte)0x49,(byte)0x50,(byte)0x25,(byte)0x89,(byte)0xC0,(byte)0x01,(byte)0x9B,(byte)0x01};
	public static final String LOG_TAG = "debug";
	/** Smartcard API handle. */
	SmartcardClient smartcard;
	boolean smartCardConnected=false;
	public DESEngine engine;
	Intent intent;  // Reusable Intent for each tab

	/** GUI elements on the screen. */
	TextView textview = null;
	ScrollView scrollview = null;
	Button button = null;
	int entityInUse=-1;

	
	/**
	 * Override onCreate and create the UI elements programmatically.
	 */
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		Log.e("debug", "antes de SetUpView");
		engine=new DESEngine();
		
		setUpView();
		Log.e("debug", "tras SetUpView");
	    try {
	    	connectToService();
	    	Log.e("debug", "Tras el connect");
	    	
	   	} catch (SecurityException e) {
	     	  Log.e(LOG_TAG, "Binding not allowed, uses-permission SMARTCARD?");
	     	  return;         
	   	} catch (Exception e) {
	     	  Log.e(LOG_TAG, "Exception: " + e.getMessage());
	   	}
	   	
	}

	private void setUpView(){
		
		setContentView(R.layout.main);
		intent = new Intent().setClass(this, SelectEntityActivity.class);
		
		final Button balanceButton = (Button) findViewById(R.id.balancesButton);
	    balanceButton.setOnClickListener(new View.OnClickListener() {
	    	public void onClick(View v) {
	    		// Perform action on click
				Log.e("debug", "En onClick");
				intent.putExtra("entities",engine.getEntities());
				intent.putExtra("balances", engine.getBalances());
				MainActivity.this.startActivityForResult(intent, Utils.SET_ENTITY_RESULT);
	        }
	     });
	    
	    final Button addCreditButton = (Button) findViewById(R.id.addCredit);
	    addCreditButton.setOnClickListener(new View.OnClickListener() {
	    	public void onClick(View v) {
	    		Log.e("SetUpView","AddCredit Action");
	    		EditText entry=(EditText)findViewById(R.id.entry);
	    		if(entityInUse>=0){
	    			entry.setText(String.valueOf(Integer.parseInt(entry.getText().toString())+1));
	    			engine.addCredit();
	    		}else{
	    			Log.e("onCLick","Entity not selected");
	    		}
	    	}
	    });
	    
	    final Button commit=(Button)findViewById(R.id.commit);
	    commit.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				Log.e("SetUpView","Commit");
				if(entityInUse>=0){
//					try {
//						engine.executeHttpGet();
//					} catch (Exception e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					}
					engine.commit((byte)2);
				}
			}
		});
	}

	/**
	 * Connection listener object to be called when the
	 * service is successfully connected or disconnected.
	 * After <code>serviceConnected</code> was called,
	 * <code>SmartcardClient</code> object is valid.
	 */
	ISmartcardConnectionListener connectionListener = new ISmartcardConnectionListener() {
		public void serviceConnected() {
			/** Enable the button to allow access to the smart card. */
			Log.e("debug","Smart card service connected\n");
			engine.connect(smartcard); 
			 
			smartCardConnected = true;
		}

		public void serviceDisconnected() {
			/** Disable the button to omit smart card access. */
			Log.e("debug","Smart card service disconnected\n");
			button.setEnabled(false);
			
			/** Paranoia mode on: reconnect if the service was killed. */
			connectToService();
		}
	};
	
	/**
	 * Internal helper method to do the Smartcard Service binding.
	 */
	private void connectToService() {
		Log.e("debug","Connecting to smart card service...\n");
		try {
			smartcard = new SmartcardClient(this, connectionListener);
		} catch (SecurityException e) {
			Log.e("debug","Binding not allowed, uses-permission SMARTCARD?");
		} catch (Exception e) {
			Log.e("debug","Exception: " + e.getMessage());
		}
	}
	@Override
	/**
	 * Override onDestroy to cleanup the service binding
	 */
	protected void onDestroy() {
		if (smartcard != null) {
			Log.e("debug","Disconnecting from smart card service\n");
			smartcard.shutdown();
		}
		super.onDestroy();
	}

	protected void onActivityResult(int requestCode, int resultCode,
            Intent data) {
    	
		Log.e("result","OnActivityResult");
    	
    	switch (requestCode){
    		case Utils.SET_ENTITY_RESULT:
    			EditText entry=(EditText)findViewById(R.id.entry);
    			engine.setTempCredit(0);
    			entry.setText(String.valueOf(intent.getIntArrayExtra("balances")[resultCode]));
    			
    			engine.selectEntity(resultCode);
    			entityInUse=resultCode;
    			break;
    	}
	}	
}
