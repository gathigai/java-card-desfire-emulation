package des.Android.engine;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;


import exceptions.InvalidResponse;
import exceptions.NoCardConnected;

import utils.Utils;
import android.smartcard.CardException;
import android.smartcard.ICardChannel;
import android.smartcard.SmartcardClient;
import android.util.Log;

public class DESEngine {
	
	public static ICardChannel cardChannel;
	public byte[] AID=Utils.hexStringToByteArray("01 02 03 04 05 06 07 08 09 00 00");
	/**
	 * Key to read
	 */
	byte[] key1=Utils.hexStringToByteArray("01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 01");
	byte[] key2=Utils.hexStringToByteArray("01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 02");
//	private static final byte[] APPLET_AID = new byte[] {(byte)0xD2,(byte)0x76,(byte)0x00,(byte)0x01,(byte)0x18,(byte)0x00,(byte)0x02,(byte)0xFF,(byte)0x49,(byte)0x50,(byte)0x25,(byte)0x89,(byte)0xC0,(byte)0x01,(byte)0x9B,(byte)0x01};
	DESfireApi card;
	
	int tempCredit;
	String id="12345678";
	
//	public DESEngine(){
//		 
//	}
	
	private static String url = "http://192.168.1.103:8080/CreditServer/creditServlet";
    public void executeHttpGet() throws Exception {
    	Log.e("executeHttpGet","hola");
 	   // Create an instance of HttpClient.
	    HttpClient client = new HttpClient();

	    // Create a method instance.
	    GetMethod method = new GetMethod(url);
	    method.addRequestHeader("command", "addCredit");
//	    method.addRequestHeader("value", "addCredit");
	    
	    // Provide custom retry handler is necessary
	    method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, 
	    		new DefaultHttpMethodRetryHandler(3, false));

	    try {
	      // Execute the method.
	      int statusCode = client.executeMethod(method);
	      Log.e("statusCode",String.valueOf(statusCode));

	      if (statusCode != HttpStatus.SC_OK) {
	        Log.e("fallo","Method failed: " + method.getStatusLine());
	      }

	      // Read the response body.
	      byte[] responseBody = method.getResponseBody();
	      Log.e("servlet",method.getResponseHeader("response").getValue());

	      // Deal with the response.
	      // Use caution: ensure correct character encoding and is not binary data
	      System.out.println(new String(responseBody));

	    } catch (HttpException e) {
	      System.err.println("Fatal protocol violation: " + e.getMessage());
	      e.printStackTrace();
	    } catch (IOException e) {
	      System.err.println("Fatal transport error: " + e.getMessage());
	      e.printStackTrace();
	    } finally {
	      // Release the connection.
	      method.releaseConnection();
	    }
    }
	public void connect(SmartcardClient smartcard) {
		Log.e("debug","Engine");
		String cardReader = "";	
		try {
			Log.e("debug","Length of readers: "+ smartcard.getReaders().length );
			cardReader = smartcard.getReaders()[0];
			Log.e("debug",cardReader);
			cardChannel = smartcard.openLogicalChannel(cardReader, AID);
			Log.e("debug","Tras openLC");
		} catch (CardException e) {
			Log.e("debug", "Exception in opening basic channel: " + e.getMessage());
		}
		card=new DESfireApi(cardChannel);
			
	}
	public void nada(){
		Log.e("debug","Engine");
	}
	public String startApplication(){
		
		try {
			Log.e("debug","Engine");
			 cardChannel.transmit(Utils.hexStringToByteArray("90 CA 00 00 05 11 11 11 10 10 00"));
			cardChannel.transmit(Utils.hexStringToByteArray("90 CC 00 00 11 08 11 EE EE 22 00 00 00 FF 0F 00 00 40 00 00 00 01 00"));
			byte[] rspApdu =cardChannel.transmit(Utils.hexStringToByteArray("90 6C 00 00 01 08 00"));//Get Value 0100
			Log.e("debug","Respuesta: "+Utils.hexDumpSpaces(rspApdu));
			return Utils.hexDumpSpaces(rspApdu);
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}//Crea DF
		return null;
	}
	
	public void selectEntity(int entityNumber){
		String[] AIDs = null;
		if(card!=null){
			try {
				card.selectApplication("000000");
				AIDs = card.getApplicationIDs();
				card.selectApplication(AIDs[entityNumber]);
				card.authenticate((byte)2,key2);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidResponse e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoCardConnected e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CardException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public  String[] getEntities() {
		String[] AIDs = null;
		
		try {
			if(card!=null){
				card.selectApplication("000000");
				AIDs = card.getApplicationIDs();
				String[] entities=new String[AIDs.length]; 
				for (int i = 0; i < AIDs.length; i++) {
					Log.e("debug","Obtengo el AID "+AIDs[i]);
					card.selectApplication(AIDs[i]);
					card.authenticate((byte)1,key1);
					entities[i]=new String(card.readData((byte)1));
					Log.e("getEntities", entities[i]);
				}
				
				return entities;
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (exceptions.InvalidResponse e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (exceptions.NoCardConnected e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	}
	public void setTempCredit(int value){
		tempCredit=value;
	}
	public int getTempCredit(){
		return tempCredit;
	}
	public  int[] getBalances() {
		String[] AIDs = null;
		
		try {
			if(card!=null){
				card.selectApplication("000000");
				AIDs = card.getApplicationIDs();
				int[] balances=new int[AIDs.length]; 
				for (int i = 0; i < AIDs.length; i++) {
					Log.e("debug","Obtengo el AID "+AIDs[i]);
					card.selectApplication(AIDs[i]);
					card.authenticate((byte)1,key1);
					balances[i]=Utils.byteArrayToInt((card.getValue((byte)2)));
					Log.e("getEntities",  String.valueOf(balances[i]));
				}
				
				return balances;
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (exceptions.InvalidResponse e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (exceptions.NoCardConnected e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	}
	public void addCredit(){
		tempCredit++;
		return;
//		try {
//			card.addCredit(fileN);
//		} catch (InvalidKeyException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IllegalBlockSizeException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (BadPaddingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (InvalidResponse e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (NoCardConnected e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (CardException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}
	public void commit(byte fileN) {
		
//			Log.e("executeHttpGet","hola");
//	 	   // Create an instance of HttpClient.
//		    HttpClient client = new HttpClient();
//
//		    // Create a method instance.
//		    GetMethod method = new GetMethod(url);
//		    method.addRequestHeader("command", "addCredit");
//		    method.addRequestHeader("identity",id);
//		    method.addRequestHeader("value", String.valueOf(tempCredit));
//		    
//		    // Provide custom retry handler is necessary
//		    method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, 
//		    		new DefaultHttpMethodRetryHandler(3, false));
//
//		    try {
//		      // Execute the method.
//		      int statusCode = client.executeMethod(method);
//		      Log.e("statusCode",String.valueOf(statusCode));
//
//		      if (statusCode != HttpStatus.SC_OK) {
//		        Log.e("fallo","Method failed: " + method.getStatusLine());
//		      }
//
//		      // Read the response body.
//		      byte[] responseBody = method.getResponseBody();
//		      Log.e("servlet",method.getResponseHeader("response").getValue());
//
//		      // Deal with the response.
//		      // Use caution: ensure correct character encoding and is not binary data
//		      System.out.println(new String(responseBody));
//
//		    } catch (HttpException e) {
//		      System.err.println("Fatal protocol violation: " + e.getMessage());
//		      e.printStackTrace();
//		    } catch (IOException e) {
//		      System.err.println("Fatal transport error: " + e.getMessage());
//		      e.printStackTrace();
//		    } finally {
//		      // Release the connection.
//		      method.releaseConnection();
//		    }
		try {
			
			card.addCredit(fileN,(byte) tempCredit);
			card.commit(fileN);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidResponse e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoCardConnected e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CardException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
//	public final static String hexChars[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F" };
//	public static String hexDumpSpaces(byte[] data, int offset, int length) {
//		String result = "";
//		String part = "";
//		for (int i = 0; i < min(data.length, length); i++) {
//			
//			part = "" + hexChars[(byte) (unsignedInt(data[offset + i]) / 16)] + hexChars[(byte) (unsignedInt(data[offset + i]) % 16)];
//			result = result + part;
//			result=result+" ";
//		}
//		return result;
//	}
//	public static String hexDumpSpaces(byte[] data) {
//		return hexDumpSpaces(data, 0, data.length);
//	}
//	public static byte[] hexStringToByteArray(String s) {
//		int len = s.length();
//		byte[] data = new byte[(len+1) / 3];
//		for (int i = 0; i < len; i += 3) {
//			data[i / 3] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
//		}
//		return data;
//	}
//	private static String bytesToString(byte[] bytes) {
//		StringBuffer sb = new StringBuffer();
//		for (byte b : bytes) {
//			sb.append(String.format("%02x ", b & 0xFF));
//		}
//		return sb.toString();
//	}
//	public static int unsignedInt(int a) {
//		if (a < 0) {
//			return a + 256;
//		}
//		return a;
//	}
//	public static int min(int a, int b) {
//		if (a < b) {
//			return a;
//		}
//		return b;
//	}
}











