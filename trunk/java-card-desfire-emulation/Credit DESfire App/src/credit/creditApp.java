package credit;

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
import javax.smartcardio.CardException;

import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;





import be.fedict.eidtoolset.exceptions.AIDNotFound;
import be.fedict.eidtoolset.exceptions.InvalidResponse;
import be.fedict.eidtoolset.exceptions.NoCardConnected;
import be.fedict.eidtoolset.exceptions.NoReadersAvailable;

public class creditApp {
	
	/**
	 * -Gets by command line a "entity" with a AID and a credit.
	 * -Creates an application in the DESfire Card with the AID and 2 keys.
	 * -The application has a StdFile with the name of the "entity" (i.e. Carrefour,Alma...).
	 * -The application has a ValueFile with the current credit.
	 * -The access to the files is secure with 	Key1: Read
	 * 											Key2: W/R
	 * @throws NoCardConnected 
	 * @throws AIDNotFound 
	 * @throws CardException 
	 * @throws NoReadersAvailable 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidResponse 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchProviderException 
	 * @throws InvalidKeyException 
	 * 										
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, NoReadersAvailable, CardException, AIDNotFound, NoCardConnected, InvalidResponse, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		
//		String entityName=args[0];
//		String AID=args[1];
//		String credit=args[2];
//		byte[] masterKey=Utils.hexStringToByteArray("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
//		byte[] key1=Utils.hexStringToByteArray("01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 01");
//		byte[] key2=Utils.hexStringToByteArray("01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 02");
//		DESfireApi card=new DESfireApi();
//		card.createApplication(AID,(byte)3);
//		card.selectApplication(AID);
//		card.getApplicationIDs();
//		card.authenticate((byte) 0, masterKey);
//		card.changeKey((byte)1,key1,masterKey);
//		
//		card.changeKey((byte)2,key2,masterKey);
//		card.createStdDataFile((byte)1,(byte)0x01,(byte)0x0F,(byte)0x02,(byte)0x0F,(short)0x0F00);
//		card.authenticate((byte)2, key2);
//		card.writeData((byte)1,entityName);
//		card.readData((byte)1);
//		card.createValueFile((byte)2,(byte)0x01,(byte)0x0F,(byte)0x02,(byte)0x0F,40);
//		card.getValue((byte)2);
//		card.addCredit((byte)2);
//		card.commit((byte)2);
//		card.getValue((byte)2);
//		
//		card.selectApplication("000000");
		try {
			executeHttpGet();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private static String url = "http://localhost:8080/CreditServer/creditServlet";
	
	public static void executeHttpGet() throws Exception {
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

	      if (statusCode != HttpStatus.SC_OK) {
	        System.err.println("Method failed: " + method.getStatusLine());
	      }

	      // Read the response body.
	      byte[] responseBody = method.getResponseBody();
	      System.out.println(responseBody);
	      System.out.println(method.getResponseHeader("response"));

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
}
