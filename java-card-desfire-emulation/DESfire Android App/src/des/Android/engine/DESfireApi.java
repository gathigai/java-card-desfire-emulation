package des.Android.engine;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import exceptions.*;

import utils.Utils;

import android.smartcard.CardException;
import android.smartcard.ICardChannel;
import android.util.Log;

public class DESfireApi {

	
	public ICardChannel cardChannel;
    private byte securityLevel;
    private byte authenticated=-1;
    byte[] AID;
    private SecretKey sessionKey;
    private Cipher cipher;
	
	/**
	 * debugLevel = 0: no debug information; 1: minimal debug information
	 * (reader and card information); 2: maximal debug information (apdus)
	 */
	private int debugLevel = 2;
	
	private String cardReader;
		
	public DESfireApi(ICardChannel cardChannel){
		 this.cardChannel=cardChannel;
		 Security.addProvider(new BouncyCastleProvider());
		    this.securityLevel=Utils.PLAIN_COMMUNICATION;
		    try {
				cipher=Cipher.getInstance("DESede/ECB/NoPadding","BC");
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
	
	public void selectApplication(String AID) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		sendCommand(Utils.hexStringToByteArray("90 5A 00 00 03 " +Utils.addSpaces(AID)+" 00"));
		this.securityLevel=Utils.PLAIN_COMMUNICATION;
		this.authenticated=-1;
	}
	
	public String[] getApplicationIDs() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException {
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 6A 00 00 00"));
		Log.e("getApplicationIDs",Utils.hexDumpSpaces(response));
		String[] result = new String[response.length/3];
		if(result.length==0)return null;
		
		for (short i = 0; i < (short)(response.length-2); i=(short)(i+3)) {
			Log.e("debug","response length: "+response.length+" i: "+i);
			result[i/3]=Utils.hexDump(Utils.subByteArray(response, i,(short)(i+2)));
		}		
		Log.e("getApplicaionIDs","AID 1: "+result[0]);
		return result;
	}
	
	/**
	 * Authenticates the key as the key with the keyNumber in the currently selected DF
	 * 
	 * @param keyNumber
	 * @param key
	 * @throws InvalidKeyException
	 * @throws InvalidResponse
	 * @throws NoCardConnected
	 * @throws CardException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
   public void authenticate(byte keyNumber,byte[]key) throws InvalidKeyException, InvalidResponse, NoCardConnected, CardException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
	    byte[] response = null;
	    byte[] response2=new byte[8];
	    byte[] rndA=new byte[8];
	    byte[] rndB=new byte[8];
	    System.out.println("**************************  AUTHENTICATION *****************************\n");
		System.out.println("Autentificamos la clave: "+Utils.hexDumpSpaces(key));
		System.out.flush();
		response = sendCommand(Utils.hexStringToByteArray("90 0A 00 00 01 "+Utils.hexDump(keyNumber)+" 00"));	
	    
	    //Recibimos mensaje
	    System.arraycopy(response, 0, response2, 0, 8);
	    //System.out.println("EKRndB: "+ Utils.hexDumpSpaces(response2));
		     
    	//Desencriptamos
    	
    	SecretKey keySpec = new SecretKeySpec(key, "DESede");
		
		cipher.init(Cipher.DECRYPT_MODE, keySpec);
        //System.out.println("RndB: "+cipherText);
        rndB=cipher.doFinal(response2);
        String cipherText=Utils.hexDumpSpaces(rndB);
        
        
        //Enviamos respuesta encriptada        
        Random random= new Random();
        random.nextBytes(rndA);
        //System.out.println("RANDOM A: "+Utils.hexDumpSpaces(rndA));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        //System.out.println("ASí funciona el rotate: "+cipherText+"PP"+Utils.hexDumpStringRotate(cipherText));
        cipherText=Utils.hexDumpSpaces(cipher.update(rndA))+" "+Utils.hexDumpSpaces(cipher.doFinal(Utils.hexStringToByteArray(Utils.hexDumpStringRotate(cipherText))));
        //System.out.println("90 AF 00 00 "+  Utils.intToHexDumpSpaces(cipherText.length()/3)+cipherText);
        
        //Recibimos el ultimo mensaje
        response=sendCommand(Utils.hexStringToByteArray("90 AF 00 00 10 "+cipherText+" 00"));
        //System.out.println(response + " " + Utils.hexStringToByteArray("91 AE"));
        if(response[1]==Utils.hexStringToByteArray("91 AE")[1]){
        	System.err.println("Authentication Error\n");
        	System.out.flush();
        	return;
        }
        else{
	        System.out.flush();
	        System.err.println("Authentication OK\n");
	        //SessionKey is created
	        byte[] sessionKeyBytes=Utils.create3DESSessionKey(rndA,rndB);
	        System.out.println("SESSION KEY BYTES: "+Utils.hexDumpSpaces(sessionKeyBytes));
	        this.sessionKey=new SecretKeySpec(sessionKeyBytes, "DESede");
	        this.securityLevel=Utils.FULLY_ENCRYPTED;
	        this.authenticated=keyNumber;
	        
	        //Ek(RndA') is checked
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
	        System.arraycopy(response, 0, response2, 0, 8);
	        cipherText=Utils.hexDumpSpaces(cipher.doFinal(response2));
        }
   }
   

	
	public byte[] readData(byte fileN) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 8D 00 00 07 " + Utils.hexDump(fileN)+" 00 00 00 00 00 00 00"));
		Log.e("readData"," Leido: "+ new String(Utils.subByteArray(response,(short) 0, (short)(response.length-3))));
		return Utils.subByteArray(response,(short) 0, (short)(response.length-3));
	}
	
	public byte[] getValue(byte fileN) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException {
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 6C 00 00 01 " + Utils.hexDump(fileN)+" 00"));
		System.out.println("GET VALUE: "+Utils.subByteArray(response,(short) 0, (short)(response.length-3)));
		return Utils.subByteArray(response,(short) 0, (short)(response.length-3));
	}
	
	public void addCredit(byte fileN,byte credit) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException{
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 0C 00 00 05 " + Utils.hexDump(fileN)+" "+Utils.hexDumpSpaces(Utils.switchBytes(Utils.intToByteArray(credit)))+" 00"));
	}


	public void commit(byte fileN) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException {
		Log.e("commit","card Commit");
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 C7 00 00 01 " + Utils.hexDump(fileN)+" 00"));
	}

	public byte[] sendCommand(byte[] command) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (cardChannel == null) {
                throw new NoCardConnected();
        }
        command=getSecureCommand(command);
        if (debugLevel > 1)
                Log.e("Debug","Sending <" + Utils.hexDump(command) + "> to card in reader <" + cardReader + ">");
        byte[] response = getSecureResponse(cardChannel.transmit(command));
//        byte[] response = conn.transmit(new CommandAPDU(command)).getBytes();
        
        if (debugLevel > 1)
        	Log.e("Debug","Receiving data <" + Utils.hexDump(response) + ">");
        return response;
	}
	
	private byte[] getSecureResponse(byte[] response) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		switch(securityLevel){
		case Utils.PLAIN_COMMUNICATION:
			return response;
		case Utils.FULLY_ENCRYPTED:
			if(response.length>2){
				System.out.println("RESPUESTA TIENE: "+response.length);
				byte[] data=Utils.subByteArray(response, (short)0, (short)(response.length-3));//data-SW
				data=decryptMessage(data,sessionKey);
				return Utils.concatByteArray(data, Utils.subByteArray(response, (short)(response.length-2), (short)(response.length-1)));
			}else return response;
		default:
			break;
		}
		return null;
	}
	private byte[] encryptMessage(byte[] msg, SecretKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		//CRC16
		byte[] crc=Utils.crc16(msg);
		msg=Utils.concatByteArray(msg, crc);
		//padding
		System.out.println("ANTES DEL PADDING: "+Utils.hexDumpSpaces(msg));
		msg=Utils.preparePaddedByteArray(msg);
		//Encypher		
		cipher.init(Cipher.ENCRYPT_MODE,key);
		System.out.println("MENSAJE A CIFRAR: "+Utils.hexDumpSpaces(msg));
		
		return cipher.doFinal(msg);
	}
	
	private byte[] getSecureCommand(byte[] command) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		switch(securityLevel){
		case Utils.PLAIN_COMMUNICATION:
			return command;
		case Utils.FULLY_ENCRYPTED:
			byte[] data=Utils.subByteArray(command, (short)5, (short)(command.length-2));//Does not include the Le
			data=encryptMessage(data,sessionKey);
			System.out.println("SALIDA DEL CIPHER:"+Utils.hexDumpSpaces(data));
			return Utils.hexStringToByteArray("90 "+Utils.hexDump(command[1])+" 00 00 "+Utils.hexDump((byte)data.length)+" "+Utils.hexDumpSpaces(data)+" 00");
		default:
			return null;			
		}
	}
	
	private byte[] decryptMessage(byte[]msg,SecretKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		cipher.init(Cipher.DECRYPT_MODE, key);
		msg=cipher.doFinal(msg);		
		byte[] data=Utils.removePadding(msg);
		//Checks CRC
		byte[] receivedCrc=Utils.subByteArray(data, (byte)(data.length-2),(byte) (data.length-1));
		data=Utils.subByteArray(data,(byte) 0, (byte)(data.length-3));
		byte[] newCrc=Utils.crc16(data);
		if(Utils.byteArrayCompare(newCrc,receivedCrc)==false){
			//We check if there was no padding
			receivedCrc=Utils.subByteArray(msg, (byte)(msg.length-2),(byte) (msg.length-1));
			msg=Utils.subByteArray(msg,(byte) 0, (byte)(msg.length-3));
			newCrc=Utils.crc16(msg);
			if(Utils.byteArrayCompare(newCrc,receivedCrc)==false){
				securityLevel=Utils.PLAIN_COMMUNICATION;
				throw new InvalidKeyException();
			}
			return msg;
		}
		return data;
	}
}
