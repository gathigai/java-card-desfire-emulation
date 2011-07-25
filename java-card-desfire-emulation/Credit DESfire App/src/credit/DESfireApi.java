package credit;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.List;
import java.util.Random;

import be.fedict.eidtoolset.exceptions.AIDNotFound;
import be.fedict.eidtoolset.exceptions.InvalidResponse;
import be.fedict.eidtoolset.exceptions.NoCardConnected;
import be.fedict.eidtoolset.exceptions.NoReadersAvailable;
import be.fedict.util.TextUtils;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;





public class DESfireApi {
	

	
    private List<CardTerminal> readers;
    private CardTerminal reader;
    private Card card;
    private CardChannel conn;
    private int usingReaderNr = -1;
    private byte securityLevel;
    private byte authenticated=-1;
    private SecretKey sessionKey;
    private Cipher cipher;
//    byte[] AID = {(byte)0x00,(byte)0xA4,(byte)0x04,(byte)0x00,(byte)0x10,(byte)0xD2,(byte)0x76,(byte)0x00,(byte)0x01,(byte)0x18,(byte)0x00,(byte)0x02,(byte)0xFF,(byte)0x49,(byte)0x50,(byte)0x25,(byte)0x89,(byte)0xC0,(byte)0x01,(byte)0x9B,(byte)0x01,(byte)0x00};
    byte[] AID;
    
    /**
	 * debugLevel = 0: no debug information; 1: minimal debug information
	 * (reader and card information); 2: maximal debug information (apdus)
	 */
	private int debugLevel = 2;

	public DESfireApi() throws NoSuchAlgorithmException, NoReadersAvailable, CardException, AIDNotFound, NoCardConnected, NoSuchProviderException, NoSuchPaddingException{
		
		 
	    AID=Utils.hexStringToByteArray("00 A4 04 00 0B 01 02 03 04 05 06 07 08 09 00 00");
	    
	    String[] readers;
	    readers=getReaders();
	    for (int i = 0; i < readers.length; i++){
	    	System.out.println(readers[i]);
	    }
	    lookForSmartCard("SCM Microsystems Inc. SDI010 Contactless Reader 0", 10100, AID);
	    Security.addProvider(new BouncyCastleProvider());
	    this.securityLevel=Utils.PLAIN_COMMUNICATION;
	    cipher=Cipher.getInstance("DESede/ECB/NoPadding","BC");
		 
	}
	/**
	 *	Creates an application with default key settings 
	 * @param AID
	 *
	 * @param changeKeyAccessRigths
	 * @throws CardException 
	 * @throws NoCardConnected 
	 * @throws InvalidResponse 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public void createApplication(String AID,byte numberOfKeys) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		sendCommand(Utils.hexStringToByteArray("90 CA 00 00 05 " +Utils.addSpaces(AID)+ " 01 "+Utils.hexDump(numberOfKeys)+" 00"));//Create App
	}
	
	/**
	 * Selects the application with the AID specified
	 * 
	 * @param AID
	 * @throws InvalidResponse
	 * @throws NoCardConnected
	 * @throws CardException
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public void selectApplication(String AID) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		sendCommand(Utils.hexStringToByteArray("90 5A 00 00 03 " +Utils.addSpaces(AID)+" 00"));
		this.securityLevel=Utils.PLAIN_COMMUNICATION;
		this.authenticated=-1;
	}
	
	/**
	 * Creates a file with encrypted access and specifies the keys and the size
	 * @param fileN
	 * @param readKey
	 * @param writeKey
	 * @param readWriteKey
	 * @param changeKey
	 * @param size
	 * @throws CardException 
	 * @throws NoCardConnected 
	 * @throws InvalidResponse 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public void createStdDataFile(byte fileN,byte readKey,byte writeKey,byte readWriteKey,byte changeKey,short size) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{		
		sendCommand(Utils.hexStringToByteArray("90 CD 00 00 07 " +Utils.hexDump(fileN)+" 03 " +Utils.hexDump(Utils.twoNibbleToByte(readWriteKey, changeKey))+" "+Utils.hexDump(Utils.twoNibbleToByte(readKey, writeKey))+" "+Utils.hexDumpSpaces(Utils.shortToByteArray(size))+" 00 00"));//Create App
	}
	
	public void createValueFile(byte fileN,byte readKey,byte writeKey,byte readWriteKey,byte changeKey,int value) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		sendCommand(Utils.hexStringToByteArray("90 CC 00 00 11 " +Utils.hexDump(fileN)+" 03 "+Utils.hexDump(Utils.twoNibbleToByte(readWriteKey, changeKey))+" "+Utils.hexDump(Utils.twoNibbleToByte(readKey, writeKey))+" 00 00 00 80 FF FF FF 7F "+Utils.hexDumpSpaces(Utils.switchBytes(Utils.intToByteArray(value)))+ " 00" ));
	}
	
	public String[] getApplicationIDs() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException {
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 6A 00 00 00"));
		String[] result = new String[response.length/3];
		if(result.length==0)return null;
		
		for (short i = 0; i < (short)(response.length-2); i=(short)(i+3)) {
			result[i/3]=Utils.hexDump(Utils.subByteArray(response, i,(short)(i+2)));
		}		
		return result;
	}
	
	/**
	 * Selects a file and write this data inside(no offset)
	 * 
	 * @param	data
	 * 			A normal string (no hexDump)
	 * @throws CardException 
	 * @throws NoCardConnected 
	 * @throws InvalidResponse
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 * @note	The data length has to be shorter than 52 characters 
	 */
	public void writeData(byte fileN,String data) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
//		data="1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
//		System.out.println("DATA TO WRITE: "+Utils.hexDumpSpaces(data.getBytes()));
		int bytesLeft=data.length();
//		//First Message
//		if(bytesLeft>Utils.BUFFER_DATA_LENGTH_MAX-7){
//			System.out.println("BYTES LEFT: "+bytesLeft+ " y BUFFER_LENGTH_MAX-7 : "+(Utils.BUFFER_DATA_LENGTH_MAX-7) );
//			sendCommand(Utils.hexStringToByteArray("90 3D 00 00 "+Utils.hexDump((byte)(0x7F))+" " + Utils.hexDump(fileN)+" 00 00 00 "+Utils.hexDumpSpaces(Utils.switchTwoBytes(Utils.shortToByteArray((short)data.length())))+" 00 "+Utils.hexDumpSpaces(Utils.subByteArray(data.getBytes(), (short)0, (short)(0x77)))+" 00"));
//			bytesLeft=(bytesLeft-Utils.BUFFER_DATA_LENGTH_MAX-7);
//			System.out.println("BYTES LEFT: "+bytesLeft+ " y BUFFER_LENGTH_MAX-7 : "+(Utils.BUFFER_DATA_LENGTH_MAX-7) );
//		}
//		else {
			sendCommand(Utils.hexStringToByteArray("90 3D 00 00 "+Utils.hexDump((byte)(7+bytesLeft))+" " + Utils.hexDump(fileN)+" 00 00 00 "+Utils.hexDumpSpaces(Utils.switchTwoBytes(Utils.shortToByteArray((short)data.length())))+" 00 "+Utils.hexDumpSpaces(data.getBytes())+" 00"));
//			return;
//		}
//		//Next Messages
//		while(bytesLeft>Utils.BUFFER_DATA_LENGTH_MAX){
//			sendCommand(Utils.hexStringToByteArray("90 AF 00 00 "+Utils.hexDump((byte)(Utils.BUFFER_DATA_LENGTH_MAX-1))+" "+Utils.hexDumpSpaces(Utils.subByteArray(data.getBytes(), (short)0, (short)(Utils.BUFFER_DATA_LENGTH_MAX)))+" 00"));
//			bytesLeft=(bytesLeft-Utils.BUFFER_DATA_LENGTH_MAX);			
//		}
//		if(bytesLeft>0)sendCommand(Utils.hexStringToByteArray("90 AF 00 00 "+Utils.hexDump((byte)(bytesLeft))+" "+Utils.hexDumpSpaces(Utils.subByteArray(data.getBytes(), (short)0, (short)(bytesLeft)))+" 00"));
	}
	
	public byte[] readData(byte fileN) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 8D 00 00 07 " + Utils.hexDump(fileN)+" 00 00 00 00 00 00 00"));
		response=Utils.subByteArray(response,(short) 0, (short)(response.length-2));
		while((response.length==2)&&(response[1]==(byte)0xAF)){
			byte[] nextResponse=sendCommand(Utils.hexStringToByteArray("90 AF 00 00 00 00"));
			nextResponse=Utils.subByteArray(nextResponse,(short) 0, (short)(nextResponse.length-2));
			response=Utils.concatByteArray(response, nextResponse);
		}
		return response;
	}
	
	public byte[] getValue(byte fileN) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException {
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 6C 00 00 01 " + Utils.hexDump(fileN)+" 00"));
		System.out.println("GET VALUE: "+Utils.subByteArray(response,(short) 0, (short)(response.length-3)));
		return Utils.subByteArray(response,(short) 0, (short)(response.length-3));
	}
	
	public void addCredit(byte fileN) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException{
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 0C 00 00 05 " + Utils.hexDump(fileN)+" "+Utils.hexDumpSpaces(Utils.switchBytes(Utils.intToByteArray(1)))+" 00"));
	}
	
	public void commit(byte fileN) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException {
		byte[] response=sendCommand(Utils.hexStringToByteArray("90 C7 00 00 01 " + Utils.hexDump(fileN)+" 00"));
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
	        this.sessionKey=new SecretKeySpec(sessionKeyBytes, "DESede");
	        this.securityLevel=Utils.FULLY_ENCRYPTED;
	        this.authenticated=keyNumber;
	        
	        //Ek(RndA') is checked
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
	        System.arraycopy(response, 0, response2, 0, 8);
	        cipherText=Utils.hexDumpSpaces(cipher.doFinal(response2));
        }
   }

   public void changeKey(byte keyN, byte[] newKey, byte[] oldKey) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidResponse, NoCardConnected, CardException {
	   
	   	SecretKey keySpec = new SecretKeySpec(oldKey, "DESede");
		Cipher cipher=Cipher.getInstance("DESede/ECB/NoPadding","BC");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		sendCommand(Utils.hexStringToByteArray("90 C4 00 00 11 "+Utils.hexDump(keyN)+" "+Utils.hexDumpSpaces(cipher.doFinal(newKey))+" 00"));
		if(this.authenticated==keyN){
			this.authenticated=-1;
			this.securityLevel=Utils.PLAIN_COMMUNICATION;
		}	
   }
/**************************************************************************/	
	/*
	 * Connection stuff
	 */
	public String[] getReaders() throws NoReadersAvailable, NoSuchAlgorithmException, CardException {
	    List<CardTerminal> allReaders;
	    allReaders = TerminalFactory.getInstance("PC/SC", null).terminals().list();
        if (allReaders.isEmpty()) {
                throw new NoReadersAvailable();
        }
        String[] names = new String[allReaders.size()];
        for (int i = 0; i < allReaders.size(); i++)
                names[i] = ((CardTerminal) allReaders.get(i)).getName();
        return names;
	}




	public void lookForSmartCard(String preferredReader, int milliSecondsBeforeTryingAnotherReader, byte[] AID_APDU) throws NoReadersAvailable, CardException, NoSuchAlgorithmException, AIDNotFound, NoCardConnected {
        readers = TerminalFactory.getInstance("PC/SC", null).terminals().list();
        if (readers.isEmpty()) {
        	throw new NoReadersAvailable();
        }
        if (debugLevel > 0) {
            for (int i = 0; i < readers.size(); i++) System.err.println("Discovered smart card reader <" + ((CardTerminal) readers.get(i)).getName() + "> as reader <" + i + ">");
        }
        usingReaderNr = 0;
        preferredReader = preferredReader.toUpperCase();
        for (int i = 0; i < readers.size(); i++){ 
        	if (((CardTerminal) readers.get(i)).getName().toUpperCase().indexOf(preferredReader) >= 0) usingReaderNr = i;
        }
        System.out.println("Name "+ ((CardTerminal) readers.get(usingReaderNr)).getName().toUpperCase());
        if (debugLevel > 0)	System.err.println("Using smart card reader <" + usingReaderNr + ">, <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">, preferred reader was <" + preferredReader + ">");
        card = null;
        //do {
        	if (debugLevel > 0) System.err.println("Waiting for a card to be inserted into smart card reader <" + usingReaderNr + ">, <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">, will timeout in <" + milliSecondsBeforeTryingAnotherReader+ "> milliseconds");
            reader = (CardTerminal) readers.get(usingReaderNr);
            if (reader.isCardPresent() || reader.waitForCardPresent(milliSecondsBeforeTryingAnotherReader)) {
                // Always connect using T=0
                try {
                	card = reader.connect("T=1");
                } catch (CardException e) { 
                    // Sometimes the NFC phones only support "T=1" to get
                    // connection (nothing else changes though)
                	System.out.println("CARD EXCEPTION");
                    card = reader.connect("T=1");
                }
                conn = card.getBasicChannel();
                if(!((CardTerminal)readers.get(usingReaderNr)).getName().equalsIgnoreCase("    CCID USB Reader 0")){
                	System.err.println("The reader is "+((CardTerminal)readers.get(usingReaderNr)).getName().toUpperCase());
            		selectApplet(AID_APDU); //Aquí teniamos un problema ya que no existía tal Aplicacion
                }
            }
            else card = null;
  /*      	if (card == null) {
                usingReaderNr++;
                if (usingReaderNr >= readers.size())
                    throw new NoCardConnected();
                if (debugLevel > 0)
                	System.err.println("Trying again with smart card reader <" + usingReaderNr + ">, <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + "> as no card was detected within <" + milliSecondsBeforeTryingAnotherReader+ "> milliseconds");
            }*/
            if (card == null) {
            	throw new NoCardConnected();
            }
    //	} while (card == null);
            if (debugLevel > 0)	System.err.println("Discovered card in <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">");
            if (debugLevel > 0) System.err.println("Card ATR is <" + TextUtils.hexDump(card.getATR().getBytes()) + ">");
            ((CardTerminal) readers.get(usingReaderNr)).getName();
	}




	private void selectApplet(byte[] AID_APDU) throws AIDNotFound, CardException {
        ResponseAPDU response = conn.transmit(new CommandAPDU(AID_APDU));
        if (response.getSW() != (Integer) 0x9000)
                throw new AIDNotFound();
	}



	public byte[] sendCommand(byte[] command) throws InvalidResponse, NoCardConnected, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (card == null) {
                throw new NoCardConnected();
        }
        
        if (debugLevel > 1)
                System.err.println("Sending <" + TextUtils.hexDump(command) + "> to card in reader <" + ((CardTerminal) readers.get(usingReaderNr)).getName() + ">");
        command=getSecureCommand(command);
        byte[] response = getSecureResponse(conn.transmit(new CommandAPDU(command)).getBytes());
//     
        
        if (debugLevel > 1)
                System.err.println("Receiving data <" + TextUtils.hexDump(response) + ">");
        return response;
	}

	private byte[] getSecureCommand(byte[] command) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		switch(securityLevel){
		case Utils.PLAIN_COMMUNICATION:
			return command;
		case Utils.FULLY_ENCRYPTED:
			byte[] data=Utils.subByteArray(command, (short)5, (short)(command.length-2));//Does not include the Le
			data=encryptMessage(data,sessionKey);
			return Utils.hexStringToByteArray("90 "+Utils.hexDump(command[1])+" 00 00 "+Utils.hexDump((byte)data.length)+" "+Utils.hexDumpSpaces(data)+" 00");
		default:
			return null;			
		}
	}
	private byte[] getSecureResponse(byte[] response) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		switch(securityLevel){
		case Utils.PLAIN_COMMUNICATION:
			return response;
		case Utils.FULLY_ENCRYPTED:
			if(response.length>2){
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
		msg=Utils.preparePaddedByteArray(msg);
		//Encypher		
		cipher.init(Cipher.ENCRYPT_MODE,key);
		
		return cipher.doFinal(msg);
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
	public byte[] getATR() {
        return card.getATR().getBytes();
	}

	public void powerOff() throws CardException {
        try {
                card.disconnect(true);// boolean true will reset card: a select
                // command is needed again after this
                card = null;
                conn = null;
        } catch (CardException e) {
                if (debugLevel > 0) {
                        e.printStackTrace();
                        System.err.println("Try to disconnect card form reader: " + ((CardTerminal) readers.get(usingReaderNr)).getName() + "\n Card already disconnected.");
                }
                card = null;
                conn = null;
                throw new CardException("Card already disconnected.");
        }
	}

	
}
