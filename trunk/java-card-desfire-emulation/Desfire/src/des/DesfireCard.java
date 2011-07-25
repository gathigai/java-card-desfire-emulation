package des;

import javacard.framework.*;
import javacard.framework.service.BasicService;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class DesfireCard extends javacard.framework.Applet  implements MultiSelectable{
	
	/**
	 * Master file of the card
	 */
	protected MasterFile masterFile;
	
	/**
	 * File selected
	 */
	private File selectedFile;
	
	/**
	 * Directory file selected
	 */
	private DirectoryFile selectedDF;
	
	/**
	 * Sets wich command has to continue after a CONTINUE command
	 */
	private byte commandToContinue;//para comandos que necesitan continuar
	
	/**
	 * Used in R/W operations to keep the number of bytes processed so far
	 */
	private short readed;
	
	/**
	 * Pointer to the location where the operaton will continue
	 */
	private short offset;
	
	/**
	 * Number of bytes not processed yet
	 */
	private short bytesLeft;
	
	/**
	 * Keeps the number of the key that is going to be authenticated during
	 * the authenticate operation
	 */
	private byte keyNumberToAuthenticate;
	
	/**
	 * Key number that has been authenticated last
	 */
	private byte authenticated;
	
	private RandomData randomData;
	private Cipher cipher;
	private byte[] dataBuffer;
	byte[] randomNumberToAuthenticate;
	BasicService bs;
	
	
	byte securityLevel;
	
	Key sessionKey;
//	byte[] sessionKeyBytes;//
	
   /**
	 * called by the JCRE to create an applet instance
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// create a eID card applet instance
		new DesfireCard();
	}
	
	/**
	 * private constructor - called by the install method to instantiate a
	 * EidCard instance
	 * 
	 * needs to be protected so that it can be invoked by subclasses
	 */
	protected DesfireCard() {
		masterFile=new MasterFile();
		selectedDF=masterFile;
		if (this.randomData == null)
			this.randomData=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);			
		if (this.cipher == null)
			this.cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
		offset=0;
		bytesLeft=0;
		keyNumberToAuthenticate=0;
		authenticated=Util.NO_KEY_AUTHENTICATED;
		sessionKey=(DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
		sessionKey.clearKey();
		securityLevel=Util.PLAIN_COMMUNICATION;
		bs=new BasicService();
		
		// register the applet instance with the JCRE
		register();
	}
			
	public void process(APDU apdu) {
		// return if the APDU is the applet SELECT command
		if (selectingApplet())
			return;
		
		byte[] buffer = apdu.getBuffer();
		
		
		if(authenticated==-1)this.securityLevel=Util.PLAIN_COMMUNICATION;
	    if((commandToContinue!=0) && (buffer[ISO7816.OFFSET_INS]!=(byte)0xAF))ISOException.throwIt((short) 0x91CA);
		// check the INS byte to decide which service method to call
		switch (buffer[ISO7816.OFFSET_INS]) {
		case Util.AUTHENTICATE:
			authenticate(apdu,buffer);
			break;
		case Util.CHANGE_KEY_SETTINGS:
			changeKeySettings(apdu,buffer);
			break;
		case Util.CHANGE_KEY:
			changeKey(apdu,buffer);
			break;		
		case Util.CREATE_APPLICATION:
			createApplication(apdu, buffer);
			break;
		case Util.DELETE_APPLICATION:
			deleteApplication(apdu, buffer);
			break;
		case Util.GET_APPLICATION_IDS:
			getApplicationIDs(apdu,buffer);
			break;
		case Util.GET_KEY_SETTINGS:
			getKeySettings(apdu, buffer);
			break;
		case Util.SELECT_APPLICATION:
			selectApplication(apdu, buffer);
			break;
		case Util.FORMAT_PICC:
			formatPICC(apdu, buffer);
			break;
		case Util.SET_CONFIGURATION:
			setConfiguration(apdu,buffer);
			break;
		case Util.GET_FILE_IDS:
			getFileIDs(apdu, buffer);
			break;
		case Util.CREATE_STDDATAFILE:
			createStdDataFile(apdu, buffer);
			break;
		case Util.CREATE_VALUE_FILE:
			createValueFile(apdu, buffer);
			break;
		case Util.CREATE_LINEAR_RECORD_FILE:
			createLinearRecordFile(apdu, buffer);
			break;
		case Util.CREATE_CYCLIC_RECORD_FILE:
			createCyclicRecordFile(apdu, buffer);
			break;
		case Util.DELETE_FILE:
			deleteFile(apdu, buffer);
			break;
		case Util.READ_DATA:
			readData(apdu, buffer);
			break;
		case Util.WRITE_DATA:
			writeData(apdu, buffer);
			break;
		case Util.GET_VALUE:
			getValue(apdu, buffer);
			break;
		case Util.CREDIT:
			credit(apdu,buffer);
			break;
		case Util.DEBIT:
			debit(apdu,buffer);
			break;
		case Util.READ_RECORDS:
			readRecords(apdu,buffer);
			break;
		case Util.WRITE_RECORD:
			writeRecord(apdu,buffer);
			break;
		case Util.CLEAR_RECORD_FILE:
			clearRecordFile(apdu,buffer);
			break;
		case Util.COMMIT_TRANSACTION:
			commitTransaction(apdu, buffer);
			break;
		case Util.ABORT_TRANSACTION:
			abortTransaction(apdu, buffer);
			break;
		case Util.CONTINUE:
			switch(commandToContinue){
			case Util.AUTHENTICATE:
				authenticate(apdu,buffer);
				break;
			case Util.GET_APPLICATION_IDS:
				getApplicationIDs(apdu, buffer);
				break;
			case Util.READ_DATA:
				readData(apdu, buffer);
				break;
			case Util.WRITE_DATA:
				writeData(apdu, buffer);
				break;
			case Util.READ_RECORDS:
				readRecords(apdu,buffer);
				break;
			case Util.WRITE_RECORD:
				writeRecord(apdu,buffer);
				break;
				
			default:
				ISOException.throwIt((short) 0x911C);
				break;
			}
			break;
		default:
			ISOException.throwIt((short) 0x911C);
			break;
		}
	}
	
	/**
	 * PICC and reader device show in an encrypted way that they posses the same key.
	 *  
	 * @effect	Confirms that both entities are permited to do operations on each 
	 * 			other and creates a session key.
	 * @note	This procedure has two parts. depending on the commandToContinue status.
	 * @note	||KeyNumber|| 
	 * 			
	 */
	private void authenticate(APDU apdu, byte[] buffer){
	//APDU: KeyNo
		receiveAPDU(apdu, buffer);
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			//FIRST MESSAGE
			// RndB is generated			
			keyNumberToAuthenticate=buffer[ISO7816.OFFSET_CDATA];
			if(!selectedDF.isValidKeyNumber(keyNumberToAuthenticate))ISOException.throwIt(Util.NO_SUCH_KEY);
			randomNumberToAuthenticate=new byte[8];
			randomData.generateData(randomNumberToAuthenticate,(short) 0,(short) 8);
			//Ek(RndB) is created
			byte[] ekRndB=new byte[8];
			if(selectedDF.isMasterFile())cipher.init(selectedDF.getMasterKey(), Cipher.MODE_ENCRYPT);
			else cipher.init(selectedDF.getKey(keyNumberToAuthenticate), Cipher.MODE_ENCRYPT);
			cipher.doFinal(randomNumberToAuthenticate, (short)0,(short)8, ekRndB, (short)0);
			commandToContinue=Util.AUTHENTICATE;

			//Ek(RndB) is sent
			sendResponse(apdu, buffer, ekRndB,(byte)0xAF);
		}
		else{
			//SECCOND MESSAGE 
			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
			byte[] encryptedRndA=new byte[8];
			byte[] encryptedRndArndB=new byte[16];
			byte[] rndA=new byte[8];
			byte[] rndB=new byte[8];
			byte[] rndArndB=new byte[16];
			//Ek(RndA-RndB') is recieved. RndB' is a 8 bits left-shift of RndB	
			encryptedRndArndB=Util.subByteArray(buffer, (byte)ISO7816.OFFSET_CDATA, (byte)(ISO7816.OFFSET_CDATA+16));
			if(selectedDF.isMasterFile())cipher.init(selectedDF.getMasterKey(), Cipher.MODE_DECRYPT);
			else cipher.init(selectedDF.getKey(keyNumberToAuthenticate), Cipher.MODE_DECRYPT);
			cipher.doFinal(encryptedRndArndB, (short)0, (short)16, rndArndB, (short)0);
			rndA=Util.subByteArray(rndArndB, (byte)0, (byte)7);
			rndB=Util.subByteArray(rndArndB, (byte)8, (byte)15);
			rndB=Util.rotateRight(rndB);//Because rndB was left shifted
			//RndB is checked
			if(javacard.framework.Util.arrayCompare(rndB,(short)0,randomNumberToAuthenticate,(short)0,(short)rndB.length)!=0){
				//Authentication Error
				authenticated=Util.NO_KEY_AUTHENTICATED;
				ISOException.throwIt(Util.AUTHENTICATION_ERROR);
			}
			else {
				//The key is authenticated
				authenticated=keyNumberToAuthenticate;
			}
			//Session key is created
			byte[] newSessionKey=Util.create3DESSessionKey(rndA,rndB);
			
			//Ek(RndA')is sent back
			rndA=Util.rotateLeft(rndA);
			if(selectedDF.isMasterFile())cipher.init(selectedDF.getMasterKey(), Cipher.MODE_ENCRYPT);
			else cipher.init(selectedDF.getKey(keyNumberToAuthenticate), Cipher.MODE_ENCRYPT);
			cipher.doFinal(rndA, (short)0,(short)8, encryptedRndA, (short)0);
			sendResponseAndChangeStatus(apdu, buffer,encryptedRndA,newSessionKey);				
		}
	}
	
	/**
	 * Changes the master key settings on PICC and application level
	 * 
	 * 	@note	||Ciphered Key Settings||	
	 */
	private void changeKeySettings(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		//Hay que descifrar el campo de datos
		//FALTA
		byte keySettings=buffer[ISO7816.OFFSET_CDATA];
		if(!selectedDF.hasKeySettingsChangeAllowed(authenticated))ISOException.throwIt(Util.PERMISSION_DENIED);
		if(selectedDF.getFileID()==(byte)0x00){
			masterFile.changeKeySettings(keySettings);
			selectedDF=masterFile;
		}
		else{
			selectedDF.changeKeySettings(keySettings);
			masterFile.arrayDF[selectedDF.getFileID()]=selectedDF;//Actualizamos
		}
		ISOException.throwIt(Util.OPERATION_OK);		
	}
	
	/**
	 * Changes any key stored on the PICC
	 * 
	 * @note ||Key number | Ciphered Key Data||	
	 */
	private void changeKey(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		byte keyN=buffer[ISO7816.OFFSET_CDATA];
		
		if(selectedDF.hasChangeAccess(authenticated,keyN)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		//El resto del contenido viene cifrado y hay un cifrado particular para ciertos casos
		//FALTA
		byte[] newKey = new byte[(byte)(buffer[ISO7816.OFFSET_LC]-1)];
		for (byte i = 0; i < newKey.length; i++) {
			newKey[i]=buffer[(byte)(ISO7816.OFFSET_CDATA+i+1)];		
		}
		cipher.init(selectedDF.getKey(keyNumberToAuthenticate), Cipher.MODE_DECRYPT);
		byte[] newKeyDecrypted=new byte[newKey.length];
		cipher.doFinal(newKey,(short) 0, (short)16, newKeyDecrypted,(short) 0);
		
		if(selectedDF.isMasterFile()){
			if(authenticated==keyN)authenticated=Util.NO_KEY_AUTHENTICATED;
			masterFile.changeKey(keyN,newKeyDecrypted);
			selectedDF=masterFile;
		}
		else{
			if(authenticated==keyN)authenticated=Util.NO_KEY_AUTHENTICATED;
			selectedDF.changeKey(keyN,newKeyDecrypted);
			masterFile.arrayDF[selectedDF.getFileID()]=selectedDF;
		}
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Creates a new oplication on the PICC
	 * 
	 * 	@note	|| AID | KeySettings1 | KeySettings2 | ISOFileID | DF_FILE || 
	 */
	private void createApplication(APDU apdu, byte[] buffer){
		
		receiveAPDU(apdu, buffer);
		if(masterFile.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		if(masterFile.getIndexDF().hasWriteAccess((byte)0)==false) ISOException.throwIt(Util.PERMISSION_DENIED);//CREO QUE SOBRA
		byte[] AID = {buffer[ISO7816.OFFSET_CDATA],buffer[ISO7816.OFFSET_CDATA+1],buffer[ISO7816.OFFSET_CDATA+2]};
		byte[] keySettings={buffer[ISO7816.OFFSET_CDATA+3],buffer[ISO7816.OFFSET_CDATA+4]};
		masterFile.addDF(AID,keySettings);
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Permanently desactivates applications on the PICC
	 * 
	 * 	@effect If the application that is going to be removed is the currently selected
	 * 			the PICC level is set
	 * 	@note	|| AID ||
	 */
	private void deleteApplication(APDU apdu, byte[] buffer){
		
		receiveAPDU(apdu, buffer);
		byte[] AID= {buffer[ISO7816.OFFSET_CDATA],buffer[ISO7816.OFFSET_CDATA+1],buffer[ISO7816.OFFSET_CDATA+2]};
		if(masterFile.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		if(selectedDF.getFileID()==masterFile.searchAID(AID))selectedDF=masterFile;
		masterFile.deleteDF(AID);
		if(selectedDF.isMasterFile())selectedDF=masterFile;
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Returns the application identifiers of all applications on a PICC
	 * 	@note	If the number of applications is higher than 19 the command will
	 * 			work in two parts. 
	 */
	private void getApplicationIDs(APDU apdu, byte[] buffer){
		 byte[] response;
		 byte numApp=(byte)(masterFile.numApp-1);//-1 because the IndexFile won't be included
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			if(masterFile.hasGetRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
			if(numApp==0)ISOException.throwIt(Util.OPERATION_OK);
//			if(numApp==1){
//				sendResponse(apdu,buffer,masterFile.getAID((byte) 1));
//				return;
//			}
			if(numApp>19){
				response=new byte[(byte)19*3];
				commandToContinue=Util.GET_APPLICATION_IDS;
			}
			else response=new byte[(byte)(numApp*3)];
			for (byte i = 0; i < response.length; i=(byte)(i+3)) {
				byte[] AID=masterFile.getAID((byte)(i/3+1));//+1 because the IndexFile won't be included
				response[i]=AID[0];
				response[(byte)(i+1)]=AID[1];
				response[(byte)(i+2)]=AID[2];
			}
//			ISOException.throwIt(response[3]);
			//Habría que devolver STATUS WORD AF si hay más AID q enviar
			sendResponse(apdu, buffer, response);
		}
		else{//Second part
			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
			response=new byte[(byte)((numApp-19)*3)];
			for (byte i = 0; i < response.length; i=(byte)(i+3)) {
				byte[] AID=masterFile.getAID((byte)(i/3+21));//21 beacuase the IndexFile won't be included
				response[i]=AID[0];
				response[(byte)(i+1)]=AID[1];
				response[(byte)(i+2)]=AID[2];
			}
			sendResponse(apdu, buffer, response);
		}
	
		
		
	}
	
	/**
	 *	Gets information on the PICC and application master key settings.
	 * 	In addition it returns the maximum number of keys which are configured for the selected application. 
	 */
	private void getKeySettings(APDU apdu, byte[] buffer){
		if(!selectedDF.hasGetRights(authenticated))ISOException.throwIt(Util.PERMISSION_DENIED);
		byte ks=selectedDF.getKeySettings();
		byte kn=selectedDF.getKeyNumber();
		byte[] response=new byte[2];
		response[0]=ks;
		response[1]=kn;
		sendResponse(apdu, buffer, response);
	}
	
	/**
	 * Select one specific application for further access
	 * 
	 * @note || AID ||
	 */
	private void selectApplication(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if(masterFile.getIndexDF().hasReadAccess((byte)0)==false) ISOException.throwIt(Util.PERMISSION_DENIED);
		//AID
		byte[] AID = {buffer[ISO7816.OFFSET_CDATA],buffer[ISO7816.OFFSET_CDATA+1],buffer[ISO7816.OFFSET_CDATA+2]};
		if(javacard.framework.Util.arrayCompare(AID, (short)0, Util.masterFileAID,(short)0,(short) AID.length)== 0){
			selectedDF=masterFile;
		}else{
			byte i=masterFile.searchAID(AID);
			
			if(i!=(byte)-1)	selectedDF=masterFile.arrayDF[masterFile.searchAID(AID)];
			else ISOException.throwIt(Util.APPLICATION_NOT_FOUND);//Aplication not found
		}
		authenticated=Util.NO_KEY_AUTHENTICATED;
		securityLevel=Util.PLAIN_COMMUNICATION;
		//envía 00
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/** 
	 * Releases the PICC user memory
	 * 
	 * @note 	Requires a preceding authentication with the PICC Master Key
	 * @effect	All application are deleted and all files within them. 
	 * 			The PICC Master Keyand the PICC Master Key settings keep their currently set values
	 */
	private void formatPICC(APDU apdu,byte[] buffer){
		if(selectedDF.isMasterFile()==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		if(masterFile.isFormatEnabled()==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		if(authenticated!=0)ISOException.throwIt(Util.PERMISSION_DENIED);
		masterFile.format();
		ISOException.throwIt(Util.OPERATION_OK);
		
	}
	
	/**
	 * Configures the card and pre personalizes the card with a key, defines if the UID or the 
	 * random ID is sent back during communication setup and configures the ATS string.
	 * 
	 * 	@note	|| Option | ciphered( data || CRC )||
	 */
	private void setConfiguration(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		//Autentificacion con MK requerida
		//FALTA
		byte encData[]=new byte[(byte)(buffer[ISO7816.OFFSET_LC]-1)];
		for (byte i = 0; i < encData.length; i++) {
			encData[i]=buffer[(byte)(i+ISO7816.OFFSET_CDATA+1)];
		}
		//Hay que descifrar esto
		//FALTA
		byte[] data =new byte[encData.length];//AUX
		data=encData;//AUX
		switch(buffer[ISO7816.OFFSET_CDATA]){
		case (byte) 0x00: //Configuration byte
			masterFile.setConfiguration(data[0]);
			break;
		case (byte) 0x01://Default key version and default key
			byte[] keyBytes=new byte[(byte)(data.length-1)];
			for (byte i = 0; i < keyBytes.length; i++) {
				keyBytes[i]=data[i];
			}
			masterFile.changeKey(masterFile.getMasterKeyType(), keyBytes);
			break;
		case (byte) 0x02://Data is the user defined ATS
			//FALTA
			break;
		default:
			ISOException.throwIt(Util.PARAMETER_ERROR);
			
		}
	}
	
	/**
	 * Returns the File Identifiers of all active files within the currently selected application
	 */
	private void getFileIDs(APDU apdu, byte[] buffer){
		if(selectedDF.hasGetRights(authenticated))ISOException.throwIt(Util.PERMISSION_DENIED);
		byte[] IDs=new byte[selectedDF.getNumberFiles()+1];
		byte mark=0;
		for (byte i = 0; i < (byte)(IDs.length-1); i++) {
			for (byte j = mark; j < 32; j++) {
				if(selectedDF.activatedFiles[j]==true){
					selectedFile=selectedDF.getFile(j);
					selectedFile.getFileID();
					IDs[i]=selectedFile.getFileID();
					mark=(byte)(j+1);
					break;
				}
			}
		}
		IDs[(byte)IDs.length-1]=(byte)0x00;
		sendResponse(apdu,buffer,IDs);
	}
	
	/**
	 * 	Creates files for the storage of plain unformatted user data 
	 * 	within an existing application on the PICC
	 * 
	 * 	@note	|| File Number | ISO7816 FileID | CommunicationSettings | AccessRights | FileSize(3) ||
	 * @note	The MSB in the 3 bits values is not readed. 
	 */
	private void createStdDataFile(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if(selectedDF.isMasterFile())ISOException.throwIt(Util.PERMISSION_DENIED);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		byte[] accessPermissions={(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2]};
		byte[] size={(byte)buffer[ISO7816.OFFSET_CDATA+5],(byte)buffer[ISO7816.OFFSET_CDATA+4]};
		
		if(buffer[ISO7816.OFFSET_LC]==9){
			accessPermissions[0]=(byte)buffer[ISO7816.OFFSET_CDATA+5];
			accessPermissions[1]=(byte)buffer[ISO7816.OFFSET_CDATA+4]; 
			size[0]=(byte)(byte)buffer[ISO7816.OFFSET_CDATA+7];
			size[1]=(byte)(byte)buffer[ISO7816.OFFSET_CDATA+6];
		}			
		short sizeS= Util.byteArrayToShort(size);
		if(sizeS>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))ISOException.throwIt(Util.OUT_OF_EEPROM_ERROR);
		if(selectedDF.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		selectedFile=new StandartFile(fileID, masterFile.arrayDF[selectedDF.getFileID()], accessPermissions, sizeS);	
		selectedDF=masterFile.arrayDF[selectedDF.getFileID()];
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * 	Creates files for the storage and manipulation of 32bit signed 
	 * 	integer values within an existing application on the PICC
	 * 
	 * 	@note	|| FileN | CommunicationSetting | AccessRights | LowerLimit(4) | UpperLimit(4) | Value(4) | LimitedCreditEnabled ||
	 */
	private void createValueFile(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if(selectedDF.isMasterFile())ISOException.throwIt(Util.PERMISSION_DENIED);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		byte[] accessPermissions={(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2]};
		Value lowerLimit= new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+7],(byte)buffer[ISO7816.OFFSET_CDATA+6],(byte)buffer[ISO7816.OFFSET_CDATA+5],(byte)buffer[ISO7816.OFFSET_CDATA+4]});
		Value upperLimit= new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+11],(byte)buffer[ISO7816.OFFSET_CDATA+10],(byte)buffer[ISO7816.OFFSET_CDATA+9],(byte)buffer[ISO7816.OFFSET_CDATA+8]});
		Value value=new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+15],(byte)buffer[ISO7816.OFFSET_CDATA+14],(byte)buffer[ISO7816.OFFSET_CDATA+13],(byte)buffer[ISO7816.OFFSET_CDATA+12]});
		if(upperLimit.compareTo(lowerLimit)!=1)ISOException.throwIt(Util.BOUNDARY_ERROR);
		if(upperLimit.compareTo(value)!=1)ISOException.throwIt(Util.BOUNDARY_ERROR);
		if(value.compareTo(lowerLimit)!=1)ISOException.throwIt(Util.BOUNDARY_ERROR);
		byte limitedCreditEnabled=(byte)buffer[ISO7816.OFFSET_CDATA+16];
		if((short)(30)>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))ISOException.throwIt(Util.OUT_OF_EEPROM_ERROR);
		if(selectedDF.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		selectedFile=new ValueRecord(fileID, masterFile.arrayDF[selectedDF.getFileID()], accessPermissions,lowerLimit,upperLimit,value,limitedCreditEnabled);
		selectedDF=masterFile.arrayDF[selectedDF.getFileID()];
		ISOException.throwIt(Util.OPERATION_OK);		
	}
	
	/**
	 * 	Creates files for multiple storage of structural similar data within
	 *  an existing application on the PICC.
	 *   
	 * 	@note 	Once the file is filled completely with data records further
	 * 			writing to the file is not possible unless it is cleared.
	 * 	@note	|| File Number | ISO7816 FileID | CommunicationSettings | AccessRights | RecordSize(3) | MaxNumRecords(3) ||
	 * 	@note	The MSB in the 3 bits values is not readed.
	 */
	private void createLinearRecordFile(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if(selectedDF.isMasterFile())ISOException.throwIt(Util.PERMISSION_DENIED);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		byte[] accessPermissions={(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2]};
		short recordSize= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+5],(byte)buffer[ISO7816.OFFSET_CDATA+4]});
		short maxRecordNum= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+8],(byte)buffer[ISO7816.OFFSET_CDATA+7]});
		if(buffer[ISO7816.OFFSET_LC]==12){
			accessPermissions[0]=(byte)buffer[ISO7816.OFFSET_CDATA+5];
			accessPermissions[1]=(byte)buffer[ISO7816.OFFSET_CDATA+4];
			recordSize= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+7],(byte)buffer[ISO7816.OFFSET_CDATA+6]});
			maxRecordNum= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+10],(byte)buffer[ISO7816.OFFSET_CDATA+9]});
		}			

		if((short)(recordSize*maxRecordNum)>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))ISOException.throwIt(Util.OUT_OF_EEPROM_ERROR);
		if(selectedDF.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		selectedFile=new LinearRecord(fileID, masterFile.arrayDF[selectedDF.getFileID()], accessPermissions,recordSize,maxRecordNum);
		selectedDF=masterFile.arrayDF[selectedDF.getFileID()];
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Creates files for multiple storage of structural similar data within
	 *  an existing application on the PICC.
	 *   
	 * 	@note 	Once the file is filled completely with data records, the oldest record
	 * 			is overwritten with the latest written one. 
	 * 	@note	|| File Number | ISO7816 FileID | CommunicationSettings | AccessRights | RecordSize(3) | MaxNumRecords(3) ||
	 * 	@note	The MSB in the 3 bits values is not readed.
	 */
	private void createCyclicRecordFile(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		if(selectedDF.isMasterFile())ISOException.throwIt(Util.PERMISSION_DENIED);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		byte[] accessPermissions={(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2]};
		short recordSize= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+5],(byte)buffer[ISO7816.OFFSET_CDATA+4]});
		short maxRecordNum= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+8],(byte)buffer[ISO7816.OFFSET_CDATA+7]});
		if(buffer[ISO7816.OFFSET_LC]==12){
			accessPermissions[0]=(byte)buffer[ISO7816.OFFSET_CDATA+5];
			accessPermissions[1]=(byte)buffer[ISO7816.OFFSET_CDATA+4];
			recordSize= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+7],(byte)buffer[ISO7816.OFFSET_CDATA+6]});
			maxRecordNum= Util.byteArrayToShort(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+10],(byte)buffer[ISO7816.OFFSET_CDATA+9]});
		}			
		if((short)(recordSize*maxRecordNum)>(short)JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT))ISOException.throwIt(Util.OUT_OF_EEPROM_ERROR);
		if(selectedDF.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		selectedFile=new CyclicRecord(fileID, masterFile.arrayDF[selectedDF.getFileID()], accessPermissions,recordSize,maxRecordNum);
		selectedDF=masterFile.arrayDF[selectedDF.getFileID()];
		ISOException.throwIt(Util.OPERATION_OK);	
	}
	
	/**
	 * 	Permanently desactivates a file within the file directory of the
	 * 	currently selected application
	 * 
	 * 	@note	|| FileNumber || 	
	 * 
	 */
	private void deleteFile(APDU apdu, byte[] buffer){
		
		receiveAPDU(apdu, buffer);
		byte fileNumber=(byte)buffer[ISO7816.OFFSET_CDATA];
		if(selectedDF.hasManageRights(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		selectedDF.deleteFile(fileNumber);
		masterFile.arrayDF[selectedDF.getFileID()]=selectedDF;
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * 	Reads data frin Standard Data Files or Backup Data Files
	 * 
	 * 	@note	|| FileNumber | Offset(3) | Length(3) ||
	 * 	@note	The MSB in the 3 bits values is not readed
	 * 	@note	When data is sent, if the length of the data doesn't fit in one
	 * 			message (59 bytes) the data field is splitted. If more thata will
	 * 			be sent the PICC informs with the SW: 0xAF 	
	 */
	private void readData(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		byte[] out;
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			selectedFile=(StandartFile) selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
			if(((StandartFile)selectedFile).hasReadAccess(authenticated)==false){
				ISOException.throwIt(Util.PERMISSION_DENIED);
			}
			offset=Util.byteArrayToShort(new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+2],(byte) buffer[ISO7816.OFFSET_CDATA+1]});		
			bytesLeft=Util.byteArrayToShort(new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+5],(byte) buffer[ISO7816.OFFSET_CDATA+4]});
			if(bytesLeft==0)bytesLeft=selectedFile.getSize();
		}
		if(bytesLeft>=59){
			out=new byte[59];
			out=((StandartFile)selectedFile).readArray(offset,(byte)59,(byte)0);
			bytesLeft=(short)(bytesLeft-59);
			offset=(short)(offset+59);
			commandToContinue=Util.READ_DATA;
			sendResponse(apdu,buffer,out,Util.CONTINUE);
		}else{	
			out=new byte[bytesLeft];
			out=((StandartFile)selectedFile).readArray(offset,(short)bytesLeft,(byte)0);
			bytesLeft=0;
			offset=0;
			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
			sendResponse(apdu,buffer,out);
		}
	}
	
	/**
	 *	Writes data to Standard Data Files or Backup Data Files
	 *
	 *	@note	|| File No | Offset | Lenght | Data ||
	 *	@note	The MSB in the 3 bits values is not readed
	 *	@note	If the data doesn't fit in one message (52 bytes)
	 *			the sender will split it in more messages (59 bytes)
	 *		 	so this command may have more than one execution in row.
	 */
	private void writeData(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		byte readed;
		byte[] data;
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			selectedFile=(StandartFile) selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
			if(((StandartFile)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
			offset=Util.byteArrayToShort(new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+2],(byte) buffer[ISO7816.OFFSET_CDATA+1]});	
			bytesLeft=Util.byteArrayToShort(new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+5],(byte) buffer[ISO7816.OFFSET_CDATA+4]});
			data=new byte[52];
			readed=(byte)(buffer[ISO7816.OFFSET_LC]-7);
			bytesLeft=(short)(bytesLeft-(short) readed);
			for (byte i = 0; i < readed; i++) {
				data[i]=buffer[(byte)(ISO7816.OFFSET_CDATA+i+7)];					
			}
		}
		else{ //commandToContinue==Util.WRITE_DATA
			data=new byte[59];
			readed=(byte)buffer[ISO7816.OFFSET_LC];
			bytesLeft=(short)(bytesLeft-(short) readed);
			for (byte i = 0; i < readed; i++) {
				data[i]=buffer[(byte)(ISO7816.OFFSET_CDATA+i)];					
			}
		}	
		//Write
		((StandartFile)selectedFile).writeArray(data,offset,readed);

		if(bytesLeft>0){
			commandToContinue=Util.WRITE_DATA;
			offset=(short)(offset+readed);
			ISOException.throwIt(Util.CONTINUE);
		}
		else{ 
			commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
			offset=0;
			bytesLeft=0;
			ISOException.throwIt(Util.OPERATION_OK);
		}
	}

	/**
	 * 	Reads the currently stored value form Value Files
	 * 
	 * 	@note	|| FileN ||	 
	 */
	private void getValue(APDU apdu, byte[] buffer){

		receiveAPDU(apdu, buffer);
		byte fileN=buffer[ISO7816.OFFSET_CDATA];
		selectedFile=(ValueRecord)selectedDF.getFile(fileN);
		if(((ValueRecord)selectedFile).hasReadAccess(authenticated)!=true) ISOException.throwIt(Util.PERMISSION_DENIED);
		byte[] response=Util.switchBytes((((ValueRecord)selectedFile).getValue().getValue()));
		sendResponse(apdu, buffer, response);
	}
	
	/**
	 * 	Increases a value stored in a Value File
	 * 
	 * 	@note	||	FileN | Data(4)	|| 	
	 */
	
	private void credit(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		selectedFile=(ValueRecord)selectedDF.getFile(fileID);
		if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		((ValueRecord)selectedFile).addCredit(new Value(new byte[] {(byte)buffer[ISO7816.OFFSET_CDATA+4],(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2],(byte)buffer[ISO7816.OFFSET_CDATA+1]}));
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Decreases a value stored in a Value File
	 * 
	 * @note	||	FileN | Data(4)	|| 	
	 */
	private void debit(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		byte fileID=(byte)buffer[ISO7816.OFFSET_CDATA];
		selectedFile=(ValueRecord)selectedDF.getFile(fileID);
		if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
		((ValueRecord)selectedFile).decDebit(new Value(new byte[]{(byte)buffer[ISO7816.OFFSET_CDATA+4],(byte)buffer[ISO7816.OFFSET_CDATA+3],(byte)buffer[ISO7816.OFFSET_CDATA+2],(byte)buffer[ISO7816.OFFSET_CDATA+1]}));
		ISOException.throwIt(Util.OPERATION_OK);
		
	}
	
	/**
	 * 	Writes data to a record in a Cyclic or Linear Record File
	 * 
	 * 	@note	|| FileN | Offset | Length | Data ||
	 * 	@note	The MSB in the 3 bits values is not readed
	 * 	@note	If the data doesn't fit in one message (52 bytes)
	 *			the sender will split it in more messages (59 bytes)
	 *		 	so this command may have more than one execution in row.
	 */
	private void writeRecord(APDU apdu, byte[] buffer){
		
		receiveAPDU(apdu, buffer);
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			File file= selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
			offset=Util.byteArrayToShort(new byte[] {(byte) buffer[ISO7816.OFFSET_CDATA+2],(byte) buffer[ISO7816.OFFSET_CDATA+1]});
			bytesLeft=Util.byteArrayToShort(new byte[] {(byte) buffer[ISO7816.OFFSET_CDATA+5],(byte) buffer[ISO7816.OFFSET_CDATA+4]});
			byte length=(byte)(buffer[ISO7816.OFFSET_LC]-7);
			dataBuffer=new byte[bytesLeft];
			for (byte i = 0; i < length; i++) {
				dataBuffer[i]=buffer[(byte)(ISO7816.OFFSET_CDATA+i+7)];					
			}
			if(file instanceof LinearRecord){
				file=(LinearRecord)selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
				if(((LinearRecord)file).hasWriteAccess(authenticated)==false){
					ISOException.throwIt(Util.PERMISSION_DENIED);
				}
			}else if(file instanceof CyclicRecord){
				file=(CyclicRecord)selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
				if(((CyclicRecord)file).hasWriteAccess(authenticated)==false){
					ISOException.throwIt(Util.PERMISSION_DENIED);
				}
			}
			if(bytesLeft<=52){
				if(file instanceof LinearRecord )((LinearRecord)file).writeRecord(dataBuffer,offset);
				if(file instanceof CyclicRecord)((CyclicRecord) file).writeRecord(dataBuffer,offset);
				dataBuffer=null;
				offset=0;
				bytesLeft=0;
				ISOException.throwIt(Util.OPERATION_OK);
			}
			else{
				readed=52;
				bytesLeft=(short)(bytesLeft-52);
				commandToContinue=Util.WRITE_RECORD;
				ISOException.throwIt(Util.CONTINUE);
			}
		}
		else{//commandToContinue==Util.WRITE_RECORD
			byte length=(byte)(buffer[ISO7816.OFFSET_LC]);
			for (byte i = 0; i < length; i++) {
				dataBuffer[(short)(i+readed)]=buffer[(byte)(ISO7816.OFFSET_CDATA+i)];					
			}
			if(bytesLeft<=59){
				if(selectedFile instanceof LinearRecord)((LinearRecord)selectedFile).writeRecord(dataBuffer,offset);
				if(selectedFile instanceof CyclicRecord)((CyclicRecord)selectedFile).writeRecord(dataBuffer,offset);
				dataBuffer=null;
				offset=0;
				bytesLeft=0;
				ISOException.throwIt(Util.OPERATION_OK);
			}
			else{
				readed=(short)(readed+59);
				bytesLeft=(short)(bytesLeft-59);
				commandToContinue=Util.WRITE_RECORD;
				ISOException.throwIt(Util.CONTINUE);
			}
		}
		return;
	}
	
	/**
	 * 	Reads out a set of complete records from a Cyclic or Linear Record File
	 * 
	 * 	@note	|| FileN | Offset | Length ||
	 * 			Offset.	Position of the newest record to read starting from the end
	 * 			Length.	Number of records to read
	 * 	@note	Records are sent in cronological order.
	 * 	@note	When data is sent, if the length of the data doesn't fit in one
	 * 			message (59 bytes) the data field is splitted. If more thata will
	 * 			be sent the PICC informs with the SW: 0xAF
	 */
	private void readRecords(APDU apdu, byte[] buffer){
		
		receiveAPDU(apdu, buffer);
		byte[] out=null;
		if(commandToContinue==Util.NO_COMMAND_TO_CONTINUE){
			File file= selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
			offset=Util.byteArrayToShort(new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+2],(byte) buffer[ISO7816.OFFSET_CDATA+1]});
			short length=Util.byteArrayToShort(new byte[]{(byte) buffer[ISO7816.OFFSET_CDATA+5],(byte) buffer[ISO7816.OFFSET_CDATA+4]});
			if(file instanceof LinearRecord){
				file=(LinearRecord)selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
				if(((LinearRecord)file).hasReadAccess(authenticated)==false){
					ISOException.throwIt(Util.PERMISSION_DENIED);
				}
				bytesLeft=(short)(length*((LinearRecord)file).recordSize);
				offset=(short)(((LinearRecord)file).getCurrentSize()-offset*((LinearRecord)file).recordSize-bytesLeft);//offset respecto al inicio
				if(bytesLeft<=59){
					out=((LinearRecord)file).readData(offset, bytesLeft, (byte) 0);
					offset=0;
					bytesLeft=0;
					sendResponse(apdu,buffer,out);
				}
				else{
					out=((LinearRecord)file).readData(offset, (byte)59, (byte) 0);
					commandToContinue=Util.READ_RECORDS;
					offset=(short)(offset+59);
					bytesLeft=(short)(bytesLeft-59);
					sendResponse(apdu,buffer,out,Util.CONTINUE);
				}
			}
			if(file instanceof CyclicRecord){
				file=(CyclicRecord)selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
				if(((CyclicRecord)file).hasReadAccess(authenticated)==false){
					ISOException.throwIt(Util.PERMISSION_DENIED);
				}
				
				bytesLeft=(short)(length*((CyclicRecord)file).recordSize);
				offset=(short)(((CyclicRecord)file).getCurrentSize()-offset*((CyclicRecord)file).recordSize-bytesLeft);//offset respecto al inicio
				if(bytesLeft<=59){
					out=((CyclicRecord)file).readData(offset, bytesLeft, (byte) 0);
					offset=0;
					bytesLeft=0;
					sendResponse(apdu,buffer,out);
				}
				else{
					out=((CyclicRecord)file).readData(offset, (byte)59, (byte) 0);
					commandToContinue=Util.READ_RECORDS;
					offset=(short)(offset+59);
					bytesLeft=(short)(bytesLeft-59);
					sendResponse(apdu,buffer,out,Util.CONTINUE);
				}
				
			}
			
		}else {//commandToContinue==Util.READ_RECORDS
			if(selectedFile instanceof LinearRecord){
				if(bytesLeft<=59){
					out=((LinearRecord)selectedFile).readData(offset, bytesLeft, (byte) 0);
					offset=0;
					bytesLeft=0;
					commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
					sendResponse(apdu,buffer,out);
				}
				else{
					out=((LinearRecord)selectedFile).readData(offset, (byte)59, (byte) 0);
					commandToContinue=Util.READ_RECORDS;
					offset=(short)(offset+59);
					bytesLeft=(short)(bytesLeft-59);
					sendResponse(apdu,buffer,out,Util.CONTINUE);
				}
			}
			if(selectedFile instanceof CyclicRecord){
				if(bytesLeft<=59){
					out=((CyclicRecord)selectedFile).readData(offset, bytesLeft, (byte) 0);
					offset=0;
					bytesLeft=0;
					commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
					sendResponse(apdu,buffer,out);
				}
				else{
					out=((CyclicRecord)selectedFile).readData(offset, (byte)59, (byte) 0);
					commandToContinue=Util.READ_RECORDS;
					offset=(short)(offset+59);
					bytesLeft=(short)(bytesLeft-59);
					sendResponse(apdu,buffer,out,Util.CONTINUE);
				}
			}		
		}
	}
	
	/**
	 * 	Resets a Cyclic or Linear Record File to empty state.
	 * 	
	 * 	@note	|| FileN ||	
	 */
	private void clearRecordFile(APDU apdu, byte[] buffer){
		receiveAPDU(apdu, buffer);
		File file= selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
		if(file instanceof LinearRecord){
			file= (LinearRecord) selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
			if(((LinearRecord)file).hasWriteAccess(authenticated)==false){
				ISOException.throwIt(Util.PERMISSION_DENIED);
			}
			((LinearRecord)file).deleteRecords();
			ISOException.throwIt(Util.OPERATION_OK);
		}
		if(file instanceof CyclicRecord){
			file= (CyclicRecord) selectedDF.getFile(buffer[ISO7816.OFFSET_CDATA]);
			if(((CyclicRecord)file).hasWriteAccess(authenticated)==false){
				ISOException.throwIt(Util.PERMISSION_DENIED);
			}
			((CyclicRecord)file).deleteRecords();
			ISOException.throwIt(Util.OPERATION_OK);
		}
	}
	
	/**
	 * 	Validates all previous write access on Backup Data Files, Value Files and 
	 * 	Record Files within one application 
	 */
	private void commitTransaction(APDU apdu, byte[] buffer){
		
		for (byte i = 0; i < 32; i++) {
			if(selectedDF.waitingForTransaction[i]==true){
				//if(directoryFile.getFile(i)instanceof BackupDataFile){
					//FALTA
				//}
				if(selectedDF.getFile(i) instanceof LinearRecord){
					selectedFile=(LinearRecord)selectedDF.getFile(i);
					if(((LinearRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((LinearRecord)selectedFile).commitTransaction();
				}
				if(selectedDF.getFile(i)instanceof CyclicRecord){
					selectedFile=(CyclicRecord) selectedDF.getFile(i);
					if(((CyclicRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((CyclicRecord)selectedFile).commitTransaction();
				}
				if(selectedDF.getFile(i)instanceof ValueRecord){
					selectedFile=(ValueRecord)selectedDF.getFile(i);
					if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((ValueRecord)selectedFile).commitTransaction();
				}
			}
		}
		ISOException.throwIt(Util.OPERATION_OK);
	}
	
	/**
	 * Invalidates all previous write access on Backup Data Files, Value Files and 
	 * 	Record Files within one application
	 */
	private void abortTransaction(APDU apdu,byte[] buffer){
		for (byte i = 0; i < 32; i++) {
			if(selectedDF.waitingForTransaction[i]==true){
//				if(directoryFile.getFile(i) instanceof BackupDataFile){
//					//FALTA
//				}
				if(selectedDF.getFile(i) instanceof LinearRecord){
					selectedFile=(LinearRecord)selectedDF.getFile(i);
					if(((LinearRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((LinearRecord)selectedFile).abortTransaction();
				}
				if(selectedDF.getFile(i) instanceof CyclicRecord){
					selectedFile=(CyclicRecord) selectedDF.getFile(i);
					if(((CyclicRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((CyclicRecord)selectedFile).abortTransaction();
				}
				if(selectedDF.getFile(i) instanceof ValueRecord){
					selectedFile=(ValueRecord)selectedDF.getFile(i);
					if(((ValueRecord)selectedFile).hasWriteAccess(authenticated)==false)ISOException.throwIt(Util.PERMISSION_DENIED);
					((ValueRecord)selectedFile).abortTransaction();
				}
			}
		}
	}
	
	/**
	 * 	Encrypts the message
	 * 
	 * 	@return 	The message encrypted in the following way:
	 * 				- The CRC16 is calculated
	 * 				- The whole array is padded
	 * 				- Everything is encyphered
	 * 	@note 	For the moment it only uses 3DES
	 */
	private byte[] encrypt16(byte[]msg,Key key) {
		
		//CRC16
		byte[] crc=Util.crc16(msg);//16-bit
		msg=Util.concatByteArray(msg, crc);
		//padding
		msg=Util.preparePaddedByteArray(msg);
		//Encypher		
		cipher.init(key, Cipher.MODE_ENCRYPT);
		cipher.doFinal(msg,(short)0,(short)msg.length, msg , (short)0);
		return msg;
	}
	
	/**
	 * 	Decrypts the message
	 * 
	 * 	@return The message decrypted in the following way:
	 * 				- Everything is decyphered
	 * 				- The padding is taken out				
	 * 				- The CRC16 is calculated and compared with the received
	 * 	@note 	For the moment it only uses 3DES
	 */
	private byte[] decrypt16(byte[] encryptedMsg,Key key){
		byte[]msg=new byte[encryptedMsg.length];
		try{
			//Decrypt
			cipher.init(key, Cipher.MODE_DECRYPT);
			cipher.doFinal(encryptedMsg,(short) 0,(short)encryptedMsg.length, msg, (short)0);
			//Padding out
			byte[] data=Util.removePadding(msg);
			//Checks CRC
			byte[] receivedCrc=Util.subByteArray(data, (byte)(data.length-2),(byte) (data.length-1));
			data=Util.subByteArray(data,(byte) 0, (byte)(data.length-3));
			byte[] newCrc=Util.crc16(data);
			if(Util.byteArrayCompare(newCrc,receivedCrc)==false){
				//We check if there was no padding
				receivedCrc=Util.subByteArray(msg, (byte)(msg.length-2),(byte) (msg.length-1));
				msg=Util.subByteArray(msg,(byte) 0, (byte)(msg.length-3));
				newCrc=Util.crc16(msg);
				if(Util.byteArrayCompare(newCrc,receivedCrc)==false){
					securityLevel=Util.PLAIN_COMMUNICATION;
					ISOException.throwIt(Util.INTEGRITY_ERROR);
				}
				return msg;
			}
			return data;
		}catch ( CryptoException e){
			securityLevel=Util.PLAIN_COMMUNICATION;
			ISOException.throwIt(Util.PERMISSION_DENIED);	
		}
		return null;		
	}

	/**
	 * Returns the plain data of the APDU 
	 */
	private byte[] getCData(byte[] cData){
		switch(this.securityLevel){
			case Util.PLAIN_COMMUNICATION:
				return cData;
			case Util.FULLY_ENCRYPTED:
				cData=decrypt16(cData,sessionKey);
				
				return cData;
			default:
				break;
		}
		return null;
	}

	/**
	 * 
	 */
	private void receiveAPDU(APDU apdu, byte[] buffer){
		// Lc tells us the incoming apdu command length
		  short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		  short readCount = apdu.setIncomingAndReceive();
		  while ( bytesLeft > 0){
		      // process bytes in buffer[5] to buffer[readCount+4];
		      bytesLeft -= readCount;
		      readCount = apdu.receiveBytes ( ISO7816.OFFSET_CDATA );
		      }		
		  byte[] cData=getCData(Util.subByteArray(buffer,(byte)ISO7816.OFFSET_CDATA,(byte)(ISO7816.OFFSET_CDATA+buffer[ISO7816.OFFSET_LC]-1)));
		  
		buffer=Util.copyByteArray(cData, (short) 0, (short)cData.length,buffer, (short)ISO7816.OFFSET_CDATA);
		buffer[ISO7816.OFFSET_LC]=(byte) cData.length;
		  
	}

	/**
	 * 
	 */
	private void sendResponse(APDU apdu, byte[] buffer,byte[] response){
		sendResponse(apdu,buffer,response,(byte)0x00);
	}
	
	/**
	 * This is needed for the authentication because the last message should be sended 
	 * encrypted with the old session key and afterwards the session key should change 
	 */
	private void sendResponseAndChangeStatus(APDU apdu, byte[] buffer,byte[] response,byte[] newSessionKey){
		
		// construct the reply APDU
		short le = apdu.setOutgoing();
		// if (le < (short)2) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
		if(response.length==0)ISOException.throwIt( (short)0x917E);//AUX
//			this.securityLevel=Util.PLAIN_COMMUNICATION;
		// build response data in apdu.buffer[ 0.. outCount-1 ];
		switch (this.securityLevel) {
		case Util.PLAIN_COMMUNICATION:
			break;
		case Util.PLAIN_COMMUNICATION_MAC:		
			break;
		case Util.FULLY_ENCRYPTED:
			response=encrypt16(response,sessionKey);
			break;
		default:
			break;
		}
		sessionKey.clearKey();
		((DESKey)sessionKey).setKey(newSessionKey, (byte)0);
		securityLevel=Util.FULLY_ENCRYPTED;
		apdu.setOutgoingLength( (short) response.length );
		for (byte i = 0; i < response.length; i++) {
			buffer[i]=response[i];
		}
		apdu.sendBytes ( (short)0 , (short)response.length );
		return;
	}
		
	private void sendResponse(APDU apdu, byte[] buffer,byte[] response, byte status){
		// construct the reply APDU
		try{
			short le = apdu.setOutgoing();
			// if (le < (short)2) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
			if(response.length==0)ISOException.throwIt( (short)0x917E);//AUX
	//			this.securityLevel=Util.PLAIN_COMMUNICATION;
			// build response data in apdu.buffer[ 0.. outCount-1 ];
			switch (this.securityLevel) {
			case Util.PLAIN_COMMUNICATION:
				break;
			case Util.PLAIN_COMMUNICATION_MAC:		
				break;
			case Util.FULLY_ENCRYPTED:
				response=encrypt16(response,sessionKey);
				break;
			default:
				break;
			}
			apdu.setOutgoingLength( (short) response.length );
			for (byte i = 0; i < response.length; i++) {
				buffer[i]=response[i];
			}
			apdu.sendBytes ( (short)0 , (short)response.length );
		}catch (APDUException e) {
				ISOException.throwIt(e.getReason());
		}
		return;	

//		// construct the reply APDU
////		short le = apdu.setOutgoing();
//		apdu.setOutgoing();
//		// if (le < (short)2) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
//		if(response.length==0)ISOException.throwIt( (short)0x917E);//AUX
////			this.securityLevel=Util.PLAIN_COMMUNICATION;
//		// build response data in apdu.buffer[ 0.. outCount-1 ];
//		switch (this.securityLevel) {
//		case Util.PLAIN_COMMUNICATION:
//			break;
//		case Util.PLAIN_COMMUNICATION_MAC:		
//			break;
//		case Util.FULLY_ENCRYPTED:
//			response=encrypt16(response,sessionKey);
//			break;
//		default:
//			break;
//		}
//		
//		try{
//		
//		apdu.setOutgoingLength( (short) (response.length) );
//		for (byte i = 0; i < response.length; i++) {
//			buffer[i]=response[i];
//		}
//		apdu.sendBytes ((short)0 , (short)(response.length) );
//		}catch (APDUException e) {
//			ISOException.throwIt(e.getReason());
//		}
//		return;
		}
	
	public boolean select(boolean appInstAlreadyActive){
		clear();
		return true;
	}
	public void deselect(boolean appInstStillActive){
		clear();
		return;
	}
	public Key getCurrentKey(){
		if(selectedDF.isMasterFile()==true)return selectedDF.getMasterKey();
		else if(authenticated>0)return selectedDF.getKey(authenticated);
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return null;
		}
	}
	private void clear(){
		selectedFile=null;
		selectedDF=masterFile;
		commandToContinue=Util.NO_COMMAND_TO_CONTINUE;
		authenticated=Util.NO_KEY_AUTHENTICATED;
		dataBuffer=null;
		securityLevel=Util.PLAIN_COMMUNICATION;
		sessionKey.clearKey();	
	}
	
}


