package des;

	import org.bouncycastle.crypto.MaxBytesExceededException;

import des.File;

	import javacard.framework.ISO7816;
import javacard.framework.ISOException;


	public class LinearRecord extends File {
		// link to parent DF
	private DirectoryFile parentFile;
	// data stored in file
	private byte[] data;
	// current size of data stored in file
	short size;
	short maxSize;
	short recordSize;
	byte[] uncommitedRecord;
	boolean waitingToDeleteRecord;
	private byte[] permissions;// 2 bytes with the access configuration
	
	public LinearRecord(byte fid, DirectoryFile parent,byte[] accessPermissions, short recordSize, short maxSize) {
		super(fid,Util.LINEAR_RECORD_FILE);
		this.parentFile = parent;
		this.permissions=accessPermissions;
		this.data = new byte[(short)(maxSize*recordSize)];
		this.size = (short) 0;
		this.recordSize=recordSize;
		this.maxSize=maxSize;
		this.uncommitedRecord=new byte[recordSize];
		this.waitingToDeleteRecord=false;
		parent.addFile(this);
	}
	public DirectoryFile getParent() {
		return parentFile;
	}
	public byte[] getData() {
		if (active == true)
			return data;
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return null;
		}
	}
	public short getCurrentSize() {
		if (active == true)
			return size;
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return 0;
		}
	}
	public short getMaxSize() {
		return (short) data.length;
	}
	public void eraseData() {
		for (short i = 0; i < data.length; i++) {
			data[i]=0;
		}
	}
	public void deleteRecord(){
		//No se puede borrar hasta que la transaccion se compromete
		parentFile.waitingForTransaction[this.getFileID()]=true;
		this.waitingToDeleteRecord=true;
	}
	public void deleteRecords(){
		eraseData();
		size=0;
	}
	
	public void writeRecord(byte[] newData) {
		
		if(size==maxSize)ISOException.throwIt((short)0x91BE);
		if(newData.length>=recordSize) ISOException.throwIt((short)0x91BE);
		if(waitingToDeleteRecord==true)ISOException.throwIt((short)0x910C);
		parentFile.waitingForTransaction[this.getFileID()]=true;
		// copy new data in temporal record
		for (short i = 0; i < recordSize; i++) {
			this.uncommitedRecord[i]=newData[i];
			if(i>=newData.length)this.uncommitedRecord[i]=(byte)0x00;
		}		
	}
	public void writeRecord(byte[] newData,short offset) {
			
		if(size==maxSize)ISOException.throwIt((short)0x91BE);
		if((short)(newData.length+offset)>=recordSize) ISOException.throwIt((short)0x91BE);
		if(waitingToDeleteRecord==true)ISOException.throwIt((short)0x910C);
		parentFile.waitingForTransaction[this.getFileID()]=true;
		// copy new data in temporal record
		for (short i = 0; i < recordSize; i++) {
			if(i<offset)this.uncommitedRecord[i]=(byte)0x00;
			this.uncommitedRecord[i]=newData[i];
			if(i>=newData.length)this.uncommitedRecord[i]=(byte)0x00;
		}
	}
	public void commitTransaction(){
		parentFile.waitingForTransaction[this.getFileID()]=false;
		if(waitingToDeleteRecord==true){
			waitingToDeleteRecord=false;
			for (short i = (short)(size*recordSize); i <(short)((size+1)*recordSize); i++) {
				this.data[i]=(byte)0x00;						
			}
			size--;
		}else{//uncommited transaction
			for (short i = (short)(size*recordSize); i <(short)((size+1)*recordSize); i++) {
				this.data[i]=uncommitedRecord[i];
			}
	//			update size
			size++;
		}
	}
	public void abortTransaction(){
		parentFile.waitingForTransaction[this.getFileID()]=false;
		waitingToDeleteRecord=false;
	}
	
	public byte[] readValue(){
		byte[] value= new byte[recordSize];
		for (short i = 0; i < recordSize; i++) {
			value[i]=data[(short)(i+(size-1)*recordSize)];//Size apunta al siguiente al último escrito
		}
		return(value);
	}
	public byte[] readData(short offset, short length, byte offsetOut){
		
			byte[] bytesRead=new byte[length];
			for (short i = 0; i < length; i++) {
				bytesRead[(short)(offsetOut+i)]=data[(short)(offset+i)];				
			}
			
			return(bytesRead);
	}
		
	
	public byte[] getPermissions(){
		return permissions;
	}
	public byte getAccessRight(byte keyNumber){
		//Responde que tipo de acceso permite ese fichero para esa clave.
		/*****************      FUNCIONAMIENTO DE LAS CLAVES DE ACCESO    ******************
		    Tenemos un nibble de 2 bytes y cada 4 bits indican que clave permite ese acceso concreto:
		    
		    Read - Write - W&R - Change
		    
		    Por tanto es necesario tener una clave concreta para poder realizar una de esas operaciones.
	*/
		if(((permissions[1])&((byte)0x0F))==(byte)keyNumber)return((byte) 4);//CHANGE
		if(((permissions[1])&((byte)0x0F))==(byte)0x0E)return((byte) 4);//CHANGE
		if(((permissions[1])&((byte)0xF0))==(byte)(keyNumber<< 4))return((byte) 3);//W&R
		if(((permissions[1])&((byte)0xF0))==(byte)0xE0)return((byte) 3);//W&R
		if(((permissions[0])&((byte)0x0F))==(byte)keyNumber)return((byte) 2);//WRITE
		if(((permissions[0])&((byte)0x0F))==(byte)0x0E)return((byte) 2);//WRITE
		if(((permissions[0])&((byte)0xF0))==(byte)(keyNumber<< 4))return((byte) 1);//READ
		if(((permissions[0])&((byte)0xF0))==(byte)0xE0)return((byte) 1);//READ
//			if((((byte)(keyNumber << 4))&(permissions[1])& ((byte)0x0F))==(byte)0xFF)return((byte) 3);//W&R
//			if((((byte)keyNumber)&(permissions[0])& ((byte)0x0F))==(byte)0xFF)return((byte) 2);//WRITE
//			if((((byte)(keyNumber << 4))&(permissions[0])& ((byte)0x0F))==(byte)0xFF)return((byte) 1);//READ	
		return((byte)0);
	}
	public boolean hasWriteAccess(byte keyNumber){
		
		if(((permissions[0])&((byte)0x0F))==(byte)keyNumber)return(true);//WRITE
		if(((permissions[0])&((byte)0x0F))==(byte)0x0E)return(true);//WRITE			
		if(((permissions[1])&((byte)0xF0))==(byte)(keyNumber<< 4))return(true);//W&R			
		if(((permissions[1])&((byte)0xF0))==(byte)0xE0)return(true);//W&R
		return(false);
	}
	public boolean hasReadAccess(byte keyNumber){
		if(((permissions[0])&((byte)0xF0))==(byte)(keyNumber<< 4))return(true);//READ
		if(((permissions[0])&((byte)0xF0))==(byte)0xE0)return(true);//READ
		if(((permissions[1])&((byte)0xF0))==(byte)(keyNumber<< 4))return(true);//W&R
		if(((permissions[1])&((byte)0xF0))==(byte)0xE0)return(true);//W&R
		return(false);
	}
	
}