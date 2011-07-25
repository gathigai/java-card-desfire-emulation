package des;

import des.File;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class IndexFile extends File{
	// link to parent DF
	private DirectoryFile parentFile;
	// data stored in file
	private byte[] data;
	// current size of data stored in file
	short size;
	short recordSize;
	private byte[] permissions;// 2 bytes with the access configuration
	
	public IndexFile(byte fid, DirectoryFile parent,byte[] accessPermissions, byte[] d) {
		super(fid);
		parentFile = parent;
		parent.addFile(this);
		permissions=accessPermissions;
		data = d;
		size = (short) d.length;
	}
	public IndexFile(byte fid, DirectoryFile parent,byte[] accessPermissions, short recordSize, short maxSize) {
		super(fid);
		this.parentFile = parent;
		this.parentFile.addFile(this);
		this.permissions=accessPermissions;
		this.data = new byte[(short)(maxSize*recordSize)];
		this.size = (short) 0;
		this.recordSize=recordSize;
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
	
	public void eraseData(short offset) {
		for (short i = 0; i < data.length; i++) {
			data[i]=0;
		}
	}
	public void deleteRecord(short index){
		for (short i = (short)(index*recordSize); i <(short)((index+1)*recordSize); i++) {
			this.data[i]=(byte)0x00;						
		}
		size--;
		
	}
	public void writeRecord(short index, byte[] newData) {
		
		 if(newData.length!=recordSize) ISOException.throwIt((short)0xBB01); 
		// update size
		size++;
		
		// copy new data
		for (short i = (short)(index*recordSize); i <(short)((index+1)*recordSize); i++) {
			this.data[i]=newData[(short)(i-index*recordSize)];						
		}		
		//Util.arrayCopy(newData, 0, data, index*recordSize, recordSize);
	}
	public byte[] readValue(short index){
		byte[] value= new byte[recordSize];
		for (short i = 0; i < recordSize; i++) {
			value[i]=data[(short)(i+index*recordSize)];
		}
		return(value);
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
