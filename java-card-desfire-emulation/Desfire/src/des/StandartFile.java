package des;

import des.File;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class StandartFile extends File {
		// link to parent DF
	private DirectoryFile parentFile;
	// data stored in file
	private byte[] data;
	
	
	private byte[] permissions;// 2 bytes with the access configuration
	
	public StandartFile(byte fid, DirectoryFile parent,byte[] accessPermissions, byte[] d) {
		super(fid,Util.STANDARD_DATA_FILE);
		parentFile = parent;
		permissions=accessPermissions;
		data = d;
		setSize((byte) d.length);
		parent.addFile(this);
	}
	public StandartFile(byte fid, DirectoryFile parent,byte[] accessPermissions, short maxSize) {
		super(fid,Util.STANDARD_DATA_FILE);
		parentFile = parent;
		permissions=accessPermissions;
		data = new byte[maxSize];
		setSize((byte) 0);
		parent.addFile(this);
		
	}
	public DirectoryFile getParent() {
		return parentFile;
	}
	public byte getFileID(){
		return super.getFileID();
	}
	public byte[] getData() {
		if (active == true)
			return data;
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return null;
		}
	}
	
	public short getMaxSize() {
		return (short) data.length;
	}
	public byte[] getPermissions(){
		return permissions;
	}
	
	public byte[] readArray(short offset, short length, byte offsetOut){
		byte[] bytesRead=new byte[length];
		for (short i = 0; i < length; i++) {
			bytesRead[(short)(offsetOut+i)]=data[(short)(offset+i)];				
		}
		
		return(bytesRead);
	}
	
	public void writeArray(byte[] data, short offset, short length){
		
		for (short i = 0; i < length; i++) {
			this.data[(short)(offset+i)]=data[i];				
		}
		setSize((byte) Util.max(getSize(),(short) (offset+length)));
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
//		if((((byte)(keyNumber << 4))&(permissions[1])& ((byte)0x0F))==(byte)0xFF)return((byte) 3);//W&R
//		if((((byte)keyNumber)&(permissions[0])& ((byte)0x0F))==(byte)0xFF)return((byte) 2);//WRITE
//		if((((byte)(keyNumber << 4))&(permissions[0])& ((byte)0x0F))==(byte)0xFF)return((byte) 1);//READ	
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
	
