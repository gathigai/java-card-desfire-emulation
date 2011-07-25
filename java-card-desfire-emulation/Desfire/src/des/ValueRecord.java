package des;

import des.File;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class ValueRecord extends File {

	// link to parent DF
	private DirectoryFile parentFile;
	// data stored in file
	private Value value;
	// current size of data stored in file
	private Value upperLimit;
	private Value lowerLimit;
	private byte[] permissions;// 2 bytes with the access configuration
	boolean limitedCreditEnabled;
	boolean freeGetValueEnabled;
	Value uncommitedValue;

	
	public ValueRecord(byte fid, DirectoryFile parent,byte[] accessPermissions, Value lowerLimit,Value upperLimit,Value value,byte limitedCreditEnabled) {
		super(fid,Util.VALUE_FILE);
		this.parentFile = parent;
		
		this.permissions=accessPermissions;
		this.upperLimit =upperLimit;
		this.lowerLimit = lowerLimit;
		this.value=value;
		if((limitedCreditEnabled & (byte)0x01)==(byte)0x01)this.limitedCreditEnabled=true;
		else this.limitedCreditEnabled=false;
		if((limitedCreditEnabled & (byte)0x02)==(byte)0x02)this.freeGetValueEnabled=true;
		else this.freeGetValueEnabled=false;
		this.uncommitedValue=this.value;
		parent.addFile(this);
	}
	
	public DirectoryFile getParent() {
		return parentFile;
	}
	
	public short getCurrentSize() {
		if (active == true)
			return 4;
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return 0;
		}
	}
	public Value getValue() {
		if (active == true)
			return value;
		else {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return null;
		}
	}
	public Value getLowerLimit() {
		return lowerLimit;
	}
	public Value getUpperLimit() {
		return upperLimit;
	}
	public byte[] getPermissions(){
		return permissions;
	}
	public boolean valueOutBounds(Value value){
		if(value.compareTo(lowerLimit)==2)return true;
		if(value.compareTo(upperLimit)==1)return true;
		return false;
	}
	public void addCredit(Value credit){
		//Cuidado con el overflow
		//FALTA
		
		Value newValue=this.uncommitedValue;
		if(newValue.addValue(credit)==false) ISOException.throwIt((short)0x91BE);//Exception if the operation finishes with overflow
		if(valueOutBounds(newValue)==true) ISOException.throwIt((short)0x919E);
		this.uncommitedValue=newValue;
		parentFile.waitingForTransaction[this.getFileID()]=true;
		return ;
	}
	
	public void decDebit(Value debit){
		Value newValue=this.uncommitedValue;
		if(newValue.subtractValue(debit)==false) ISOException.throwIt((short)0x919E);
		if(valueOutBounds(newValue)==true) ISOException.throwIt((short)0x919E);
		this.uncommitedValue=newValue;
		parentFile.waitingForTransaction[this.getFileID()]=true;
		return;
	}
	public void commitTransaction(){
		parentFile.waitingForTransaction[this.getFileID()]=false;
		this.value=uncommitedValue;
	}
	public void abortTransaction(){
		parentFile.waitingForTransaction[this.getFileID()]=false;
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