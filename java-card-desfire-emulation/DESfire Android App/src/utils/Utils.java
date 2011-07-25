package utils;

public class Utils {
	public final static byte PLAIN_COMMUNICATION=(byte)0x00;
	public final static byte PLAIN_COMMUNICATION_MAC=(byte)0x01;
	public final static byte FULLY_ENCRYPTED=(byte)0x02;
	 
	public final static byte SET_ENTITY_RESULT=1;
	
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[(len+1) / 3];
		for (int i = 0; i < len; i += 3) {
			data[i / 3] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
//	public static String hexDump(byte[] data) {
//		return hexDump(data, 0, data.length);
//	}
	public final static String hexChars[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F" };
	
	public static String hexDumpSpaces(byte[] data, int offset, int length) {
		String result = "";
		String part = "";
		for (int i = 0; i < min(data.length, length); i++) {
			if(i!=0) result=result+" ";
			part = hexChars[(byte) (unsignedInt(data[offset + i]) / 16)] + hexChars[(byte) (unsignedInt(data[offset + i]) % 16)];
			result = result + part;
		}
		return result;
	}
	public static String hexDump(byte[] data, int offset, int length) {
		String result = "";
		String part = "";
		for (int i = 0; i < min(data.length, length); i++) {
			part = "" + hexChars[(byte) (unsignedInt(data[offset + i]) / 16)] + hexChars[(byte) (unsignedInt(data[offset + i]) % 16)];
			result = result + part;
			
		}
		return result;
	}
	public static String hexDumpSpaces(byte[] data) {
		return hexDumpSpaces(data, 0, data.length);
	}
	public static String hexDump(byte[] data) {
			return hexDump(data, 0, data.length);
	}
	public static byte[] shortToByteArray(final short value) {
		return new byte[] { (byte) (value >>> 8), (byte) (value) };
	}
	public static byte[] intToByteArray(int value){
		return new byte[]{(byte)(value>>>24),(byte)(value>>>16),(byte)(value>>>8),(byte) value};
	}
	public static int byteArrayToInt(byte[]b){
		return b[0]+b[1]*256+b[2]*65536+b[3]*16777216;
	}
	public static String hexDumpStringRotate(String s){
		return s.substring(3)+" "+s.substring(0,3);
	}
	public static String hexDump(byte data) {
		String result = "";
		result = "" + hexChars[(byte) (unsignedInt(data) / 16)] + hexChars[(byte) (unsignedInt(data) % 16)]+"";
		return result;
	}
	/**
	 * Add spaces to an hexString without them
	 * @param aID
	 * @return
	 */
	public static String addSpaces(String aID) {
		String result="";
		String part="";
		for (int i = 0; i < aID.length(); i=i+2) {
			if(i!=0)part=" "+aID.substring(i,i+2);
			else part=aID.substring(i,i+2);
			result=result+part;
		}
		return result;
	}
	/**
	 * Concats two nibbles in one byte
	 * @param 	m
	 * 			More significant nibble
	 * @param 	l
	 * 			Less significant nibble
	 * @return
	 */
	public static byte twoNibbleToByte(byte m,byte l){
		return (byte)(m<<4|l);
	}
	
	/**
	 * Switchs two bytes
	 * @param 	a
	 * 			Byte array {a,b}
	 * @return
	 * 			Byte array {b,a}
	 */
	public static byte[] switchTwoBytes(byte[]a){
		byte[] result=new byte[2];
		result[0]=a[1];
		result[1]=a[0];
		return result;
	}
	/**
	 * Creates the 3DES Session Key as the DESfire card does in the authentication protocol 
	 * @param a
	 * @param b
	 * @return
	 */
	public static byte[] create3DESSessionKey(byte[]a,byte[] b){
		byte[] result=new byte[16];
		result[0]=a[0];
		result[1]=a[1];
		result[2]=a[2];
		result[3]=a[3];
		result[4]=b[0];
		result[5]=b[1];
		result[6]=b[2];
		result[7]=b[3];
		result[8]=a[4];
		result[9]=a[5];
		result[10]=a[6];
		result[11]=a[7];
		result[12]=b[4];
		result[13]=b[5];
		result[14]=b[6];
		result[15]=b[7];				
		return result;		
	}
	public static byte[] XORByteArrays(byte[] newKey, byte[] oldKey) {
		byte[] result= new byte[newKey.length];
		for (byte i = 0; i < result.length; i++) {
			result[i]=(byte)(newKey[i]^oldKey[i]);
		}
		return result;
		
	}
	
	/**
	 * Makes a new array with a length multiple of 8 padding with 0 on the right
	 * 
	 */
	public static byte[] preparePaddedByteArray(byte[] a){
		
		if((short)(a.length%8)!=(short)0){
			byte[] result=new byte[(short)(a.length+(8-a.length%8))];
			for (short i = 0; i < (short)a.length; i++) {
				result[i]=a[i];
			}
			result[a.length]=(byte)0x80;
			return result;
		}
		else return a;	
	}
	
	/**
	 * Removes the padding to go back to the original data
	 * 
	 * @return If the end of the byte array is 80 00...00
	 * 			returns a cut copy of the original but if the end of the
	 * 			array is not like that returns the whole byte array.
	 */
	public static byte[] removePadding(byte[]a){
		byte aux=(byte)0x00;
		byte i=(byte)(a.length);
		while(aux==(byte)0x00){
			i--;
			aux=a[i];
		}
		if(a[i]!=(byte)0x80) return a;//There was no padding
		return Utils.subByteArray(a,(short) 0,(short)(i-1));
	}
	public static byte[] takeEightBytes(byte[] input,byte offset){
		byte[] result=new byte[8];
		for (int i = 0; i < result.length; i++) {
			result[i]=input[(short)(i+offset)];
		}
		return result;
	}
	public static byte[] switchBytes(byte[] a) {
		byte[] result=new byte[a.length];
		for (int i = 0; i < result.length; i++) {
			result[i]=a[result.length-i-1];
		}
		return result;
	}
	
	public static byte[] crc16(byte[] a){
	    int[] table = {
	        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
	    };
	
	    short crc = 0x0000;
	    for (byte b : a) {
	        crc =(short)( (crc >>> 8) ^ table[(crc ^ b) & 0xff]);
	    }
	
	    System.out.println("CRC16 = " + hexDump(Utils.shortToByteArray(crc)));
	    return Utils.shortToByteArray(crc);
	}
	
	/**
	 * Concats two byte arrays
	 * @param a
	 * @param b
	 * @return	A byte array starting by a and followed by b
	 */
	public static final byte[] concatByteArray(byte[] a,byte[]b){
		byte[] result=new byte[(short)(a.length+b.length)];
		for (short i = 0; i < a.length; i++) {
			result[i]=a[i];
		}
		for (short i = 0; i < b.length; i++) {
			result[(short)(i+a.length)]=b[i];
		}
		return result;
	}
	
	/**
	 * Takes a part of the byte array
	 * 
	 * @param 	input
	 * @param 	inputInit
	 * 			Index of the first byte copied to the subarray
	 * @param 	inputEnd
	 * 			Index of the last byte copied to the subarray
	 * @return
	 */
	public static byte[] subByteArray(byte[]input,short inputInit,short inputEnd){
		byte[] result=new byte[inputEnd-inputInit+1];
		for (int i = inputInit; i<=inputEnd; i++) {
			result[i-inputInit]=input[i];
		}
		return result;
	}
	
	public static int unsignedInt(int a) {
		if (a < 0) {
			return a + 256;
		}
		return a;
	}
	public static int min(int a, int b) {
		if (a < b) {
			return a;
		}
		return b;
	}
	
	public static boolean byteArrayCompare(byte[]a,byte[] b){
		if(a.length!=b.length)return false;
		for (byte i = 0; i < a.length; i++) {
			if(a[i]!=b[i])return false;
		}
		return true;
	}
}
