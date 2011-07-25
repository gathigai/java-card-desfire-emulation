package des;

public abstract class File {
	private byte fileID;
	
	// current size of data stored in file
	private byte size;
	protected boolean active = true;
	
	public File(byte fid) {
		fileID = fid;
	}
	public File(byte fid,byte type) {
		fileID = fid;
	}
	public byte getFileID() {
		return fileID;
	}
	public void setActive(boolean b) {
		active = b;
	}
	public byte getSize(){
		return size;
	}
	public void setSize(byte size){
		this.size=size;
	}
}