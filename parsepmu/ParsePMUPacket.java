import java.io.*;
import java.util.Arrays;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.Path;

public class ParsePMUPacket {
	
	private static final String inputFilePath = "/home/ubuntu/programs/C37Example.pcap";
	private static final String outputFilePath = "/testfiles/C37Example.pmu";
	private static final String outputFileDir = "/testfiles";

	private static final int HEADER_OFFSET = 32;
	private static final int TIME_OFFSET = 6;
	private static final int TIME_LENGTH = 4;
	private static final int FRAC_OFFSET = 10;
	private static final int FRAC_LENGTH = 4;
	private static final int FRAME_SIZE_OFFSET = 2;
	private static final int FRAME_SIZE_LENGTH = 2;
	private static long skip_index = 72;
	
	private static FileInputStream inputStream;
	private static byte[] frame; 
	private static FileSystem fs;
	private static int snapshot_index = 0;
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		frame = new byte[200]; 
		
		Configuration conf = new Configuration();
		conf.set("fs.defaultFS", "hdfs://128.84.105.178:50090");
		try {
	        	fs = FileSystem.get(conf);
		} catch (IOException e) {
			e.printStackTrace();
                }
		
		try {
			inputStream = new FileInputStream(inputFilePath);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

		long timeStamp;
		try {
			//cleanDirectory();	
			Path snapshotPath = new Path(outputFileDir);
			while (getNextPacket(frame)) {
				timeStamp = getTimeStamp(frame);
				addRecord(fs, frame);
				System.out.println(timeStamp);
				fs.createSnapshot(snapshotPath, "" + timeStamp);
				snapshot_index++;
			}
		} catch (IOException e) {
			System.out.println(skip_index);
			e.printStackTrace();
		}
	}
	
	private static boolean getNextPacket(byte[] b) throws IOException {
		if (inputStream.skip(skip_index) < 0) {
			return false;
		}
		if (inputStream.read(frame, 0, TIME_OFFSET + TIME_LENGTH + FRAC_OFFSET + FRAC_LENGTH) < 0){
			return false;
		}
		long frameSize = findField(frame, FRAME_SIZE_OFFSET, FRAME_SIZE_LENGTH);
		skip_index = frameSize + 24;
		b = Arrays.copyOfRange(b, 0, (int)frameSize);
		return true;
	}
	
	private static long getTimeStamp(byte[] frame) {
		return getJavaTime(findField(frame, TIME_OFFSET, TIME_LENGTH), findField(frame, FRAC_OFFSET, FRAC_LENGTH), 100000);
	}
	
	private static long findField(byte[] b, int offset, int length){
		String frameSizeHex = "0x";
		for(int i = 0; i < length; i++){
			frameSizeHex += Integer.toHexString(0x000000ff & b[offset + i]);
		}
		return Long.decode(frameSizeHex).longValue();
	}
	
	public static long getJavaTime(long soc, long frac, int timeBase) // SOC*1000 to set the seconds to millisecond correctly, then add the fraction of a second. Only the bottom 32bits from each argument are used
    {      
        return (0x00000000FFFFFFFFl&soc)*1000l+(long)fracToMS(frac, timeBase);
    }
	
	public static int fracToMS(long time, int timeBase) //returns fraction of a second in milliseconds. Only the bottom 24bits from the long are used.
    {       //mask out the upper byte (c37 flags) &0x00ffffff
        return Math.round( ((float)(time&0x0000000000FFFFFFl)/(float)(0x0000000000FFFFFFl&timeBase)) * 1000f );
    }
	
	private static void addRecord(FileSystem fs, byte[] b) throws IOException{
		FSDataOutputStream fsos = fs.append(new Path(outputFilePath));
		DataOutputStream dos = new DataOutputStream(fsos);
		PrintStream ps = new PrintStream(fsos);
		int frameSize = (int)findField(frame, FRAME_SIZE_OFFSET, FRAME_SIZE_LENGTH);
		dos.write(b, 0, frameSize);
		dos.writeInt(snapshot_index);
		dos.writeChar('\n');
		dos.close();
		fsos.close();
	}

	private static void cleanDirectory() throws IOException{
		Path outputPath = new Path(outputFilePath);
		fs.delete(outputPath, false);
		fs.createNewFile(outputPath);
		Path snapshotPath = new Path(outputFileDir);
		for (int i = 0; i < 100; i++) {
			fs.deleteSnapshot(snapshotPath, "Snapshot" + i);
		}
	}

	
}
