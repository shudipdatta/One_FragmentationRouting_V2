package datahandler;

public class Constant {

	public static final int INFINITE = 99999999;
	public static final int keyByteLenght = 32;//32byte
	public static final int dataByteLenght = 262144*2;//256 KB
	public static final String inputFile = "input_msg.txt";
	
	public static final String filesToSend = "files_to_send";
	public static final int wordSize = 8;
	public static final int packetSize = dataByteLenght/wordSize;

	
	public static final double highDataFactorKN = 2.0;
	public static final double medDataFactorKN = 1.5;
	public static final double lowDataFactorKN = 1.25;

	public static final double highDataFactorWait = 1.0;
	public static final double medDataFactorWait = 1.5;
	public static final double lowDataFactorWait = 2.0;
	public static final int waitTimeInSecond = 40;
	public static final int sleepTimeInSecond = 4;
}
