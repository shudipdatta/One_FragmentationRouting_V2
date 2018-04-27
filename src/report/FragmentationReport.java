package report;

import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

public class FragmentationReport extends Report {
	
	DecimalFormat df;
	int avgKeyPossession;
	long avgTimeDelayMPE;
	long avgTimeDelayOur;
	int[] delayDistMPE;
	int[] delayDistOur;

	public static int totalMsgCreate;
	public static long totalEncodeTime;
	
	public static int totalMsgSent;
	public static int totalMsgReceived;
	public static int totalEmptyPacket;
	public static int tatalCorruptedKeyReceived;
	public static int tatalCorruptedMsgReceived;
	public static int tatalUncorruptedKeyReceived;
	public static int tatalUncorruptedMsgReceived;
	public static int totalKeyShareSent;
	public static int totalDataFragSent;
	
	public static int totalKeyReceived;
	public static int totalDataReceived;
	
	public static int totalFileDecoded;
	public static long totalDecodeTime;
	public static long totalFileSkippedDecode;
	public static int totalFileReceived;
	public static int totalFileSent;
	public static int totalCorruptedFileReceived;
	
	public static long totalCompromisedFileMPE;
	public static int totalCompromisedFileOur;
	
	public static long shareEncodeTime;
	public static long shareDecodeTime;
	
	public static long cryptoTime;
	public static long cryptoTimeExtra;
	
	public static long integrityComputationTimeInSender;
	public static long integrityComputationTimeInReceiver;
	
	
	public static int totalHighPriorityFileSent;
	public static int totalMedPriorityFileSent;
	public static int totalLowPriorityFileSent;
	
	public static int totalHighPriorityFileReceived;
	public static int totalMedPriorityFileReceived;
	public static int totalLowPriorityFileReceived;
	
	public static int totalHopCount;
	
	public static HashMap<Integer, Integer> totalPublicKeyReceived;
	public static HashMap<String, Double> fileSentTime;
	public static HashMap<String, Double> fileRcvdTimeMPE;
	public static HashMap<String, Double> fileRcvdTimeOur;
	
	
	public FragmentationReport() {
		super.init();
	}
	
	public static void Initialize() {
		
		totalMsgCreate = 0;
		totalEncodeTime = 0;
		
		totalMsgSent = 0;
		totalMsgReceived = 0;
		totalEmptyPacket = 0;
		tatalCorruptedKeyReceived = 0;
		tatalCorruptedMsgReceived = 0;
		tatalUncorruptedKeyReceived = 0;
		tatalUncorruptedMsgReceived = 0;
		totalKeyShareSent = 0;
		totalDataFragSent = 0;
		
		totalKeyReceived = 0;
		totalDataReceived = 0;
		
		totalFileDecoded = 0;
		totalDecodeTime = 0;
		totalFileSkippedDecode = 0;
		totalFileReceived = 0;
		totalFileSent = 0;
		totalCorruptedFileReceived = 0;
		
		totalCompromisedFileMPE = 0;
		totalCompromisedFileOur = 0;
		
		shareEncodeTime = 0;
		shareDecodeTime = 0;
		
		cryptoTime = 0;
		cryptoTimeExtra = 0;
		
		integrityComputationTimeInSender = 0;
		integrityComputationTimeInReceiver = 0;
		
		
		totalHighPriorityFileSent = 0;
		totalMedPriorityFileSent = 0;
		totalLowPriorityFileSent = 0;
		
		totalHighPriorityFileReceived = 0;
		totalMedPriorityFileReceived = 0;
		totalLowPriorityFileReceived = 0;
		
		totalHopCount = 0;
		
		totalPublicKeyReceived = new HashMap<Integer, Integer>();	
		fileSentTime = new HashMap<String, Double>();
		fileRcvdTimeMPE = new HashMap<String, Double>();
		fileRcvdTimeOur = new HashMap<String, Double>();
	}
	
	private void CalculateSummary() {

		df = new DecimalFormat(".##"); 
		avgKeyPossession = 0;
		avgTimeDelayMPE = 0;
		avgTimeDelayOur = 0;
		
		//calculating avg key possession
		int totalKeyReceivedSize = totalPublicKeyReceived.size();
		Iterator<Entry<Integer, Integer>> it = totalPublicKeyReceived.entrySet().iterator();
	    while (it.hasNext()) {
	    	@SuppressWarnings("rawtypes")
			HashMap.Entry pair = (HashMap.Entry)it.next();
	    	avgKeyPossession += (int) pair.getValue();
	    	it.remove(); // avoids a ConcurrentModificationException
	    }
	    avgKeyPossession/=totalKeyReceivedSize;
	    
	    //calculating time delay
	    int fileSentStart = 150000;
	    int fileReceiveEnd = 800000;
	    int delayInterval = 25000; 
	    int delaySlot = (fileReceiveEnd-fileSentStart)/delayInterval; //(800000-150000)/50000;
	    delayDistMPE = new int[delaySlot];
	    delayDistOur = new int[delaySlot];
	    for(int i=0; i<delaySlot; i++) {
	    	delayDistMPE[i] = 0;
	    	delayDistOur[i] = 0;
	    }	
	    
	    int fileRcvdTimeMPESize = fileRcvdTimeMPE.size();
	    Iterator<Entry<String, Double>> itMPE = fileRcvdTimeMPE.entrySet().iterator();
	    while (itMPE.hasNext()) {
	    	@SuppressWarnings("rawtypes")
			HashMap.Entry pair = (HashMap.Entry)itMPE.next();
	    	double timeDelayMPE = ((Double) pair.getValue() - fileSentTime.get(pair.getKey()) );
	    	avgTimeDelayMPE += timeDelayMPE;
	    	delayDistMPE[(int)timeDelayMPE/delayInterval]++;
	    	itMPE.remove(); // avoids a ConcurrentModificationException
	    }
	    avgTimeDelayMPE/=fileRcvdTimeMPESize;
	    
	    int fileRcvdTimeOurSize = fileRcvdTimeOur.size();
	    Iterator<Entry<String, Double>> itOur = fileRcvdTimeOur.entrySet().iterator();
	    while (itOur.hasNext()) {
	    	@SuppressWarnings("rawtypes")
			HashMap.Entry pair = (HashMap.Entry)itOur.next();
	    	double timeDelayOur = ((Double) pair.getValue() - fileSentTime.get(pair.getKey()) );
	    	avgTimeDelayOur += timeDelayOur;
	    	delayDistOur[(int)timeDelayOur/delayInterval]++;
	    	itOur.remove(); // avoids a ConcurrentModificationException
	    }
	    avgTimeDelayOur/=fileRcvdTimeOurSize;
	}
	
	@Override
	public void done() {
		
		CalculateSummary();
		
		String statsText = 
				"\ntotalMsgCreate:\t" + totalMsgCreate + 
				"\ntotalMsgSent:\t" + totalMsgSent +
				"\ntotalMsgReceived:\t" + totalMsgReceived + 
				"\ntotalCorruptedKeyReceived:\t" + tatalCorruptedKeyReceived +
				"\ntotalCorruptedMsgReceived:\t" + tatalCorruptedMsgReceived +
				"\ntotalUncorruptedKeyReceived:\t" + tatalUncorruptedKeyReceived +
				"\ntotalUncorruptedMsgReceived:\t" + tatalUncorruptedMsgReceived +
				"\ntotalEmptyPacket:\t" + totalEmptyPacket +
				"\ntotalKeyShareSent:\t" + totalKeyShareSent +
				"\ntotalDataFragSent:\t" + totalDataFragSent +
				
				"\ntotalKeyReceived:\t" + totalKeyReceived + 
				"\ntotalDataReceived:\t" + totalDataReceived +
				
				"\ntotalFileDecoded:\t" + totalFileDecoded + 
				"\ntotalFileSkippedDecode:\t" + totalFileSkippedDecode +
				"\ntotalFileSent:\t" + totalFileSent +
				"\ntotalFileReceived:\t" + totalFileReceived +
				"\ntotalCorruptedFileReceived:\t" + totalCorruptedFileReceived +
				
				"\ntotalCompromisedFileMPE:\t" + totalCompromisedFileMPE +
				"\ntotalCompromisedFileOur:\t" + totalCompromisedFileOur +
			
				"\nhighPriorityFileReceived:\t" + df.format((totalHighPriorityFileReceived / (1.0 * totalHighPriorityFileSent)) * 100) + "%" +
				"\nmediumPriorityFileReceived:\t" + df.format((totalMedPriorityFileReceived / (1.0 * totalMedPriorityFileSent)) * 100) + "%" +
				"\nlowPriorityFileReceived:\t" + df.format((totalLowPriorityFileReceived / (1.0 * totalLowPriorityFileSent)) * 100) + "%" +
				
				"\nshareEncodeTime:\t" + df.format(shareEncodeTime/1000.00) + //microsecond
				"\nshareDecodeTime:\t" + df.format(shareDecodeTime/1000.00) + //microsecond				
				"\ntotalEncodeTime:\t" + df.format(totalEncodeTime/1000.00) + //microsecond
				"\ntotalDecodeTime:\t" + df.format(totalDecodeTime/1000.00) + //microsecond
				"\ncryptoTime:\t" + df.format(cryptoTime/1000.00) + //microsecond
				"\ncryptoTimeExtra:\t" + df.format(cryptoTimeExtra/1000.00) + //microsecond	
				"\nintegrityComputationTimeInSender:\t" + integrityComputationTimeInSender/1000.00 + //microsecond
				"\nintegrityComputationTimeInReceiver:\t " + integrityComputationTimeInReceiver/1000.00 + //microsecond
				
				"\ntotalHopCount:\t" + totalHopCount +
				"\navgKeyPossession:\t" + avgKeyPossession +
				
				"\navgTimeDelayMPE:\t" + df.format(avgTimeDelayMPE) +
				"\navgTimeDelayOur:\t" + df.format(avgTimeDelayOur)
				;
		statsText += "\nDelayDistMPE:\t";
		for(int i=0; i<delayDistMPE.length; i++) statsText+= "\t" + delayDistMPE[i];
		statsText += "\nDelayDistOur:\t";
		for(int i=0; i<delayDistOur.length; i++) statsText+= "\t" + delayDistOur[i];
		
		
		write(statsText);
		super.done();
	}
}
