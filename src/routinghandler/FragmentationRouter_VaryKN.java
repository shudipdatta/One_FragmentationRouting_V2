package routinghandler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Random;

import datahandler.Constant;
import datahandler.ErasureCodec;
import keyhandler.AEScrypto;
import report.FragmentationReport;
import keyhandler.ImageFileSizeReducer;
import keyhandler.MarkleHashTree;
import keyhandler.RSecretShare;
import keyhandler.SecretShare;
import routing.FragmentationRouter;
import routing.FragmentationRouter.Chunk;

public class FragmentationRouter_VaryKN {
	FragmentationRouter router;
	
	public FragmentationRouter_VaryKN(FragmentationRouter router) {
		this.router = router;
	}
	/*
	 * Initialize all key and data; Defining the simulation
	 */
	public void Initialize() {	
		//Generate key shares and data shares from the input file using AES cryptography
		try {
			router.aes = new AEScrypto();
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		router.rss = new RSecretShare(router.keyShareK, router.keyShareN);
		try (BufferedReader br = new BufferedReader(new FileReader(Constant.filesToSend+"/"+Constant.inputFile))) {
		    String line;
		    while ((line = br.readLine()) != null) {	
		    	try {
			       String strfrom = line.split("\t")[0];
			       if(Integer.parseInt(strfrom) == router.getHost().getAddress()) {
					   try {
						   String strto = line.split("\t")[1];
					       String strdata = line.split("\t")[2];
					       switch(router.fileSize) {
					       case "small":
					    	   strdata = "a.jpg";
					    	   break;
					       case "medium":
					    	   strdata = "b.jpg";
					    	   break;
					       case "large":
					    	   strdata = "c.jpg";
					       case "xlarge":
					    	   strdata = "d.jpg";
					    	   break;
					       }
					       //get the file found in the inputfile.txt data
					       ImageFileSizeReducer.reduceImageQuality(Constant.filesToSend + "/" + strdata, Constant.filesToSend + "/" + strdata);
					       byte [] buffer =null;
					       File dataFile = new File(Constant.filesToSend + "/" + strdata);
					       try {
					    	   FileInputStream fis = new FileInputStream(Constant.filesToSend + "/" + strdata);
					    	   int length = (int)dataFile.length();
					    	   buffer = new byte [length];
					    	   fis.read(buffer);
					    	   fis.close();
					       } catch(IOException e) {
					    	   e.printStackTrace();
					       }
					       
					       int to = Integer.parseInt(strto);
					       if(router.chunkToSend.containsKey(to) == false) {
						       router.chunkToSend.put(to, new ArrayList<Chunk>());
						       router.chunkToSendCounter.put(to, 0);
						       router.chunkToSendBlockCounter.put(to, 0);
					       }
					           
					       //32 byte symmetric key
					       byte[] key = router.aes.GenerateKey();
					       byte[] value = new byte[buffer.length];
					       System.arraycopy(buffer, 0, value, 0, buffer.length);
					       //encrypt the whole data with the key
					       byte[] encVal = router.aes.Encrypt(key, value);
					       
					       long startTime = router.getUserTime();
					       //divide the encrypted data with byteLenght chunk
					       byte[][] dataChunks = divideArray(encVal,Constant.dataByteLenght);
					       //fix data fragment k and n
					       int dataFragmentK = dataChunks.length;
					       int dataFragmentN;
					       int priority = Integer.parseInt(line.split("\t")[3]);
					       switch(priority) {
					       case 1:
					    	   dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.highDataFactorKN);
					    	   break;
					       case 3:
					    	   dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.lowDataFactorKN);
					    	   break;
					       default:
					    	   dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.medDataFactorKN);
					    	   break;
					       }
					       //creating encoded data fragments.
					       ErasureCodec codec = new ErasureCodec.Builder(ErasureCodec.Algorithm.Cauchy_Reed_Solomon)
						            .dataBlockNum(dataFragmentK)
						            .codingBlockNum(dataFragmentN-dataFragmentK)
						            .wordSize(Constant.wordSize)
						            .packetSize(Constant.packetSize)
						            .good(true)
						            .build();
					       byte[][] codedChunks = codec.encode(dataChunks);
					       long endTime = router.getUserTime();
					       long diffTime = endTime - startTime;
					       //Report Class
					       FragmentationReport.totalEncodeTime += diffTime;
					       
					       //creating key shares
					       BigInteger[] hiddenInfo = new BigInteger[router.keyShareK-2];
					       
					       byte[] firstInfo = new byte[Constant.keyByteLenght];
					       System.arraycopy(router.pubKey, 0, firstInfo, 0, firstInfo.length);
					       hiddenInfo[0] = new BigInteger(1, firstInfo);
					       
					       byte[] SecondInfo = new byte[Constant.keyByteLenght];
					       System.arraycopy(router.pubKey, SecondInfo.length, SecondInfo, 0, 8);
					       System.arraycopy(strdata.getBytes(), 0, SecondInfo, 8, strdata.getBytes().length);
					       System.arraycopy(ByteBuffer.allocate(8).putInt(dataFragmentK).array(), 0, SecondInfo, 16, 8);
					       System.arraycopy(ByteBuffer.allocate(8).putInt(priority).array(), 0, SecondInfo, 24, 8);
					       hiddenInfo[1] = new BigInteger(1, SecondInfo);
					       
					       for(int i=2; i<hiddenInfo.length; i++){
					    	   byte[] b = new byte[Constant.keyByteLenght];
					    	   new Random().nextBytes(b);
					    	   hiddenInfo[i] = new BigInteger(1, b);
					       } 
					       startTime = router.getUserTime();
					       SecretShare[] shares = router.rss.CreateShare(new BigInteger(1, key), hiddenInfo);
					       endTime = router.getUserTime();
					       diffTime = endTime - startTime;
					       FragmentationReport.shareEncodeTime += diffTime;
					       //calculate markle hash tree with the share
					       startTime = router.getUserTime();
					       MarkleHashTree hashTree = new MarkleHashTree(this.router);
					       ArrayList<byte[]> keyShares = new ArrayList<byte[]>();
					       for(int i=0; i<shares.length; i++) {
					    	   byte[] thisShare = shares[i].getShare().toByteArray();
					    	   byte[] keyShare = new byte[Constant.keyByteLenght];
					    	   if(thisShare.length >= Constant.keyByteLenght)  {
					    		   //keyShare = Arrays.copyOfRange(thisShare, thisShare.length-Constant.keyByteLenght, thisShare.length);
					    		   System.arraycopy(thisShare, thisShare.length-Constant.keyByteLenght, keyShare, 0, keyShare.length);
					    	   }
					    	   else{
					    		   //keyShare = Arrays.copyOfRange(thisShare, 0, Constant.keyByteLenght);
					    		   System.arraycopy(thisShare, 0, keyShare, Constant.keyByteLenght-thisShare.length, thisShare.length);
					    	   }
					    	   System.arraycopy(router.aes.Hash(keyShare),0, hashTree.leafNodes.get(i).hash, 0, AEScrypto.hashLenght);
					    	   byte[] fullKeyShare = new byte[Constant.keyByteLenght+AEScrypto.hashLenght*router.treeHeight];
					    	   System.arraycopy(keyShare, 0, fullKeyShare, 0, Constant.keyByteLenght);
					    	   keyShares.add(fullKeyShare);
					       }
					       hashTree.CalculateHash(hashTree.root);
					       //append the shares with additional hashes
					       for(int i=0; i<keyShares.size(); i++) {
					    	   MarkleHashTree.TreeNode node = hashTree.leafNodes.get(i);
					    	   for(int j=0; j<router.treeHeight; j++) {
									System.arraycopy(node.sibling.hash, 0, keyShares.get(i), 32+j*AEScrypto.hashLenght, AEScrypto.hashLenght);
									node=node.parent;
								}
					       }
					       endTime = router.getUserTime();
					       diffTime = endTime - startTime;
					       FragmentationReport.integrityComputationTimeInSender += diffTime;
					       //store this key shares
					       int i;
					       for(i=0; i<shares.length; i++){
					    	   router.chunkToSend.get(to).add(
					    			   	router.new Chunk("K", 
					    	   				router.chunkToSendBlockCounter.get(to) + "_" + shares[i].getNumber(), 
					    	   				keyShares.get(i),
					    	   				priority
					    	   			));
					       }//Report class
					       FragmentationReport.totalMsgCreate += i;
					       
					       //store the data fragments.
					       for(i=0; i<dataChunks.length; i++){
					    	   router.chunkToSend.get(to).add(
					    			   	router.new Chunk("M", 
					    	   				router.chunkToSendBlockCounter.get(to) + "_" + i, 
					    	   				dataChunks[i],
					    	   				priority
					    	   			));
					       }
					      
					       //store the encoded fragments.
					       for(int j=0; j<codedChunks.length; j++,i++){
					    	   router.chunkToSend.get(to).add(
					    			   	router.new Chunk("M", 
					    	   				router.chunkToSendBlockCounter.get(to) + "_" + i, 
					    	   				codedChunks[j],
					    	   				priority
					    	   			));
					       }
					       
					       //Report class
					       FragmentationReport.totalMsgCreate += i;
					       
					       //increase the blockcounter if same source and destination block is found later then it will be useful
					       router.chunkToSendBlockCounter.put(to, router.chunkToSendBlockCounter.get(to)+1);
					       //report info
					       FragmentationReport.totalFileSent++;
					   } 
					   catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
					   }
			       } 
		    	} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		    }
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	/*
	 * 
	 */
	private byte[][] divideArray(byte[] source, int chunksize) {

		int actualRows = (int)Math.ceil(source.length / (double)chunksize);		
        byte[][] ret = new byte[actualRows][chunksize];
        
        int start = 0;
        for(int i = 0; i < actualRows; i++) {
            if(start + chunksize > source.length) {
                System.arraycopy(source, start, ret[i], 0, source.length - start);
            } else {
                System.arraycopy(source, start, ret[i], 0, chunksize);
            }
            start += chunksize ;
        }
        return ret;
    }
	/*
	 * 
	 */
	public void storeReceivedDataFragments(int index, int seq, byte[] content, int sender, byte[] signature, byte[] srcKey) {
		
		if ( (router.keyReceived.get(sender).containsKey(index) && router.dataReceived.get(sender).containsKey(index)) && 
				 (router.keyReceived.get(sender).get(index) == null && router.dataReceived.get(sender).get(index) == null) ) {
			return;
		}
		
		if(!router.dataFragmentReceived.get(sender).containsKey(index)) {
			router.dataFragmentReceived.get(sender).put(index, new ArrayList<SecretShare>());
		}
		
		try {
		
			if(seq != -1) {
				//store any data fragment
				SecretShare fragment = new SecretShare(seq, new BigInteger(1, content));
				fragment.setSignature(signature);
				
				if(router.threadExistenceCheck.contains(String.valueOf(sender) +  "_" + String.valueOf(index))) { // i mean now i know the key
//					byte[] key = new byte[2*router.ec.keySizeInByte];
//					byte[] firstInfo = router.keyReceived.get(sender).get(index)[1].toByteArray();
//					System.arraycopy(firstInfo, firstInfo.length > FragmentationRouter.keyByteLenght ? 1:0, key, 0, FragmentationRouter.keyByteLenght);
//					byte[] secondInfo = router.keyReceived.get(sender).get(index)[2].toByteArray();
//					System.arraycopy(secondInfo, secondInfo.length > FragmentationRouter.keyByteLenght ? 1:0, key, FragmentationRouter.keyByteLenght, key.length - FragmentationRouter.keyByteLenght);
					long startTime = router.getUserTime();
					boolean notCorrupted = router.ecpre.VerifySignature(content, signature, srcKey);
					long endTime = router.getUserTime();
					long diffTime = endTime - startTime;
					FragmentationReport.integrityComputationTimeInReceiver += diffTime;
					
					if(notCorrupted) {
						fragment.isVerified = true;
						router.dataFragmentReceived.get(sender).get(index).add(fragment);
					}
				}
				//store any data fragment
				else {
					fragment.isVerified = false;
					router.dataFragmentReceived.get(sender).get(index).add(fragment);
				}
			}
			
			if(router.threadExistenceCheck.contains(String.valueOf(sender) +  "_" + String.valueOf(index))) {
				return;
			}
			
			if(router.keyReceived.get(sender).containsKey(index) && router.keyReceived.get(sender).get(index) != null){			
//				byte[] key = new byte[2*router.ec.keySizeInByte];
//				byte[] firstInfo = router.keyReceived.get(sender).get(index)[1].toByteArray();
//				System.arraycopy(firstInfo, firstInfo.length > FragmentationRouter.keyByteLenght ? 1:0, key, 0, FragmentationRouter.keyByteLenght);
				byte[] secondInfo = router.keyReceived.get(sender).get(index)[2].toByteArray();
//				System.arraycopy(secondInfo, secondInfo.length > FragmentationRouter.keyByteLenght ? 1:0, key, FragmentationRouter.keyByteLenght, key.length - FragmentationRouter.keyByteLenght);
				//now get priority
				int priority = 2;
				byte[] p = new byte[8];
				System.arraycopy(secondInfo, secondInfo.length-8, p, 0, 8);
				priority = ByteBuffer.wrap(p).getInt();
				//now get empty packet
				int dataFragmentK = Constant.INFINITE;
				byte[] k = new byte[8];
				System.arraycopy(secondInfo, secondInfo.length-16, k, 0, 8);
				dataFragmentK = ByteBuffer.wrap(k).getInt();
				//check signature
				for(int i=router.dataFragmentReceived.get(sender).get(index).size()-1; i>=0; i--) {
					SecretShare fragment = router.dataFragmentReceived.get(sender).get(index).get(i);
					if(fragment.isVerified == false) {
						byte[] recdata = fragment.getShare().toByteArray();
						byte[] curdata = new byte[Constant.dataByteLenght];
						if(recdata.length >= Constant.dataByteLenght) {
							System.arraycopy(recdata, recdata.length - Constant.dataByteLenght, curdata, 0, Constant.dataByteLenght);
						}
						else {
							System.arraycopy(recdata, 0, curdata, Constant.dataByteLenght-recdata.length, recdata.length);
						}
						
						long startTime = router.getUserTime();
						if(router.ecpre.VerifySignature(curdata, fragment.getSignature(), srcKey) == false) {
							router.dataFragmentReceived.get(sender).get(index).remove(i);
						}
						else {
							fragment.isVerified = true;
						}
						long endTime = router.getUserTime();
						long diffTime = endTime - startTime;
						FragmentationReport.integrityComputationTimeInReceiver += diffTime;
					}
				}		
				//now generate the actual data
				if(!router.dataReceived.get(sender).containsKey(index) && router.dataFragmentReceived.get(sender).get(index).size() >= dataFragmentK) {
					
					router.threadExistenceCheck.add(String.valueOf(sender) +  "_" + String.valueOf(index));
					//Runnable runnable = new WaitingThread(priority, dataFragmentK, sender, index);
					//new Thread(runnable).start();	
					FormMessage(priority, dataFragmentK, sender, index);
				}	
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void FormMessage(int priority, int dataFragmentK, int sender, int index) {
		int dataFragmentN;
		switch(priority) {
		case 1:
		   dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.highDataFactorKN);
		   FragmentationReport.totalHighPriorityFileReceived += 1;
		   break;
		case 3:
		   dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.lowDataFactorKN);
		   FragmentationReport.totalLowPriorityFileReceived += 1;
		   break;
		default:
		   dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.medDataFactorKN);
		   FragmentationReport.totalMedPriorityFileReceived += 1;
		   break;
		}

		//create data and coding block to decode
		ArrayList<Integer> erasureArr = new ArrayList<Integer>();
		byte[][] dataFragments = new byte[dataFragmentK][Constant.dataByteLenght];
		byte[][] codingFragments = new byte[dataFragmentN-dataFragmentK][Constant.dataByteLenght];
		ArrayList<SecretShare> receivedFragments = router.dataFragmentReceived.get(sender).get(index);
		Collections.sort(receivedFragments, new Comparator<SecretShare>() {
		    @Override
		    public int compare(SecretShare o1, SecretShare o2) {
		        return o1.getNumber() - o2.getNumber();
		    }
		});			
		int counter = -1;
		for(int f=0; f<dataFragmentK; f++) {
			counter++;
			//extract the current fragment data in byte array format
			SecretShare fragment = receivedFragments.get(f);
			byte[] recdata = fragment.getShare().toByteArray();
			byte[] curdata = new byte[Constant.dataByteLenght];
			if(recdata.length >= Constant.dataByteLenght) {
				System.arraycopy(recdata, recdata.length - Constant.dataByteLenght, curdata, 0, Constant.dataByteLenght);
			}
			else {
				System.arraycopy(recdata, 0, curdata, Constant.dataByteLenght-recdata.length, recdata.length);
			}
			//put the current fragment data to variables
			if(fragment.getNumber() < dataFragmentK) {
				System.arraycopy(curdata, 0, dataFragments[fragment.getNumber()], 0, Constant.dataByteLenght);
			}
			else {
				System.arraycopy(curdata, 0, codingFragments[fragment.getNumber()-dataFragmentK], 0, Constant.dataByteLenght);
			}
			//put missing indexex to erasure
			while(fragment.getNumber()>counter){
				erasureArr.add(counter);
				counter++;
			}
		}
		if(receivedFragments.get(dataFragmentK-1).getNumber() != dataFragmentK -1) {
			//fill the erasure array
			int erasures[] = new int[dataFragmentN-dataFragmentK];
			for(int i=0; i<erasures.length; i++) {
				if(erasureArr.size() <= i){
					erasures[i] = dataFragmentK+i;
				}
				else {
					erasures[i] = erasureArr.get(i);
				}
			}
			//get the actual data
			long startTime = router.getUserTime();
			ErasureCodec codec = new ErasureCodec.Builder(ErasureCodec.Algorithm.Cauchy_Reed_Solomon)
		            .dataBlockNum(dataFragmentK)
		            .codingBlockNum(dataFragmentN-dataFragmentK)
		            .wordSize(Constant.wordSize)
		            .packetSize(Constant.packetSize)
		            .good(true)
		            .build();
			codec.decode(erasures, dataFragments, codingFragments);		
			long endTime = router.getUserTime();
			long diffTime = endTime - startTime;
			//Report Class
			FragmentationReport.totalDecodeTime += diffTime;
			FragmentationReport.totalFileDecoded += 1;
		}
		else {
			FragmentationReport.totalFileSkippedDecode += 1;
		}
		
		//append all the byte array to a single byte array
		byte[] finalData = new byte[(dataFragmentK) * Constant.dataByteLenght];
		for(int i=0; i<dataFragmentK; i++) {
			byte[] currentArr = dataFragments[i];
			
			byte[] data = new byte[Constant.dataByteLenght];
			if(currentArr.length >= Constant.dataByteLenght) {
				System.arraycopy(currentArr, currentArr.length - Constant.dataByteLenght, data, 0, Constant.dataByteLenght);
			}
			else {
				System.arraycopy(currentArr, 0, data, Constant.dataByteLenght-currentArr.length, currentArr.length);
			}
			System.arraycopy(data, 0, finalData, i * Constant.dataByteLenght, Constant.dataByteLenght);
		}
		//remove the trailing empty data
		int l = finalData.length;
		while (l-- > 0 && finalData[l] == 0) {}
		byte[] finalCroppedData = new byte[l+1];
		System.arraycopy(finalData, 0, finalCroppedData, 0, l+1);
		router.dataReceived.get(sender).put(index, finalCroppedData);
		FragmentationReport.totalDataReceived++;

		router.decryptMessage(index, sender);
	}
}
