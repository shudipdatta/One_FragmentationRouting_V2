package keyhandler;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import core.Message;
import datahandler.Constant;
import routing.FragmentationRouter;

public class SingletoneCompromisedMessage {
	private static SingletoneCompromisedMessage thisObj;
	private HashMap<String, ArrayList<Integer>> compromisedKey;
	private HashMap<String, ArrayList<Integer>> compromisedData;
	private HashMap<String, ArrayList<SecretShare>> keyContent;
	private HashMap<String, Integer> kData;
	private HashMap<String, Integer> isKeyCalculated;
	private HashMap<String, Integer> isDataCalculated;
    /**
     * Create private constructor
     * @throws IOException 
     */
    private SingletoneCompromisedMessage() {
    	Initialize();
    }
    
    public void Initialize() {
    	compromisedKey = new HashMap<String, ArrayList<Integer>>();
    	compromisedData = new HashMap<String, ArrayList<Integer>>();
    	
    	keyContent = new HashMap<String, ArrayList<SecretShare>>();
    	kData = new HashMap<String, Integer>();
    	
    	isKeyCalculated = new HashMap<String, Integer>();
    	isDataCalculated = new HashMap<String, Integer>();
    }
    /**
     * Create a static method to get instance.
     */
    public static SingletoneCompromisedMessage getInstance(){
        if(thisObj == null){
			thisObj = new SingletoneCompromisedMessage();
        }
        return thisObj;
    }
     
    public void Add(FragmentationRouter router, String type, String name, int seq, Message msg){
    	if(type.equals("K")) {
    		if(isKeyCalculated.containsKey(name)){
        		return;
        	}    		
    		
    		if(compromisedKey.containsKey(name) && 
    				(compromisedKey.get(name) == null || compromisedKey.get(name).contains(seq)) ) {
    			return;
    		}
    		
    		if(msg.getProperty("INTERMIDIATE") != router.getHost()) {
    			return;
    		}
    		
    		if(compromisedKey.containsKey(name) == false) {
    			compromisedKey.put(name, new ArrayList<Integer>());
			
				keyContent.put(name, new ArrayList<SecretShare>());
				kData.put(name, Constant.INFINITE);
    		}

    		compromisedKey.get(name).add(seq);
    		
			byte[] content = (byte[]) msg.getProperty("CONTENT");
			byte[] reEnc = (byte[]) msg.getProperty("REENC");
			byte[] decContent = router.ecpre.Decryption(reEnc, content, router.invPvt);
			
			byte[] keyShare = new byte[Constant.keyByteLenght];
			System.arraycopy(decContent, 0, keyShare, 0, Constant.keyByteLenght);
			keyContent.get(name).add(new SecretShare(seq, new BigInteger(1,keyShare)));
			
			if(compromisedKey.get(name).size()>=router.keyShareK) {
				SecretShare[] shares = new SecretShare[router.keyShareK];
				for(int i=0; i<shares.length; i++) {
					shares[i] = keyContent.get(name).get(i);
				}
				byte[] info = router.rss.ReconstructShare(shares)[2].toByteArray();
				byte[] k = new byte[8];
				System.arraycopy(info, info.length-16, k, 0, 8);
				kData.put(name, ByteBuffer.wrap(k).getInt());
			}
    	}
    	else if(type.equals("M")) {
    		if(isDataCalculated.containsKey(name)){
        		return;
        	} 
    		
    		if(compromisedData.containsKey(name) && 
    				(compromisedData.get(name) == null || compromisedData.get(name).contains(seq)) ) {
    			return;
    		}
    		
    		if(compromisedData.containsKey(name) == false) {
    			compromisedData.put(name, new ArrayList<Integer>());
    		}
    		
    		compromisedData.get(name).add(seq);//if(compromisedData.get(name).size()>=4) System.out.print("Test");
    	}
    }
    
    public int checkCompromisedMPE(FragmentationRouter router, String type, String name) {

    	if(isKeyCalculated.containsKey(name)){
    		return 0;
    	}
    	
    	if(kData.containsKey(name) && kData.get(name)<Constant.INFINITE) {
    		isKeyCalculated.put(name, 1);
    		return 1;
    	}
    	
    	return 0;
    }
    
    public int checkCompromisedOur(FragmentationRouter router, String type, String name) {

    	if(isKeyCalculated.containsKey(name) && isDataCalculated.containsKey(name)){
    		return 0;
    	}
    	
    	if( (kData.containsKey(name) && kData.get(name)<Constant.INFINITE && compromisedData.containsKey(name)) && 
    			((router.type.equals("fixed") && (compromisedData.get(name).size()+kData.get(name))>=router.dataFragmentK) 
    			|| (router.type.equals("vary") && compromisedData.get(name).size()>=kData.get(name)))
    	) {
    		isKeyCalculated.put(name, 1);
    		isDataCalculated.put(name, 1);
    		return 1;
    	}
    		
    	return 0;
    }
}
