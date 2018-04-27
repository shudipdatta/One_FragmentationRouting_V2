package routing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import core.Application;
import core.Connection;
import core.DTNHost;
import core.DTNSim;
import core.Message;
import core.MessageListener;
import core.Settings;
import core.SimClock;
import core.SimError;
import datahandler.Constant;
import keyhandler.AEScrypto;
import keyhandler.SingletoneECPRE;
import keyhandler.RSecretShare;
import keyhandler.SecretShare;
import keyhandler.SingletoneCompromisedMessage;
import keyhandler.SingletoneFileWrite;
import report.FragmentationReport;
import routinghandler.FragmentationRouter_FixedKN;
import routinghandler.FragmentationRouter_VaryKN;

import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Map.Entry;

public class FragmentationRouter extends ActiveRouter {	
	/*
	 * List of all routers in this node group 
	 */
	private static List<FragmentationRouter> allRouters;
	static {
		DTNSim.registerForReset(FragmentationRouter.class.getCanonicalName());
		reset();
	}
	
	@Override
	public FragmentationRouter replicate() {
		return new FragmentationRouter(this);
	}
	/*
	 * Resets the static router list
	 */
	public static void reset() {
		allRouters = new ArrayList<FragmentationRouter>();
	}
	/*
	 * Router's property to be given in setting file 
	 */
	public static final String FRAGMENTATION_ROUTER = "FragmentationRouter";
	public static final String Type = "Type";
	public static final String Nkey = "KeyShare_N";
	public static final String Kkey = "KeyShare_K";
	public static final String Ndata = "DataFragment_N";
	public static final String Kdata = "DataFragment_K";
	public static final String MaliciousPercentage = "Malicious";
	public static final String SemiHonest = "SemiHonest";
	public static final String FileSize = "FileSize";
	public static final String REPORTDIR = "Directory";
	public static final String NROF_COPIES = "nrofCopies"; //multicopy
	public static final String is_Binary = "binaryMode"; //multicopy
	/*
	 * Routing wise variables
	 */
	private FragmentationRouter_VaryKN varyKN;
	private FragmentationRouter_FixedKN fixedKN;
	private SingletoneFileWrite fileWrite;
	private SingletoneCompromisedMessage compMsg;
	/*
	 * Variables to store content and order of messages to send / receive
	 */
	public HashMap<Integer, ArrayList<Chunk>> chunkToSend;
	public HashMap<Integer, Integer> chunkToSendCounter;
	public HashMap<Integer, Integer> chunkToSendBlockCounter;
	public ArrayList<String> threadExistenceCheck;
	
	public HashMap<Integer, HashMap<Integer, ArrayList<SecretShare>>> keyShareReceived;
	public HashMap<Integer, HashMap<Integer, BigInteger[]>> keyReceived;
	public HashMap<Integer, HashMap<Integer, ArrayList<SecretShare>>> dataFragmentReceived;
	public HashMap<Integer, HashMap<Integer, byte[]>> dataReceived;
	
	public HashMap<String, Integer> isMessageCorrupted;
	public HashMap<String, ArrayList<Integer>> nonCorruptedFrag;
	public HashMap<String, Boolean> nonCorruptedData;
	/*
	 * Node's public private key management
	 */
	private HashMap<DTNHost, byte[]> keyChain;
	
	public SingletoneECPRE ecpre;
	public AEScrypto aes;
	public RSecretShare rss;
	public byte[] pvtKey;
	public byte[] pubKey;
	public byte[] invPvt;
	/*
	 * Internal variables
	 */
	public int keyShareN;
	public int keyShareK;
	public int dataFragmentN;
	public int dataFragmentK;
	public String fileSize;
	public String directory;
	public String type;
	private int maliciousNodePercentage;
	public boolean isMalicious;
	private boolean semiHonest;
	public int treeHeight;
	private int initialNrofCopies; //multicopy
	private boolean isBinary; //multicopy
	/*
	 * Class Chunk which is key shares or data fragments
	 */
	public class Chunk{
		String type; 
		String sequence;
		byte[] content;
		int priority;
		public Chunk(String type, String sequence, byte[] content, int priority){
			this.type = type;
			this.sequence = sequence;
			this.content = content;
			this.priority = priority;
		}
	}
	
	/*
	 * Constructor. Creates a new message router based on the settings in the given Settings object.
	 */
	public FragmentationRouter(Settings s) {
		super(s);
		
		Settings snwSettings = new Settings(FRAGMENTATION_ROUTER);	
		this.type = snwSettings.getSetting(Type);
		this.keyShareN = snwSettings.getInt(Nkey);
		this.keyShareK = snwSettings.getInt(Kkey);
		this.dataFragmentN = snwSettings.getInt(Ndata);
		this.dataFragmentK = snwSettings.getInt(Kdata);
		this.fileSize = snwSettings.getSetting(FileSize);
		this.directory = snwSettings.getSetting(REPORTDIR);
		this.maliciousNodePercentage = snwSettings.getInt(MaliciousPercentage);
		this.semiHonest = snwSettings.getBoolean(SemiHonest);
		this.initialNrofCopies = snwSettings.getInt(NROF_COPIES);//multicopy
		this.isBinary = snwSettings.getBoolean(is_Binary);
	}	
	/*
	 * Copy constructor. The router prototype where setting values are copied from
	 */
	protected FragmentationRouter(FragmentationRouter r) {
		super(r);

		this.type = r.type;
		this.keyShareN = r.keyShareN;
		this.keyShareK = r.keyShareK;
		
		if(this.type.equals("fixed")) {
			this.dataFragmentN = r.dataFragmentN;
			this.dataFragmentK = r.dataFragmentK;
		}
		this.fileSize = r.fileSize;
		this.directory = r.directory;
		this.fileWrite = SingletoneFileWrite.getInstance(this.directory);
		this.compMsg = SingletoneCompromisedMessage.getInstance();
		this.ecpre = SingletoneECPRE.getInstance();
		
		this.maliciousNodePercentage = r.maliciousNodePercentage;
		this.semiHonest = r.semiHonest;
		
		this.treeHeight = (int) (Math.log(r.keyShareN)/Math.log(2));
		this.initialNrofCopies = r.initialNrofCopies; //multicopy
		this.isBinary = r.isBinary; //multicopy
		
		this.chunkToSend = new HashMap<Integer, ArrayList<Chunk>>();
		this.chunkToSendCounter = new HashMap<Integer, Integer>();
		this.chunkToSendBlockCounter = new HashMap<Integer, Integer>();
		this.threadExistenceCheck = new ArrayList<String>();
		
		this.keyShareReceived = new HashMap<Integer, HashMap<Integer, ArrayList<SecretShare>>>();
		this.keyReceived = new HashMap<Integer, HashMap<Integer, BigInteger[]>>();
		this.dataFragmentReceived = new HashMap<Integer, HashMap<Integer, ArrayList<SecretShare>>>();
		this.dataReceived = new HashMap<Integer, HashMap<Integer, byte[]>>();
		
		this.isMessageCorrupted = new HashMap<String, Integer>();
		this.nonCorruptedFrag = new HashMap<String, ArrayList<Integer>>();
		this.nonCorruptedData = new HashMap<String, Boolean>();
		
		this.keyChain = new HashMap<DTNHost, byte[]>();
		allRouters.add(this);
	}
	/*
	 * 
	 */
	@Override
	public void init(DTNHost host, List<MessageListener> mListeners) {
		super.init(host, mListeners);

		try {
			int maliciousBase = (int) Math.ceil(100 / (maliciousNodePercentage));
			if( (this.getHost().getAddress()+1) % maliciousBase == 0 ) {
				this.isMalicious = true;
			}
		} catch (Exception e) {
			this.isMalicious = false;
		}
		
		if(this.getHost().getAddress() == 0) {
			compMsg.Initialize();
			FragmentationReport.Initialize();
		}
		byte[][] keys = ecpre.GetKey(host.getAddress());
		this.pvtKey = keys[0];
		this.pubKey = keys[1];
		this.invPvt = keys[2];
		
		switch (this.type) {
		case "vary":
			varyKN = new FragmentationRouter_VaryKN(this);
			varyKN.Initialize();
			break;
		case "fixed":
			fixedKN = new FragmentationRouter_FixedKN(this);
			fixedKN.Initialize();
			break;
		}
	}
	/*
	 * 
	 */
	@Override 
	public boolean createNewMessage(Message msg) {		
	
		//if public key message
		if(msg.getId().startsWith("K")) {
			
			msg.addProperty("CONTENT", this.pubKey);
			//this.fileWrite.writeInFile("KEY", msg.getId() + "\t" + msg.getFrom() + "\t" + msg.getTo() + "\n");
		}
		
		//for all other data message
		else if(msg.getId().startsWith("M")){	
			
			//if not all message is created
			int to = msg.getTo().getAddress();
			if(this.chunkToSend.containsKey(to) && (this.chunkToSend.get(to).size() > this.chunkToSendCounter.get(to))) {
				
				Chunk chunk = this.chunkToSend.get(to).get(this.chunkToSendCounter.get(to));
				
				if(chunk.type.equals("K") && this.keyChain.isEmpty() == false) {
					byte[] proxyKey;		
					//check if it has the public key of destination
					if(this.keyChain.containsKey(msg.getTo())){
						msg.addProperty("INTERMIDIATE", null);
						proxyKey = this.keyChain.get(msg.getTo());
					}			
					//choose a random node from the keyChain
					else{
						Object [] keyChainNodes = this.keyChain.keySet().toArray();
						Object randomNode = keyChainNodes[new Random().nextInt(keyChainNodes.length)];
						msg.addProperty("INTERMIDIATE", randomNode);
						proxyKey = this.keyChain.get(randomNode);
					}
					msg.addProperty("KEY", pubKey);
					
					long startTime = getUserTime();
					//create encryption		
					byte[] encContent = ecpre.Encryption(chunk.content);						
					msg.addProperty("CONTENT", encContent);
					//create re-encryption
					byte[] reEnc = ecpre.ReEncryption(pubKey, proxyKey);
					msg.addProperty("REENC", reEnc);
					long endTime = getUserTime();
					long diffTime = endTime - startTime;
					FragmentationReport.cryptoTime += diffTime;
					
					//Report Class
					FragmentationReport.totalMsgSent++;
					FragmentationReport.totalKeyShareSent++;
					//Reporting
					if(this.chunkToSendCounter.get(to) == 0) {
						FragmentationReport.fileSentTime.put(
								msg.getFrom().getAddress()+"_"+msg.getTo().getAddress()+"_"+chunk.sequence.split("_")[0], 
								this.getSimTime());
					}
					//write to file
					//fileWrite.writeInFile("MSG", 
					//		msg.getId() + "\t" + msg.getFrom() + "\t" + msg.getTo() + "\t" + (chunk.type+"_"+chunk.sequence) + "\n");
				}
				else if(chunk.type.equals("M")) {
					msg.addProperty("CONTENT", chunk.content);	
					long startTime = getUserTime();
					msg.addProperty("SIGNATURE", ecpre.SignMessage(chunk.content, pvtKey));
					msg.addProperty("KEY", pubKey);
					long endTime = getUserTime();
					long diffTime = endTime - startTime;
					FragmentationReport.integrityComputationTimeInSender += diffTime;
					FragmentationReport.totalMsgSent++;
					FragmentationReport.totalDataFragSent++;
					if(this.chunkToSendCounter.get(to) == this.keyShareN) {
						switch(chunk.priority) {
						case 1:
							FragmentationReport.totalHighPriorityFileSent += 1;
							break;
						case 3:
							FragmentationReport.totalLowPriorityFileSent += 1;
							break;
						default:
							FragmentationReport.totalMedPriorityFileSent += 1;
							break;
						}
					}
				}
				msg.addProperty("SEQUENCE", chunk.type+"_"+chunk.sequence);

				this.chunkToSend.get(to).set(this.chunkToSendCounter.get(to), null);
				this.chunkToSendCounter.put(to, this.chunkToSendCounter.get(to) + 1);
			}
		}

		if(msg.getProperty("CONTENT") != null) {
			makeRoomForNewMessage(msg.getSize());
			msg.setTtl(this.msgTtl);
			msg.addProperty("COPYNUM", new Integer(initialNrofCopies));//multicopy
			addToMessages(msg, true);
			return true;
		}
		else return false;
	}
	/*
	 * 
	 */
	public Message superMessageTransferred(String id, DTNHost from) {
		//From messageRouter.java
		Message incoming = removeFromIncomingBuffer(id, from);
		boolean isFinalRecipient;
		boolean isFirstDelivery; // is this first delivered instance of the msg
		
		
		if (incoming == null) {
			throw new SimError("No message with ID " + id + " in the incoming "+
					"buffer of " + this.getHost());
		}
		
		incoming.setReceiveTime(SimClock.getTime());
		
		// Pass the message to the application (if any) and get outgoing message
		Message outgoing = incoming;
		for (Application app : getApplications(incoming.getAppID())) {
			// Note that the order of applications is significant
			// since the next one gets the output of the previous.
			outgoing = app.handle(outgoing, this.getHost());
			if (outgoing == null) break; // Some app wanted to drop the message
		}
		
		Message m = (outgoing==null)?(incoming):(outgoing);
		// If the application re-targets the message (changes 'to')
		// then the message is not considered as 'delivered' to this host.
		isFinalRecipient = (m.getTo() == this.getHost() && m.getProperty("INTERMIDIATE") == null);
		isFirstDelivery = isFinalRecipient &&
		!isDeliveredMessage(m);

		if (!isFinalRecipient && outgoing!=null) {
			// not the final recipient and app doesn't want to drop the message
			// -> put to buffer
			addToMessages(m, false);
		} else if (isFirstDelivery) {
			this.deliveredMessages.put(id, m);
		} else if (outgoing == null) {
			// Blacklist messages that an app wants to drop.
			// Otherwise the peer will just try to send it back again.
			this.blacklistedMessages.put(id, null);
		}		
		
		for (MessageListener ml : this.mListeners) {
			ml.messageTransferred(m, from, this.getHost(),
					isFirstDelivery);
		}
		return m;
	}
	@Override
	public Message messageTransferred(String id, DTNHost from) {
		Message m = superMessageTransferred(id,from);
				
		//if destination
		if (m.getTo() == getHost() && m.getProperty("INTERMIDIATE") == null) {
			//if received, then store the key
			if(m.getId().startsWith("K")){
				if(this.keyChain.containsKey(from) == false) {
					byte[] nodePubKey = (byte[]) m.getProperty("CONTENT");
					this.keyChain.put(from, ecpre.GenerateProxyKey(invPvt, nodePubKey));
					FragmentationReport.totalPublicKeyReceived.put(getHost().getAddress(), this.keyChain.size());
				}
			}
			
			//if received, then store and form data
			else if(m.getId().startsWith("M")){
/*
				//test block
				int avgKeyPossession = 0;				
				//calculating avg key possession
				int totalKeyReceivedSize = FragmentationReport.totalPublicKeyReceived.size();
				Iterator<Entry<Integer, Integer>> it = FragmentationReport.totalPublicKeyReceived.entrySet().iterator();
			    while (it.hasNext()) {
			    	@SuppressWarnings("rawtypes")
					HashMap.Entry pair = (HashMap.Entry)it.next();
			    	avgKeyPossession += (int) pair.getValue();
			    	it.remove(); // avoids a ConcurrentModificationException
			    }
			    avgKeyPossession/=totalKeyReceivedSize;
*/		    
				
				if(m.getProperty("CONTENT") != null) {					
					String[] msgInfo = ((String) m.getProperty("SEQUENCE")).split("_");
					String type = msgInfo[0];
					int index = Integer.parseInt(msgInfo[1]);
					int seq = Integer.parseInt(msgInfo[2]);
					int sender = m.getFrom().getAddress();
					
					if(!this.keyReceived.containsKey(sender) || !this.dataReceived.containsKey(sender)) {
						this.keyShareReceived.put(sender, new HashMap<Integer, ArrayList<SecretShare>>());
						this.keyReceived.put(sender, new HashMap<Integer, BigInteger[]>());
						this.dataFragmentReceived.put(sender, new HashMap<Integer, ArrayList<SecretShare>>());
						this.dataReceived.put(sender, new HashMap<Integer, byte[]>());
					}
					
					byte[] content = (byte[]) m.getProperty("CONTENT");
					byte[] reEnc = (byte[]) m.getProperty("REENC");
					
					if(type.equals("K")) {
						//decrypt by this host's private key
						long startTime = getUserTime();
						byte[] decContent = ecpre.Decryption(reEnc, content, invPvt);	
						long endTime = getUserTime();
						long diffTime = endTime - startTime;
						FragmentationReport.cryptoTime += diffTime;	
						//pseudo corruption creation
						if(m.getProperty("CORRUPTED") != null) {
							if(this.semiHonest == false) {
								int randomIndex = new Random().nextInt(decContent.length - 5) + 5; //random.nextInt(max + 1 - min) + min;
								decContent[randomIndex] = (byte) (127 ^ decContent[randomIndex]);
								if(!this.isMessageCorrupted.containsKey(sender+"_"+index+"K")) {
									this.isMessageCorrupted.put(sender+"_"+index+"K", seq-keyShareK);
								}
								else if(seq-keyShareK < this.isMessageCorrupted.get(sender+"_"+index+"K")) {
									this.isMessageCorrupted.put(sender+"_"+index+"K", seq-keyShareK);
								}
							}
							FragmentationReport.tatalCorruptedKeyReceived++;
						}
						else {
							FragmentationReport.tatalUncorruptedKeyReceived++;
						}
						//now store in local
						storeReceivedKeyShares(index, seq, decContent, sender, (byte[]) m.getProperty("KEY"));
						//Report Class
						FragmentationReport.totalMsgReceived++;
					}
					else if(type.equals("M")) {
						//pseudo corruption creation
						if(m.getProperty("CORRUPTED") != null) {
							if(this.semiHonest == false) {
								int randomIndex = new Random().nextInt(content.length - 5) + 5; //random.nextInt(max + 1 - min) + min;
								content[randomIndex] = (byte) (127 ^ content[randomIndex]);
								if(!this.isMessageCorrupted.containsKey(sender+"_"+index+"M")) {
									this.isMessageCorrupted.put(sender+"_"+index+"M", seq);
								}
								else if(seq < this.isMessageCorrupted.get(sender+"_"+index+"M")) {
									this.isMessageCorrupted.put(sender+"_"+index+"M", seq);
								}
							}
							FragmentationReport.tatalCorruptedMsgReceived++;
						}
						else {
							FragmentationReport.tatalUncorruptedMsgReceived++;
						}
						
						//track non corrupted message
						if(!this.nonCorruptedFrag.containsKey(sender+"_"+index)) {
							nonCorruptedFrag.put(sender+"_"+index, new ArrayList<Integer>());
						}
						if(m.getProperty("CORRUPTED") == null) {
							if(!this.nonCorruptedFrag.get(sender+"_"+index).contains(seq)) {
								this.nonCorruptedFrag.get(sender+"_"+index).add(seq);
							}
						}
						
						//now store in local
						switch (this.type) {
						case "vary":
							varyKN.storeReceivedDataFragments(index, seq, content, sender, (byte[]) m.getProperty("SIGNATURE"), (byte[]) m.getProperty("KEY"));
							break;
						case "fixed":
							fixedKN.storeReceivedDataFragments(index, seq, content, sender, (byte[]) m.getProperty("SIGNATURE"), (byte[]) m.getProperty("KEY"));
							break;
						}
						//Report Class
						FragmentationReport.totalMsgReceived++;
						
						/*
						//just to count how many files' data part i got
						if(this.semiHonest == false) {
							if(nonCorruptedFrag.get(sender+"_"+index).size() >= dataFragmentK) {
								if(!this.nonCorruptedData.containsKey(sender+"_"+index)) {
									nonCorruptedData.put(sender+"_"+index, true);
									FragmentationReport.totalDataReceived++;		
								}
							}
						}
						else {
							
						}
						*/
					}
				}
			}
			
			for (FragmentationRouter r : allRouters) {
				if (r != this && r != from.getRouter()) {
					r.removeDeliveredMessage(id);
				}
			}
		}
		
		//if intermediate
		else {

			if(m.getId().startsWith("M")) { 
	
				if((byte[]) m.getProperty("CONTENT") != null) {
					FragmentationReport.totalHopCount++;
		
					String[] msgInfo = ((String) m.getProperty("SEQUENCE")).split("_");
					String type = msgInfo[0];
					int index = Integer.parseInt(msgInfo[1]);
					int seq = Integer.parseInt(msgInfo[2]);
					int sender = m.getFrom().getAddress();
					int receiver = m.getTo().getAddress();
					
					//if it is miscellaneous, it will modify the content of the message
					if (this.isMalicious == true) {
						if(m.getProperty("CORRUPTED") == null) {
							m.addProperty("CORRUPTED", true);
						}
						//check for compromised message
						compMsg.Add(this, type, sender+"_"+receiver+"_"+index, seq, m);
						FragmentationReport.totalCompromisedFileMPE += compMsg.checkCompromisedMPE(this, type, sender+"_"+receiver+"_"+index);
						FragmentationReport.totalCompromisedFileOur += compMsg.checkCompromisedOur(this, type, sender+"_"+receiver+"_"+index);

					}
					
					//now do intermediate key share handling
					if(type.equals("K")  && m.getProperty("INTERMIDIATE") == this.getHost()) {
					
						//this block is only for MPE, it includes extra decryption
						long startTime = getUserTime();
						byte[] decContent = ecpre.Decryption((byte[]) m.getProperty("REENC"), (byte[]) m.getProperty("CONTENT"), invPvt);	
						long endTime = getUserTime();
						long diffTime = endTime - startTime;
						FragmentationReport.cryptoTimeExtra += diffTime;
						
						byte[] proxyKey;
						//check if it has the public key of destination
						if(this.keyChain.containsKey(m.getTo())){
							m.updateProperty("INTERMIDIATE", null);
							proxyKey = this.keyChain.get(m.getTo());
						}
						
						//choose a random node from the keyChain
						else{
							Object [] keyChainNodes = this.keyChain.keySet().toArray();
							Object randomNode = keyChainNodes[new Random().nextInt(keyChainNodes.length)];
							m.updateProperty("INTERMIDIATE", randomNode);
							proxyKey = this.keyChain.get(randomNode);
						}
						
						//update the proxy encryption data
						startTime = getUserTime();
						byte[] reEnc = ecpre.ReEncryption(pubKey, proxyKey);
						m.updateProperty("REENC", reEnc);
						endTime = getUserTime();
						diffTime = endTime - startTime;
						FragmentationReport.cryptoTime += diffTime;
						
						//now delete this message from all router other than itself
						for (FragmentationRouter r : allRouters) {
							if (r != this && r != from.getRouter()) {
								r.removeDeliveredMessage(id);
							}
						}
						m.updateProperty("COPYNUM", new Integer(initialNrofCopies));
					}
				}
				//reduce copies
				Integer nrofCopies = (Integer)m.getProperty("COPYNUM");
				assert nrofCopies != null : "Not a SnW message: " + m;
				
				if (isBinary) {
					/* in binary S'n'W the receiving node gets ceil(n/2) copies */
					nrofCopies = (int)Math.ceil(nrofCopies/2.0);
				}
				else {
					/* in standard S'n'W the receiving node gets only single copy */
					nrofCopies = 1;
				}		
				m.updateProperty("COPYNUM", nrofCopies);
			}
		}
		
		return m;
	}
	/*
	 * 
	 */
	public void storeReceivedKeyShares(int index, int seq, byte[] decContent, int sender, byte[] srcKey) {
		
		if ( (this.keyReceived.get(sender).containsKey(index) && this.dataReceived.get(sender).containsKey(index)) && 
				 (this.keyReceived.get(sender).get(index) == null && this.dataReceived.get(sender).get(index) == null) ) {
			return;
		}
		
		if(!this.keyShareReceived.get(sender).containsKey(index)) {
			this.keyShareReceived.get(sender).put(index, new ArrayList<SecretShare>());
		}
		
		//store any key share
		long startTime = getUserTime();
		byte[] keyShare = new byte[Constant.keyByteLenght];
		System.arraycopy(decContent, 0, keyShare, 0, Constant.keyByteLenght);
		byte[] hash = new byte[AEScrypto.hashLenght];
		try {
			System.arraycopy(this.aes.Hash(keyShare), 0, hash, 0, AEScrypto.hashLenght);
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for(int j=0; j<this.treeHeight; j++) {
			byte[] siblingHash = new byte[AEScrypto.hashLenght];
			System.arraycopy(decContent, Constant.keyByteLenght+j*AEScrypto.hashLenght, siblingHash, 0, AEScrypto.hashLenght);

			byte[] concatedHash = new byte[2 * AEScrypto.hashLenght];
			if( (j==0 && (seq-this.keyShareK)%2==0) || ( j>0 && ((seq-this.keyShareK)/(j*2))%2==0) ) {
				System.arraycopy(hash, 0, concatedHash, 0, AEScrypto.hashLenght);
				System.arraycopy(siblingHash, 0, concatedHash, AEScrypto.hashLenght, AEScrypto.hashLenght);
			}
			else {
				System.arraycopy(siblingHash, 0, concatedHash, 0, AEScrypto.hashLenght);
				System.arraycopy(hash, 0, concatedHash, AEScrypto.hashLenght, AEScrypto.hashLenght);
			}
			try {
				System.arraycopy(this.aes.Hash(concatedHash), 0, hash, 0, AEScrypto.hashLenght);
			} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		long endTime = getUserTime();
		long diffTime = endTime - startTime;
		FragmentationReport.integrityComputationTimeInReceiver += diffTime;
		
		SecretShare thisShare = new SecretShare(seq, new BigInteger(1, keyShare));
		try {
			thisShare.setHash(new String(hash, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.keyShareReceived.get(sender).get(index).add(thisShare);
		
		//now regenerate the key
		if(!this.keyReceived.get(sender).containsKey(index) && this.keyShareReceived.get(sender).get(index).size() >= this.keyShareK) {
			HashMap<String, String> sameHashShare = new HashMap<String, String>();
			int shareInd=0;
			for(SecretShare share: this.keyShareReceived.get(sender).get(index)) {
				if(sameHashShare.containsKey(share.getHash())) {
					String val = sameHashShare.get(share.getHash()) + "," + String.valueOf(shareInd++);
					sameHashShare.put(share.getHash(), val);
				}
				else {
					sameHashShare.put(share.getHash(), String.valueOf(shareInd++));
				}
			}
			Iterator<Entry<String, String>> it = sameHashShare.entrySet().iterator();
		    while (it.hasNext()) {
		    	@SuppressWarnings("rawtypes")
				HashMap.Entry pair = (HashMap.Entry)it.next();
		    	String[] indexes = pair.getValue().toString().split(",");
		        if(indexes.length >= this.keyShareK){
					SecretShare[] shares = new SecretShare[this.keyShareK];
					for(int i=0; i<shares.length; i++) {
						shares[i] = this.keyShareReceived.get(sender).get(index).get(Integer.parseInt(indexes[i]));
					}
					startTime = getUserTime();
					BigInteger[] keyInfo = this.rss.ReconstructShare(shares);
					FragmentationReport.totalKeyReceived++;
					endTime = getUserTime();
				    diffTime = endTime - startTime;
				    FragmentationReport.shareDecodeTime += diffTime;
					this.keyReceived.get(sender).put(index, keyInfo);
					
					switch (this.type) {
					case "vary":
						varyKN.storeReceivedDataFragments(index, -1, null, sender, new byte[0], srcKey);
						break;
					case "fixed":
						fixedKN.storeReceivedDataFragments(index, -1, null, sender, new byte[0], srcKey);
						break;
					}
					//Reporting
					FragmentationReport.fileRcvdTimeMPE.put(
							sender+"_"+getHost().getAddress()+"_"+index, 
							//System.nanoTime());
							//this.getUserTime());
							this.getSimTime());
		        	
		        	break;
		        }
		        it.remove(); // avoids a ConcurrentModificationException
		    }
		}		
	}
	/*
	 * 
	 */
	public void decryptMessage(int index, int sender) {
		try {
			//now decrypt data if both key and data is present
			if ( (this.keyReceived.get(sender).containsKey(index) && this.dataReceived.get(sender).containsKey(index)) && 
				 (this.keyReceived.get(sender).get(index) != null && this.dataReceived.get(sender).get(index) != null) ) {
				byte[] decData = aes.Decrypt(this.keyReceived.get(sender).get(index)[0].toByteArray(), this.dataReceived.get(sender).get(index));
						
				byte[] info = this.keyReceived.get(sender).get(index)[2].toByteArray();
				byte[] fileNameArr = new byte[8];
				System.arraycopy(info, info.length-24, fileNameArr, 0, 8);
				int l = fileNameArr.length;
				while (l-- > 0 && fileNameArr[l] == 0) {}
				byte[] croppedName = new byte[l+1];
				System.arraycopy(fileNameArr, 0, croppedName, 0, l+1);
				
				this.fileWrite.writeInFile("FILE", decData, 
						"F-" + sender + "_T-" + this.getHost().getAddress() + "_N-" + index + "_" + new String(fileNameArr));
			
				this.keyReceived.get(sender).put(index, null);
				this.dataReceived.get(sender).put(index, null);
				
				this.keyShareReceived.get(sender).put(index, null);// new ArrayList<SecretShare>());
				this.dataFragmentReceived.get(sender).put(index, null);// new ArrayList<SecretShare>());
				
				//Report Class
				FragmentationReport.totalFileReceived++;
				System.out.println(FragmentationReport.totalFileReceived);
				
				FragmentationReport.fileRcvdTimeOur.put(
						sender+"_"+getHost().getAddress()+"_"+index, 
						//System.nanoTime());
						//this.getUserTime());
						this.getSimTime());
				
				if( (this.isMessageCorrupted.containsKey(sender+"_"+index+"K") && this.isMessageCorrupted.get(sender+"_"+index+"K")<=keyShareK) 
						|| (this.isMessageCorrupted.containsKey(sender+"_"+index+"M") && this.isMessageCorrupted.get(sender+"_"+index+"M")<=4)) {
					FragmentationReport.totalCorruptedFileReceived++;
				}
			}
		} catch(Exception e) {
			System.out.println(this.dataReceived.get(sender).get(index).length);
		}
	}
	/*
	 * 
	 */
	protected List<Message> getMessagesWithCopiesLeft() {
		List<Message> list = new ArrayList<Message>();

		for (Message m : getMessageCollection()) {
			if(m.getId().startsWith("M")) {
				Integer nrofCopies = (Integer)m.getProperty("COPYNUM");
				assert nrofCopies != null : "SnW message " + m + " didn't have " + "nrof copies property!";
				if (nrofCopies > 1) {
					list.add(m);
				}
				else {
					List<Connection> connections = getConnections();
					DTNHost intermidiate = (DTNHost)m.getProperty("INTERMIDIATE");
					if(intermidiate != null) {
						for (int i=0, n=connections.size(); i<n; i++) {
							Connection con = connections.get(i);
							if(con.getOtherNode(getHost()) == intermidiate) {
								list.add(m);
								break;
							}
						}
					}
				}
			}
		}
		
		return list;
	}
	/*
	 * 
	 */
	@Override
	public void update() {
		super.update();
		if (isTransferring() || !canStartTransfer()) {
			return; // can't start a new transfer
		}
		
		// Try only the messages that can be delivered to final recipient
		if (exchangeDeliverableMessages() != null) {
			return; // started a transfer
		}
		
		/* create a list of SAWMessages that have copies left to distribute */
		@SuppressWarnings(value = "unchecked")
		List<Message> copiesLeft = sortByQueueMode(getMessagesWithCopiesLeft());
		
		if (copiesLeft.size() > 0) {
			/* try to send those messages */
			this.tryMessagesToConnections(copiesLeft, getConnections());
		}
	}
	///*
	//multicopy
	@Override
	protected void transferDone(Connection con) {
		Integer nrofCopies;
		String msgId = con.getMessage().getId();
		/* get this router's copy of the message */
		Message m = getMessage(msgId);

		if (m == null) { // message has been dropped from the buffer after..
			return; // ..start of transfer -> no need to reduce amount of copies
		}
		
		if(m.getId().startsWith("M")) {
			/* reduce the amount of copies left */
			nrofCopies = (Integer)m.getProperty("COPYNUM");
			if (isBinary) { 
				nrofCopies /= 2;
			}
			else {
				nrofCopies--;
			}
			m.updateProperty("COPYNUM", nrofCopies);
		}
		
		/* was the message delivered to the final recipient? */
		if (con.getMessage() != null && con.getMessage().getTo() == con.getOtherNode(getHost())) { 
			this.deleteMessage(con.getMessage().getId(), false);
		}
	}
	/*
	 * Removes the message with the given ID from this router, if the router
	 * has that message; otherwise does nothing. If the router was transferring
	 * the message, the transfer is aborted.
	 * @param id ID of the message to be removed
	 */
	public void removeDeliveredMessage(String id) {
		if (this.hasMessage(id)) {
			for (Connection c : this.sendingConnections) {
				/* if sending the message-to-be-removed, cancel transfer */
				try{ 
					if (c.getMessage().getId().equals(id)) {
						c.abortTransfer();
					}
				}
				catch(Exception ex) {
					
				}
			}
			this.deleteMessage(id, false);			
		}
	}
	/*
	 * 
	 */
	public DTNHost getHost() {
		return super.getHost();
	}

	public long getUserTime( ) {
		ThreadMXBean bean = ManagementFactory.getThreadMXBean( );
		return bean.isCurrentThreadCpuTimeSupported( ) ?
				bean.getCurrentThreadUserTime( ) : 0L;
	}
}
