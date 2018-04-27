package keyhandler;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import datahandler.Constant;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;


public class SingletoneECPRE {
	
	@SuppressWarnings("rawtypes")
	Field Zr, GT, C;
	//Zr -> [pvtKey, invPvtKey]
	//C -> [pubKey, proxyKey]
	//GT -> [reEnc]	
	Element G, K, Zk;
	Pairing pairing;
	
	byte[] bytePairing;
	byte[] byteG;
	byte[] byteK;
	byte[] byteZk;

	public int rBits = 160;
	int qBits = 512;
	int plainByteLen = qBits/8-4; //512/8=64;
	int cipherByteLen = qBits/8*2;
	
	
	private static SingletoneECPRE thisObj;
	private SingletoneECPRE() {
		Pairing();
	}
	/**
     * Create a static method to get instance.
     */
    public static SingletoneECPRE getInstance(){
        if(thisObj == null){
			thisObj = new SingletoneECPRE();
			//thisObj.GetPairing();
        }
        return thisObj;
    }
	
	@SuppressWarnings("rawtypes")
	public void Pairing() {
		// JPBC Type A pairing generator
		PairingParametersGenerator paramGenerator = new TypeACurveGenerator(rBits, qBits);
		PairingParameters params = paramGenerator.generate();
		pairing = PairingFactory.getPairing(params);
		//Bilinear Pairing
		Zr = pairing.getZr();
		GT = pairing.getGT();
		C = pairing.getG1();
		G = C.newRandomElement().getImmutable();
		K = Zr.newRandomElement().getImmutable();
		Zk = pairing.pairing(G, G.powZn(K)).getImmutable();
		//C = G.getField();
		
		bytePairing = params.toString().getBytes();
		byteG = G.toBytes();
		byteK = K.toBytes();
		byteZk = Zk.toBytes();
	}
	
	/*
	public Element[] GenerateKey() {
		Element pvtKey = Zr.newRandomElement().getImmutable();
		Element pubKey = G.powZn(pvtKey).getImmutable();
		Element invPvt = pvtKey.invert();	
		Element[] keys = {pvtKey, pubKey, invPvt};
		return keys;
	}
	
	public Element GenerateProxyKey(Element invPvtA, Element pubKeyB) {
		Element proxyKeyAB = pubKeyB.powZn(invPvtA);
		return proxyKeyAB;
	}
	
	public Element[] Encryption(byte[] plainText, Element pubKeyA, Element proxyKeyAB) {
		Element E = GT.newRandomElement();
		E.setFromBytes(plainText);
		Element cipher = Zk.mul(E);
		return ReEncryption(cipher, pubKeyA, proxyKeyAB);
	}
	
	public Element[] ReEncryption(Element cipher, Element pubKeyA, Element proxyKeyAB) {
		Element reCipher = pubKeyA.powZn(K);
		Element reEncAB = pairing.pairing(reCipher, proxyKeyAB);
		Element[] ciphers = {reEncAB, cipher};
		return ciphers;
	}
	
	public Element Decryption(Element reEncAB, Element cipher, Element invPvtB) {
		Element reCipher = reEncAB.powZn(invPvtB);
		Element plainText = cipher.div(reCipher);
		return plainText;
	}
	*/
	
	public byte[][] GenerateKey() {
		Element pvtKey = Zr.newRandomElement().getImmutable();
		Element pubKey = G.powZn(pvtKey).getImmutable();
		Element invPvt = pvtKey.invert();	
		byte[][] keys = {pvtKey.toBytes(), pubKey.toBytes(), invPvt.toBytes()};
		return keys;
	}
	
	public byte[] GenerateProxyKey(byte[] invPvtA, byte[] pubKeyB) {
		Element elemInvPvtA = Zr.newElement();
		Element elemPubKeyB = C.newElement();
		elemInvPvtA.setFromBytes(invPvtA);
		elemPubKeyB.setFromBytes(pubKeyB);
		
		Element proxyKeyAB = elemPubKeyB.powZn(elemInvPvtA);
		return proxyKeyAB.toBytes();
	}
	
//	public byte[] Encryption(byte[] plainText) {
//		Element E = GT.newElement();
//		E.setFromBytes(plainText);
//		Element cipher = Zk.mul(E);
//		return cipher.toBytes();
//	}
	
//	public byte[] Encryption(byte[] plainText) {
//		byte[] bytePlainText = new byte[((int) Math.ceil(plainText.length/(double)plainByteLen)) * plainByteLen];
//		System.arraycopy(plainText, 0, bytePlainText, 0, plainText.length);
//		int blockNum = (int) Math.ceil(plainText.length/(double)plainByteLen);
//		byte[] byteCipher = new byte[blockNum*cipherByteLen];
//		
//		for(int i=0; i<blockNum; i++) {
//			Element E = GT.newElement();
//			byte[] plainBlock = new byte[plainByteLen];
//			System.arraycopy(bytePlainText, plainByteLen*i, plainBlock, 0, plainByteLen);
//			E.setFromBytes(plainBlock);
//			Element cipher = Zk.mul(E);
//			System.arraycopy(cipher.toBytes(), 0, byteCipher, cipherByteLen*i, cipherByteLen);
//		}
//		return byteCipher;
//	}
	
	public byte[] Encryption(byte[] plainText) {
		int blockNum = (int) Math.ceil(plainText.length/(double)plainByteLen);
		byte[] byteCipher = new byte[blockNum*cipherByteLen];
		
		for(int i=0; i<blockNum; i++) {
			Element E = GT.newElement();
			byte[] plainBlock = new byte[plainText.length - plainByteLen*i < plainByteLen? plainText.length - plainByteLen*i: plainByteLen];
			System.arraycopy(plainText, plainByteLen*i, plainBlock, 0, plainBlock.length);
			E.setFromBytes(plainBlock);
			Element cipher = Zk.mul(E);
			System.arraycopy(cipher.toBytes(), 0, byteCipher, cipherByteLen*i, cipher.toBytes().length);
		}
		return byteCipher;
	}
	
	public byte[] ReEncryption(byte[] pubKeyA, byte[] proxyKeyAB) {
		Element elemPubKeyA = C.newElement();
		Element elemProxyKeyAB = C.newElement();
		elemPubKeyA.setFromBytes(pubKeyA);
		elemProxyKeyAB.setFromBytes(proxyKeyAB);
		
		Element reCipher = elemPubKeyA.powZn(K);
		Element reEncAB = pairing.pairing(reCipher, elemProxyKeyAB);
		return reEncAB.toBytes();
	}
	
	public byte[] Decryption(byte[] reEncAB, byte[] cipher, byte[] invPvtB) {
		Element elemReEncAB = GT.newElement();
		Element elemInvPvtB = Zr.newElement();
		elemReEncAB.setFromBytes(reEncAB);
		elemInvPvtB.setFromBytes(invPvtB);
		Element reCipher = elemReEncAB.powZn(elemInvPvtB);
		
		int blockNum = (int) Math.ceil(cipher.length/(double)cipherByteLen);
		byte[] bytePlain = new byte[blockNum*plainByteLen];
		for(int i=0; i<blockNum; i++) {
			byte[] cipherBlock = new byte[cipherByteLen];
			System.arraycopy(cipher, cipherByteLen*i, cipherBlock, 0, cipherByteLen);
			Element elemCipher = GT.newElement();
			elemCipher.setFromBytes(cipherBlock);			
			Element plainText = elemCipher.div(reCipher);
			
			byte[] bytePlainText = plainText.toBytes();
			int initIndex=0;
			while(bytePlainText[initIndex] == 0) initIndex++;			
			
			System.arraycopy(plainText.toBytes(), initIndex, bytePlain, plainByteLen*i, plainByteLen);
		}
		return bytePlain;
	}

//	public byte[] Decryption(byte[] reEncAB, byte[] cipher, byte[] invPvtB) {
//		Element elemReEncAB = GT.newElement();
//		Element elemCipher = GT.newElement();
//		Element elemInvPvtB = Zr.newElement();
//		elemReEncAB.setFromBytes(reEncAB);
//		elemCipher.setFromBytes(cipher);
//		elemInvPvtB.setFromBytes(invPvtB);
//		
//		Element reCipher = elemReEncAB.powZn(elemInvPvtB);
//		Element plainText = elemCipher.div(reCipher);
//		return plainText.toBytes();
//	}
	public byte[] Hash(byte[] value) throws NoSuchAlgorithmException, UnsupportedEncodingException
	{
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			byte[] bytesOfMessage = value;
			final byte[] resultByte = messageDigest.digest(bytesOfMessage);
			//System.out.println("Hash Length: " + resultByte.length); 
			return resultByte;
		} 
	    catch (Exception ex) {
	        ex.printStackTrace();
	        System.out.println("Hash Exception:");
	    }

	    return null;
	}
	
	public byte[] SignMessage(byte[] cipher, byte[] pvtKey) {		
		try {
			byte[] hash = Hash(cipher);
			Element elemHash = pairing.getG1().newElement().setFromHash(hash, 0, hash.length);
			
			Element elemPvtKey = Zr.newElement();
			elemPvtKey.setFromBytes(pvtKey);
			Element signature = elemHash.powZn(elemPvtKey);
			return signature.toBytes();
		} 
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
			return new byte[0];
		}
	}
	
	public boolean VerifySignature(byte[] cipher, byte[] signature, byte[] pubKey) {
		try {
			byte[] hash = Hash(cipher);
			Element elemHash = pairing.getG1().newElement().setFromHash(hash, 0, hash.length);
			
			Element elemSig = C.newElement();
			Element elemPubKey = C.newElement();
			elemSig.setFromBytes(signature);
			elemPubKey.setFromBytes(pubKey);
			
			Element e1 = pairing.pairing(elemSig, G);
			Element e2 = pairing.pairing(elemHash, elemPubKey);
			
			return e1.isEqual(e2)? true: false;
		} 
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
			return false;
		}
	}
	/*
	public void GetPairing() {
		String directory = System.getProperty("user.dir") + "/keyhandler/keyfolder";
		try{
			Path path = Paths.get(directory+"/Pairing");
			PairingParameters params = new PropertiesParameters().load(new ByteArrayInputStream(Files.readAllBytes(path)));
			pairing = PairingFactory.getPairing(params);
	    	Zr = pairing.getZr();
	    	GT = pairing.getGT();
	    	C = pairing.getG1();
	    	
	    	File lengthFile = new File(directory+"/Length");
			FileInputStream lengthStream = new FileInputStream(lengthFile);
			byte lengthContent[] = new byte[(int)lengthFile.length()];
			lengthStream.read(lengthContent);
			String[] lengths = new String(lengthContent).split("_");
			lengthStream.close();
	    	
	    	File settingFile = new File(directory+"/Setting");
			FileInputStream settingStream = new FileInputStream(settingFile);
			byte settingContent[] = new byte[(int)settingFile.length()];
			settingStream.read(settingContent);
			settingStream.close();
			
			byteG = new byte[Integer.parseInt(lengths[0])];
			byteK = new byte[Integer.parseInt(lengths[1])];
			byteZk = new byte[Integer.parseInt(lengths[2])];
			
			System.arraycopy(settingContent, 0, byteG, 0, byteG.length);
			System.arraycopy(settingContent, byteG.length, byteK, 0, byteK.length);
			System.arraycopy(settingContent, byteG.length+byteK.length, byteZk, 0, byteZk.length);
	    	
			G = C.newElement();
			G.setFromBytes(byteG);G.getImmutable();
			K = Zr.newElement();
	    	K.setFromBytes(byteK);K.getImmutable();
	    	Zk = GT.newElement();
	    	Zk.setFromBytes(byteZk);
		} 
		catch(Exception e) {
			e.printStackTrace();
		}
	}
	*/
	public byte[][] GetKey(int hostNum) {
		return GenerateKey();
	}
	/*
	@SuppressWarnings("resource")
	public byte[][] GetKey(int hostNum) {

		try {
			String directory = System.getProperty("user.dir") + "/keyhandler/keyfolder";
			File keyFile = new File(directory+"/KeyFile_"+hostNum);
			FileInputStream stream = new FileInputStream(keyFile);

			byte fileContent[] = new byte[(int)keyFile.length()];
			stream.read(fileContent);
			stream.close();
			
			byte[] pvtKey = new byte[rBits/8];
			byte[] pubKey = new byte[qBits/8 * 2];
			byte[] invPvt = new byte[rBits/8];
			
			System.arraycopy(fileContent, 0, pvtKey, 0, pvtKey.length);
			System.arraycopy(fileContent, pvtKey.length, pubKey, 0, pubKey.length);
			System.arraycopy(fileContent, pvtKey.length+pubKey.length, invPvt, 0, invPvt.length);
			
			byte[][] keys = {pvtKey, pubKey, invPvt};
			return keys;
		}
		catch (IOException e) {
			e.printStackTrace();
			return new byte[0][0];
		}
	}
	*/
	/*
	public void Test() {		
		//Pairing();
		//byte[][] key37 = GenerateKey();
		//byte[][] key8 = GenerateKey();
		
		GetPairing();
		byte[][] key37 = GetKey(37);
		byte[][] key8 = GetKey(8);
		
		byte[] proxyKey37_8 = GenerateProxyKey(key37[2], key8[1]);
		byte[] content = {-104, 83, 12, 101, -47, 14, -80, 22, -94, -56, 95, -70, 56, 29, 127, -57, 119, 125, -37, -56, -45, -20, -24, 91, 55, 55, -42, -74, -22, -109, -96, -71, 87, -127, -118, -6, -46, -43, 18, 3, -101, 18, 68, 73, 66, -111, 32, 124, -49, 7, -88, 113, 6, 105, -78, 101, 2, -16, -107, 117, 122, -11, 40, 87, -115, -25, 15, 23, 69, 14, 2, 48, 63, 58, 32, -57, 74, -108, -14, 112};
		byte[] cipher37_8 = Encryption(content);
		byte[] reEnc37_8 = ReEncryption(key37[1], proxyKey37_8);
		byte[] plainText123 = Decryption(reEnc37_8, cipher37_8, key8[2]);
		System.out.println("Test");
	}
	*/
	/*
	//for creating key file
	public static void main(String[] args) {
			
		SingletoneECPRE ecpre = new SingletoneECPRE();
		//ecpre.Test();
		ecpre.Pairing();

		String directory = System.getProperty("user.dir") + "/keyhandler/keyfolder";
		
    	//create the setting files
		try {
			File pairingFile = new File(directory+"/Pairing");
			Files.deleteIfExists(pairingFile.toPath());
			FileOutputStream pairingWriter = new FileOutputStream(pairingFile, true);
			pairingWriter.write(ecpre.bytePairing);
			pairingWriter.close();
			
			File lengthFile = new File(directory+"/Length");
			Files.deleteIfExists(lengthFile.toPath());
			FileOutputStream lengthWriter = new FileOutputStream(lengthFile, true);
			lengthWriter.write((ecpre.byteG.length+"_"+ecpre.byteK.length+"_"+ecpre.byteZk.length).getBytes());
			lengthWriter.close();
			
			File settingFile = new File(directory+"/Setting");
			Files.deleteIfExists(settingFile.toPath());
			FileOutputStream settingWriter = new FileOutputStream(settingFile, true);
			settingWriter.write(ecpre.byteG);
			settingWriter.write(ecpre.byteK);
			settingWriter.write(ecpre.byteZk);
			settingWriter.close();
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		//create and save keys
		try {
    		FileOutputStream stream = null;
    		int numHost = 98;
    		
    		for(int i=0; i<numHost; i++) {
    			File keyFile = new File(directory+"/KeyFile_"+i);
    			Files.deleteIfExists(keyFile.toPath());
    			stream = new FileOutputStream(keyFile, true);

    			byte[][] keys = ecpre.GenerateKey();
    			byte[] pvtKey = keys[0];
    			byte[] pubKey = keys[1]; 
    			byte[] invPvt = keys[2];

    			stream.write(pvtKey);
    			stream.write(pubKey);
    			stream.write(invPvt);
    			stream.close();
    		}			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	*/
}