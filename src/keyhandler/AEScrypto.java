package keyhandler;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AEScrypto {
	
	private final static int bitLenght = 256; //32 byte
	public final static int hashLenght = 16; //16 byte
	private static byte[] initVector;
	
	public AEScrypto() throws UnsupportedEncodingException{
		GenerateInitVector();
	}
	
	public byte[] GenerateKey() throws UnsupportedEncodingException
	{
		String CHAR_LIST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
		int RANDOM_STRING_LENGTH = bitLenght/8;
		
		StringBuffer randStr = new StringBuffer();
        for(int i=0; i<RANDOM_STRING_LENGTH; i++){
        	int randomInt = 0;
            Random randomGenerator = new Random();
            randomInt = randomGenerator.nextInt(CHAR_LIST.length());
            char ch = CHAR_LIST.charAt(randomInt);
            randStr.append(ch);
        }

        return String.valueOf(randStr).getBytes();
    }
	
	public void GenerateInitVector() throws UnsupportedEncodingException
	{
		/*
		String CHAR_LIST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
		int RANDOM_STRING_LENGTH = bitLenght/8;
		
		StringBuffer randStr = new StringBuffer();
        for(int i=0; i<RANDOM_STRING_LENGTH; i++){
        	int randomInt = 0;
            Random randomGenerator = new Random();
            randomInt = randomGenerator.nextInt(CHAR_LIST.length());
            char ch = CHAR_LIST.charAt(randomInt);
            randStr.append(ch);
        }
        //initVector = String.valueOf(randStr).getBytes();
        */
        initVector = new byte[]{'w','a','d','f','g','b','j','k','z','c','d','f','g','h','j','k'};
    }
	
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
	
	public byte[] Encrypt(byte[] key, byte[] value) 
	{
        try 
        {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value);
            //System.out.println("Encrypted Length: " + encrypted.length);
            return encrypted;    
        } 
        catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Encryption Exception:");
        }

        return null;
    }

    public byte[] Decrypt(byte[] key, byte[] encrypted) 
    {
        try 
        {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] decrypted = cipher.doFinal(encrypted);
            //System.out.println("Decrypted Length: " + original.length);
            return decrypted;            
        } 
        catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Decryption Exception:");
        }

        return null;
    }
}
