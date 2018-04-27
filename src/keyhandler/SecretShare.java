package keyhandler;
import java.math.BigInteger;

public class SecretShare
{
    public SecretShare(int number, BigInteger share)
    {
        this.number = number;
        this.share = share;
    }

    public int getNumber()
    {
        return number;
    }

    public BigInteger getShare()
    {
        return share;
    }
    
    public void setHash(String hash) {
    	this.hash = hash;
    }
    
    public String getHash() {
    	return hash;
    }
    
    public void setSignature(byte[] signature) {
    	this.signature = new byte[signature.length];
    	System.arraycopy(signature, 0, this.signature, 0, signature.length);
    }
    
    public byte[] getSignature() {
    	return signature;
    }

    private int number;
    private BigInteger share;
    private String hash;
    private byte[] signature;
    public boolean isVerified;
}