package keyhandler;
import java.math.BigInteger;
import java.util.Random;

import datahandler.Constant;

public class RSecretShare
{
	private int n;
	private int k;	
	
	public RSecretShare(int keyShareK, int keyShareN) {
		this.k = keyShareK;
		this.n= keyShareN;
	}
	
	//this prime is greater than the number 2^384
	//private final static BigInteger prime = new BigInteger("39402006196394479212279040100143613805079739270465446667948293404245721771497210611414266254884915640806627990307047"); 
	//this prime is greater than the number 2^256
	private final static BigInteger prime = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129640233"); 
	
	private SecretShare[] shares;
	private BigInteger [] constructedInfo;
	
	
    public SecretShare[] CreateShare(BigInteger key, BigInteger[] info)
    {
    	//initialize
		shares = new SecretShare[n];
		
    	BigInteger[][] yPoint = new BigInteger[k-1][k-1];  
		yPoint[0][0] = new BigInteger(Constant.keyByteLenght * 8, 1, new Random());
    	
    	//create shares with hidden info
		for(int i=0; i<info.length; i++){
			int[] x = new int[i+2];
			BigInteger[] y = new BigInteger[i+2];
			
			x[0] = 0;
			y[0] = info[i];
			
			int j=0;
			
			for(; j<=i; j++){
				x[j+1] = j+1;
				y[j+1] = yPoint[i][j];
			}
			
			for(int m=0; m<=i+1; m++, j++){
				yPoint[i+1][m] = Interpolation(x, y, j+1);
			}
		}
		
		//create shares with key
		{
			int[] x = new int[k];
			BigInteger[] y = new BigInteger[k];
			
			x[0] = 0;
			y[0] = key;
			
			for(int i=0; i<k-1; i++){
				x[i+1] = i+1;
				y[i+1] = yPoint[k-2][i];
			}
			
			for(int m=0; m<n; m++){
				shares[m] = new SecretShare(m+k, Interpolation(x, y, m+k));
			}
		}
		return shares;
    }

    public BigInteger[] ReconstructShare(SecretShare[] rShares){
    	
    	//initialize
    	constructedInfo = new BigInteger[k-1];
    	BigInteger[][] yPoint = new BigInteger[k-1][k-1];
		
		if(rShares.length >= k){
			//get key
			{
				int[] x = new int[k];
				BigInteger[] y = new BigInteger[k];
				
				for(int i=0; i<k; i++){
					x[i] = rShares[i].getNumber();
					y[i] = rShares[i].getShare();
				}
				
				BigInteger rKey = Interpolation(x, y, 0);
				constructedInfo[0] = rKey;

				for(int j=0; j<k-1; j++){
					yPoint[k-2][j] = Interpolation(x, y, j+1);
				}
			}
			//get other informations
			for(int i=k-2; i>=1; i--){
				
				int[] x = new int[i+1];
				BigInteger[] y = new BigInteger[i+1];
				
				for(int j=1; j<=i+1; j++){
					x[j-1] = i+j;
					y[j-1] = yPoint[i][j-1];
				}
				
				constructedInfo[i] = Interpolation(x, y, 0);
				
				for(int m=0; m<i; m++){
					yPoint[i-1][m] = Interpolation(x, y, m+1);
				}
			}
		}
		return constructedInfo;
	}

	private BigInteger Interpolation(int[] x, BigInteger[] y, int abscissa) {

		int l = x.length;
		BigInteger ordinate = BigInteger.ZERO;

        for(int i=0; i<l; i++)
        {
        	BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;
            for(int j=0; j<l; j++)
            {
                if(j!=i)
                {
                    numerator = numerator.multiply(BigInteger.valueOf(abscissa-x[j])).mod(prime);
                    denominator = denominator.multiply(BigInteger.valueOf(x[i]-x[j])).mod(prime);
                }
            }
            BigInteger yVal = y[i].multiply(numerator).multiply(modInverse(denominator, prime));
            ordinate = prime.add(ordinate).add(yVal).mod(prime);
        }
        
        return ordinate;
	}

    private BigInteger[] gcdD(BigInteger a, BigInteger b)
    { 
        if (b.compareTo(BigInteger.ZERO) == 0)
            return new BigInteger[] {a, BigInteger.ONE, BigInteger.ZERO}; 
        else
        { 
            BigInteger n = a.divide(b);
            BigInteger c = a.mod(b);
            BigInteger[] r = gcdD(b, c); 
            return new BigInteger[] {r[0], r[2], r[1].subtract(r[2].multiply(n))};
        }
    }

    private BigInteger modInverse(BigInteger k, BigInteger prime)
    { 
        k = k.mod(prime);
        BigInteger r = (k.compareTo(BigInteger.ZERO) == -1) ? (gcdD(prime, k.negate())[2]).negate() : gcdD(prime,k)[2];
        return prime.add(r).mod(prime);
    }
}