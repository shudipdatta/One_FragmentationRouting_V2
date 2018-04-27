package datahandler;

public class SingletoneCauchyMatrix {

	private static ErasureCodec highCodec;
	private static ErasureCodec medCodec;
	private static ErasureCodec lowCodec;
	
	public static ErasureCodec getCodec(int dataFragmentK, int factorKN, int wordSize, int packetSize) {
		
		int dataFragmentN;
		
		switch(factorKN) {
        case 1:
    	    dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.highDataFactorKN);
   		
	   		if(highCodec == null) {
	   			highCodec = new ErasureCodec.Builder(ErasureCodec.Algorithm.Cauchy_Reed_Solomon)
	   		            .dataBlockNum(dataFragmentK)
	   		            .codingBlockNum(dataFragmentN-dataFragmentK)
	   		            .wordSize(wordSize)
	   		            .packetSize(packetSize)
	   		            .good(true)
	   		            .build();
	   		}		
	   		return highCodec;
	   		
		case 3:
    	    dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.lowDataFactorKN);

	   		if(lowCodec == null) {
	   			lowCodec = new ErasureCodec.Builder(ErasureCodec.Algorithm.Cauchy_Reed_Solomon)
	   		            .dataBlockNum(dataFragmentK)
	   		            .codingBlockNum(dataFragmentN-dataFragmentK)
	   		            .wordSize(wordSize)
	   		            .packetSize(packetSize)
	   		            .good(true)
	   		            .build();
	   		}		
	   		return lowCodec;
        default:
    	    dataFragmentN = (int)Math.ceil(dataFragmentK * Constant.medDataFactorKN);

	   		if(medCodec == null) {
	   			medCodec = new ErasureCodec.Builder(ErasureCodec.Algorithm.Cauchy_Reed_Solomon)
	   		            .dataBlockNum(dataFragmentK)
	   		            .codingBlockNum(dataFragmentN-dataFragmentK)
	   		            .wordSize(wordSize)
	   		            .packetSize(packetSize)
	   		            .good(true)
	   		            .build();
	   		}		
	   		return medCodec;
	    }
	}
}