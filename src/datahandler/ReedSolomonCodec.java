package datahandler;
import com.google.common.base.Preconditions;
import com.sun.jna.Pointer;
/**
 * Normal Reed Solomon erasure codec, implemented with Vandermonde matrix.
 */
public class ReedSolomonCodec implements CodecInterface {

  private int dataBlockNum;
  private int codingBlockNum;
  private int wordSize;
  private int[] vandermondeMatrix;

  public ReedSolomonCodec(int dataBlockNum, int codingBlockNum, int wordSize) {
    Preconditions.checkArgument(dataBlockNum > 0);
    Preconditions.checkArgument(codingBlockNum > 0);
    Preconditions.checkArgument(wordSize == 8 || wordSize == 16 ||
        wordSize == 32, "wordSize must be one of 8, 16 and 32");
    Preconditions.checkArgument((dataBlockNum + codingBlockNum) < (1<<wordSize),
        "dataBlocksNum + codingBlocksNum is larger than 2^wordSize");

    this.dataBlockNum = dataBlockNum;
    this.codingBlockNum = codingBlockNum;
    this.wordSize = wordSize;
    this.vandermondeMatrix = createVandermondeMatrix(this.dataBlockNum,
        this.codingBlockNum, this.wordSize);
  }

  /** {@inheritDoc} */
  @Override
  public byte[][] encode(byte[][] data) {
    Preconditions.checkArgument(data.length > 0);

    Pointer[] dataPtrs = CodecUtils.toPointerArray(data);
    int size = data[0].length;
    byte[][] coding = new byte[codingBlockNum][size];
    Pointer[] codingPtrs = CodecUtils.toPointerArray(coding);

    JerasureLibrary.INSTANCE.jerasure_matrix_encode(dataBlockNum,
        codingBlockNum, wordSize, vandermondeMatrix, dataPtrs, codingPtrs, size);
    CodecUtils.toByteArray(codingPtrs, coding);
    return coding;
  }

  /** {@inheritDoc} */
  @Override
  public void decode(int[] erasures, byte[][]data, byte[][] coding) {
    Preconditions.checkArgument(data.length > 0);

    Pointer[] dataPtrs = CodecUtils.toPointerArray(data);
    Pointer[] codingPtrs = CodecUtils.toPointerArray(coding);
    erasures = CodecUtils.adjustErasures(erasures);
    int size = data[0].length;

    int ret = JerasureLibrary.INSTANCE.jerasure_matrix_decode(dataBlockNum,
        codingBlockNum, wordSize, vandermondeMatrix, 1, erasures,
        dataPtrs, codingPtrs, size);
    if (ret == 0) {
      CodecUtils.copyBackDecoded(dataPtrs, codingPtrs, erasures, data, coding);
    } else {
      throw new RuntimeException("Decode fail, return_code=" + ret);
    }
  }

  /**
   * Creates a Vandermonde matrix of m x k over GF(2^w).
   *
   * @param k The column number
   * @param m The row number
   * @param w The word size, used to define the finite field
   * @return The generated Vandermonde matrix
   */
  int[] createVandermondeMatrix(int k, int m, int w) {
    Pointer matrix = JerasureLibrary.INSTANCE
        .reed_sol_vandermonde_coding_matrix(k, m, w);
    return matrix.getIntArray(0, k * m);
  }
}
