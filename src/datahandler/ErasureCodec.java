package datahandler;
/**
 * ErasureCodec defines methods for users to encode given data block to
 * erasure codes block, and to decode data block from given data and erasure
 * codes blocks.
 */
public class ErasureCodec implements CodecInterface {

  /**
   * Currently supported coding algorithms.
   */
  public enum Algorithm {
    Reed_Solomon,
    Cauchy_Reed_Solomon;
  }

  /**
   * Builder class for ErasureCodec.
   */
  public static class Builder {
    private Algorithm algorithm;
    private int dataBlockNum;
    private int codingBlockNum;
    private int wordSize;
    private int packetSize;
    private boolean good;

    public Builder(Algorithm algorithm) {
      this.algorithm = algorithm;
    }

    public ErasureCodec build() {
      CodecInterface codec = null;
      switch (algorithm) {
        case Reed_Solomon:
          codec = new ReedSolomonCodec(dataBlockNum, codingBlockNum, wordSize);
          break;
        case Cauchy_Reed_Solomon:
          codec = new CauchyReedSolomonCodec(dataBlockNum, codingBlockNum,
              wordSize, packetSize, good);
          break;
        default:
          throw new IllegalArgumentException("Algorithm is not supported: "
              + algorithm);
      }
      return new ErasureCodec(codec);
    }

    public Builder dataBlockNum(int dataBlockNum) {
      this.dataBlockNum = dataBlockNum;
      return this;
    }

    public Builder codingBlockNum(int codingBlockNum) {
      this.codingBlockNum = codingBlockNum;
      return this;
    }

    public Builder wordSize(int wordSize) {
      this.wordSize = wordSize;
      return this;
    }

    public Builder packetSize(int packetSize) {
      this.packetSize = packetSize;
      return this;
    }

    public Builder good(boolean good) {
      this.good = good;
      return this;
    }
  }

  private CodecInterface wrappedCodec;

  private ErasureCodec(CodecInterface codec) {
    wrappedCodec = codec;
  }

  /** {@inheritDoc} */
  @Override
  public byte[][] encode(byte[][] data) {
    return wrappedCodec.encode(data);
  }

  /** {@inheritDoc} */
  @Override
  public void decode(int[] erasures, byte[][] data, byte[][] coding) {
    wrappedCodec.decode(erasures, data, coding);
  }
}
