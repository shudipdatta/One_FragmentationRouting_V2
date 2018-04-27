package datahandler;
/**
 * CodecInterface defines the interfaces the a codec class must implement.
 */
public interface CodecInterface {

  /**
   * Encodes specified data blocks. This method is thread safe and reenterable.
   *
   * @param data The data blocks matrix
   * @return The coding blocks matrix
   */
  public byte[][] encode(byte[][] data);

  /**
   * Decodes specified failed data blocks. This method is thread safe and
   * reenterable.
   *
   * @param erasures The failed data blocks list
   * @param data The data blocks matrix
   * @param coding The coding blocks matrix
   */
  public void decode(int[] erasures, byte[][]data, byte[][] coding);
}
