package keyhandler;

import java.io.*;  
import java.util.Iterator;  
import javax.imageio.*;  
import javax.imageio.stream.*;  
import java.awt.image.*;  
  
public class ImageFileSizeReducer {  
	private static final int sizeThreshold=4*1024*1024;
  
    public static void reduceImageQuality(String srcImg, String destImg) {  
    	try {
	        float quality = 1.0f;  
	  
	        File file = new File(srcImg);  
	  
	        long fileSize = file.length();  
	  
	        if (fileSize <= sizeThreshold) {  
	            //System.out.println("Image file size is under threshold");  
	            return;  
	        }  
	  
	        Iterator iter = ImageIO.getImageWritersByFormatName("jpeg");  
	  
	        ImageWriter writer = (ImageWriter)iter.next();  
	  
	        ImageWriteParam iwp = writer.getDefaultWriteParam();  
	  
	        iwp.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);  
	  
	        FileInputStream inputStream = new FileInputStream(file);  
	  
	        BufferedImage originalImage;
			originalImage = ImageIO.read(inputStream); 
	        IIOImage image = new IIOImage(originalImage, null, null);  
	  
	        float percent = 0.1f;   // 10% of 1  
	  
	        while (fileSize > sizeThreshold) {  
	            if (percent >= quality) {  
	                percent = percent * 0.1f;  
	            }  
	  
	            quality -= percent;  
	  
	            File fileOut = new File(destImg);  
	            if (fileOut.exists()) {  
	                fileOut.delete();  
	            }  
	            FileImageOutputStream output = new FileImageOutputStream(fileOut);  
	  
	            writer.setOutput(output);  
	  
	            iwp.setCompressionQuality(quality);  
	  
	            writer.write(null, image, iwp);  
	  
	            File fileOut2 = new File(destImg);  
	            long newFileSize = fileOut2.length();  
	            if (newFileSize == fileSize) {  
	                // cannot reduce more, return  
	                break;  
	            } else {  
	                fileSize = newFileSize;  
	            }  
	            //System.out.println("quality = " + quality + ", new file size = " + fileSize);  
	            output.close();  
	        }  
	  
	        writer.dispose();  
        } 
    	catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
    } 
}