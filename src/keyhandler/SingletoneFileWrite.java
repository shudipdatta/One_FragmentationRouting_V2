package keyhandler;

import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;

public class SingletoneFileWrite {
	private static SingletoneFileWrite thisObj;
	private final static String keyFile = "public_key_content.txt";
	private final static String msgFile = "frag_msg_content.txt";
	private final static String receivedFileNamePrefix = "received_by_";
	private final static String receivedFileDir = "ReceivedFiles";
	private String directory;
    /**
     * Create private constructor
     * @throws IOException 
     */
    private SingletoneFileWrite(String directory) {
    	this.directory = directory;
		try {
			File dfile = new File(directory);
			if(dfile.exists() == false) {
				dfile.mkdir();
			}
			File kfile = new File(directory+"/"+keyFile);
			File mfile = new File(directory+"/"+msgFile);
			Files.deleteIfExists(kfile.toPath());
			Files.deleteIfExists(mfile.toPath());

			File thisDirectory = new File(this.directory);
			for (File file : thisDirectory.listFiles()) {
				if(file.getName().startsWith(receivedFileNamePrefix)) {
					Files.deleteIfExists(file.toPath());
				}
			}
			
			File rfile = new File(directory+"/" + receivedFileDir);
			if(rfile.exists() == false) rfile.mkdir();
			for (File file : rfile.listFiles()) {
				Files.deleteIfExists(file.toPath());
			}
		
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    /**
     * Create a static method to get instance.
     */
    public static SingletoneFileWrite getInstance(String directory){
        if(thisObj == null){
			thisObj = new SingletoneFileWrite(directory);
        }
        return thisObj;
    }
     
    public void writeInFile(String type, String content){
    	BufferedWriter writer = null;
    	try {
	    	if(type == "KEY"){
	    		writer = new BufferedWriter(new FileWriter(directory+"/"+keyFile, true));
	    	}
	    	else if(type == "MSG") {
	    		writer = new BufferedWriter(new FileWriter(directory+"/"+msgFile, true));
	    	}
			writer.write(content);
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void writeInFile(String type, String content, String nodeName){
    	BufferedWriter writer = null;
    	try {
    		if(type == "RECEIVED") {
	    		writer = new BufferedWriter(new FileWriter(directory+"/"+receivedFileNamePrefix+nodeName+".txt", true));
	    	}
			writer.write(content);
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void writeInFile(String type, byte[] content, String fileName){
    	fileName = this.directory + "/"+ receivedFileDir +"/" + fileName.trim();
    	try {
    		DataOutputStream os = new DataOutputStream(new FileOutputStream(fileName));
			os.write(content);
			os.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
