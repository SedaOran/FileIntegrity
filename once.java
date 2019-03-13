import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Scanner;

import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;

public class once {
	static ArrayList<String> allfiles_names_paths = new ArrayList<String>();
	private static final String registerfile = "registerfile.txt";
	private static final String pubKeyFile = "pubKeyFile.txt";
	private static final String privKeyFile = "privKeyFile.txt";
	static File file = new File("registerfile.txt");
		
	static boolean registerfileexists = false;
	public static String signatureOld;
	public static String signatureNew;
	public static Signature sig;
	public static byte[] signatureBytes ;
	static PrivateKey privateKey;
	static PublicKey publicKey;
	static byte[] sigToVerify;
	static String hashMode;
	public static void main(String[] args) throws Exception {
		if(file.exists()) {
			registerfileexists = true;
		}
		
		File folder = new File("C:\\Users\\User\\eclipse-workspace\\info-lab\\odev2\\denemeler");
		BufferedWriter bw = null;
		FileWriter fw = null;
		
		File[] listOfFiles = folder.listFiles();
		allfiles_names_paths=FolderPath(listOfFiles,0,allfiles_names_paths);
		byte[] privateKeyBytes=null;
		byte[] publicKeyBytes=null;
	    String strline=null;
	    String sCurrentLine;
		String registerFileHashValue = null;

	
		BufferedReader br_input = null;
		System.out.println("please select MD5 or SHA-512:");
		Scanner input = new Scanner(System.in);
		hashMode = input.nextLine();
		
		if(registerfileexists==false) {
			
			try {
				
				fw = new FileWriter(registerfile);
				bw = new BufferedWriter(fw);
			
				KeyPair pair = FileClass.generateKeyPair();
				publicKey = pair.getPublic();
				privateKey = pair.getPrivate();
				
				String FinalHashValue =null;
				if(hashMode.equals("SHA-512")) {
					FinalHashValue = HashFuncSHA(FinalHashValue(fw, bw, true,hashMode));

				}
				if(hashMode.equals("MD5")) {
					FinalHashValue = HashFuncMd5(FinalHashValue(fw, bw, true,hashMode));

				}
				sig = Signature.getInstance("SHA1WithRSA");
		        sig.initSign(privateKey);
		        sig.update(FinalHashValue.getBytes());
		        signatureBytes = sig.sign();
		        signatureOld = new BASE64Encoder().encode(signatureBytes);
		        //System.out.println("Signature: "+signatureOld);
		        System.out.println();
		        String bytesEncoded = Base64.encode(signatureBytes);
				bw.write(signatureOld);
				//System.out.println("SIGNATURE:    "+ signatureOld);
				
				X509EncodedKeySpec x509EncodedKeySpec_public = new X509EncodedKeySpec(publicKey.getEncoded());
				X509EncodedKeySpec x509EncodedKeySpec_private = new X509EncodedKeySpec(privateKey.getEncoded());

				FileOutputStream fos_pubKey = new FileOutputStream(new File(pubKeyFile));
				FileOutputStream fos_privKey = new FileOutputStream(new File(privKeyFile));

				fos_privKey.write(x509EncodedKeySpec_private.getEncoded());
			    fos_privKey.close();
			    fos_pubKey.write(x509EncodedKeySpec_public.getEncoded());
			    fos_pubKey.close();
			
							
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				try {
					if (bw != null)
						bw.close();
					if (fw != null)
						fw.close();
					
				} catch (IOException ex) {
					ex.printStackTrace();
				}
			}
		}	
		else {
			String FinalHashValue=null;
			BufferedReader brr = new BufferedReader(new FileReader(registerfile));
			File filePublicKey = new File(pubKeyFile);
			FileInputStream fis_pubKey = new FileInputStream(pubKeyFile);
			if(hashMode.equals("SHA-512")) {
				FinalHashValue = HashFuncSHA(FinalHashValue(fw, bw, false,hashMode));

			}
			else if(hashMode.equals("MD5")) {
				FinalHashValue = HashFuncMd5(FinalHashValue(fw, bw, false,hashMode));

			}
			String line;

		    while ((sCurrentLine = brr.readLine()) != null) 
		    {
		        //System.out.println(sCurrentLine);
		        strline = sCurrentLine;
		    }
		    String lastLine = strline;
		    byte[] keyBytes = new byte[(int)filePublicKey.length()];
		    fis_pubKey.read(keyBytes);
		    fis_pubKey.close();

		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		    publicKey = kf.generatePublic(spec);
			
			Signature signature = Signature.getInstance("SHA1WithRSA");
			signature.initVerify(publicKey);
			signature.update(FinalHashValue.getBytes());	        
	        
			sigToVerify = Base64.decode(lastLine);
	        boolean result = signature.verify(sigToVerify);
	        
	        if (result == false) {
	        	System.out.println("FILE CHANGED");
	        	
	        	Writer writer = null;
	        	Timestamp timestamp = new Timestamp(System.currentTimeMillis());
	        	try {
	        	    writer = new BufferedWriter(new OutputStreamWriter(
	        	          new FileOutputStream("log.txt"), "utf-8"));
	        	    writer.write(timestamp+":  verification failed ");
	        	} catch (IOException ex) {
	        	    // Report
	        	} finally {
	        	   try {writer.close();} catch (Exception ex) {/*ignore*/}
	        	}
	        	try {
	        		File filePrivateKey = new File(privKeyFile);
				    byte[] keyBytes_priv = new byte[(int)filePrivateKey.length()];

					FileInputStream fis_privKey = new FileInputStream(filePrivateKey);
		        	fw = new FileWriter(registerfile);
					bw = new BufferedWriter(fw);
					if(hashMode.equals("SHA-512")) {
						HashFuncSHA(FinalHashValue(fw, bw, true,hashMode));

					}
					if(hashMode.equals("MD5")) {
						HashFuncMd5(FinalHashValue(fw, bw, true,hashMode));

					}
					
				    fis_privKey.read(keyBytes_priv);
				    fis_privKey.close();
					
				    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes_priv);
				    KeyFactory keyfac = KeyFactory.getInstance("RSA");
				    PrivateKey privKey =  keyfac.generatePrivate(keySpec);
				    
				    sig = Signature.getInstance("SHA1WithRSA");
			        sig.initSign(privKey);
			        sig.update(FinalHashValue.getBytes());
			        signatureBytes = sig.sign();
			        signatureOld = new BASE64Encoder().encode(signatureBytes);
					bw.write(signatureOld);
	        	}
	        	catch (IOException e) {
					e.printStackTrace();
				} finally {
					try {
						if (bw != null)
							bw.close();
						if (fw != null)
							fw.close();
						
					} catch (IOException ex) {
						ex.printStackTrace();
					}
				}			
	        }
	        else {
	        	System.out.println("FILE NOT CHANGED");
	        	Writer writer = null;
	        	Timestamp timestamp = new Timestamp(System.currentTimeMillis());
	        	try {
	        	    writer = new BufferedWriter(new OutputStreamWriter(
	        	          new FileOutputStream("log.txt"), "utf-8"));
	        	    writer.write(timestamp+": verification ");
	        	} catch (IOException ex) {
	        	    // Report
	        	} finally {
	        	   try {writer.close();} catch (Exception ex) {/*ignore*/}
	        	}
	        }
	        System.out.println();
		}
	}
	
	public static String FinalHashValue(FileWriter fw, BufferedWriter bw, boolean change, String hashMode) throws IOException {
		String line;
		String strline = null;
		String registerFileHashValue = null;
		for (int i = 0; i < allfiles_names_paths.size(); i++) {	
			String HashValue=null;
			BufferedReader br = new BufferedReader(new FileReader(allfiles_names_paths.get(i)));

		    while ((line = br.readLine()) != null) 
		    {
		        strline+= line;
		    }
			String LongString = strline;
			if(hashMode.equals("SHA-512")) {
				HashValue = HashFuncSHA(LongString);

			}
			if(hashMode.equals("MD5")) {
				HashValue = HashFuncMd5(LongString);

			}
			registerFileHashValue+=allfiles_names_paths.get(i)+HashValue;
			if(change==true) {
				bw.write(allfiles_names_paths.get(i)+" ");
				bw.write(HashValue);
				bw.newLine();
			}
		}
		return registerFileHashValue;
	}
	public static ArrayList<String> FolderPath(File[] listOfFiles,int numberOfFiles , ArrayList<String> all_files_name_paths){
		
		for (File file : listOfFiles) {
		    if (file.isFile()) {
		        numberOfFiles++; 
		        all_files_name_paths.add(file.getAbsolutePath());
		    }
		    else if(file.isDirectory()) {
				listOfFiles=file.listFiles();
				FolderPath(listOfFiles,numberOfFiles,all_files_name_paths);
			}
		}
		return all_files_name_paths;
	}
	public static String HashFuncSHA(String input) 
    { 
        try { 
            // getInstance() method is called with algorithm SHA-512 
            MessageDigest filetext = MessageDigest.getInstance("SHA-512"); 
  
            byte[] file_index_digest = filetext.digest(input.getBytes()); 
            BigInteger no = new BigInteger(1, file_index_digest); 
            String hash_file_text = no.toString(16); 
  
            while (hash_file_text.length() < 32) { 
            	hash_file_text = "0" + hash_file_text; 
            } 
            return hash_file_text; 
        } 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
	public static String HashFuncMd5(String input) 
    { 
        try { 
            MessageDigest filetext = MessageDigest.getInstance("MD5"); 
            byte[] file_index_digest = filetext.digest(input.getBytes()); 
  
            BigInteger no = new BigInteger(1, file_index_digest); 
              String hash_file_text = no.toString(16); 
            while (hash_file_text.length() < 32) { 
            	hash_file_text = "0" + hash_file_text; 
            } 
            return hash_file_text; 
        }  
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
	public static String toLongString(String shortlines) throws IOException {
		String longstring=""; 
		String my_file = "";

		File file = new File(shortlines); 
		  
		BufferedReader br = new BufferedReader(new FileReader(file)); 
		while ((longstring = br.readLine()) != null){
		  //System.out.println(longstring);
		  
		  my_file += longstring;
		}
		return my_file;
	}
}