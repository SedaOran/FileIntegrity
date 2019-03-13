import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class FileClass {
	
	public static KeyPair generateKeyPair() throws Exception {
	    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    generator.initialize(2048, new SecureRandom());
	    KeyPair pair = generator.generateKeyPair();
	     
	    PrivateKey privKey = pair.getPrivate();   
	      
	    PublicKey publicKey = pair.getPublic(); 
	    return pair;
	}
}


