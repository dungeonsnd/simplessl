import java.io.*;  
import java.security.*;  
import javax.crypto.*;  
import javax.crypto.spec.*;  
  
/** 
* <p>Description: </p> 
* <p>Copyright: Copyright (c) 2003</p> 
* <p>Company: </p> 
* @author not attributable 
* @version 1.0 
*/  
  
public class RSAKeyWrapper {  
private KeyPairGenerator kpg = null;  
private KeyPair kp = null;  
private PublicKey public_key = null;  
private PrivateKey private_key = null;  
private FileOutputStream public_file_out = null;  
private ObjectOutputStream public_object_out = null;  
private FileOutputStream private_file_out = null;  
private ObjectOutputStream private_object_out = null;  
  
/** 
  */  
public RSAKeyWrapper(int in, String address) throws NoSuchAlgorithmException,FileNotFoundException, IOException   
    {  
        kpg = KeyPairGenerator.getInstance("RSA"); //generate pair  
        kpg.initialize(in); //(512-2048)  
        kp = kpg.genKeyPair(); //  
        public_key = kp.getPublic(); //  
        private_key = kp.getPrivate(); //  
        //  
        public_file_out = new FileOutputStream(address + "/public_key.dat");  
        public_object_out = new ObjectOutputStream(public_file_out);  
        public_object_out.writeObject(public_key);  
        //  
        private_file_out = new FileOutputStream(address + "/private_key.dat");  
          
        private_object_out = new ObjectOutputStream(private_file_out);  
        private_object_out.writeObject(private_key);  
  }  
  
  public static void main(String[] args) {  
    try {  
      System.out.println("generated");  
      new RSAKeyWrapper(2048, "./");  
    }  
    catch (IOException ex) {  
    }  
    catch (NoSuchAlgorithmException ex) {  
    }  
  }  
}  
