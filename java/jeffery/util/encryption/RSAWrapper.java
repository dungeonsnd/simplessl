import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;
//import org.bouncycastle.util.encoders.Hex;
public class RSACoderSimple {
 
    public static String byte2hex(byte[] b) {
        String hs = ""; 
        String stmp = ""; 
        String tag ="\\x";
        for (int n = 0; n < b.length; n++) { 
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF)); 
            stmp =stmp.toUpperCase();
            if (stmp.length() == 1) 
                hs = hs + tag + "0" + stmp; 
            else 
                hs = hs + tag +stmp; 
        } 
        return hs; 
    } 
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        //numbers
        keyPairGen.initialize(2048);
        //key pair
        KeyPair keyPair = keyPairGen.generateKeyPair();
        //public key
        PublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        System.out.println("publicKey="+publicKey);
        //private key
        PrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        System.out.println("privateKey="+privateKey);

        //cipher class
        //Cipher cipher = Cipher.getInstance("RSA");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] plainText = "abcdefg".getBytes();
        System.out.println("plain="+byte2hex(plainText));
        
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] enBytes = cipher.doFinal(plainText);

        //decode
        System.out.println("after en="+byte2hex(enBytes));
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[]deBytes = cipher.doFinal(enBytes);
        System.out.println("after de="+byte2hex(deBytes));
    }
}
