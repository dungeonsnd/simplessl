import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AESDemo {
//	protected static String hexStr =new String("01020304050607080900010203040506");
	protected static String hexStr =new String("01010101010101010101010101010101");

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    public static void printHexString( byte[] b) { 
    	for (int i = 0; i < b.length; i++) { 
    		String hex = Integer.toHexString(b[i] & 0xFF); 
    		if (hex.length() == 1) 
    		hex = '0' + hex;
        	System.out.print(hex.toUpperCase() ); 
    	}  
    	System.out.println(" ");
    } 
    public static String encrypt(String strKey, String strIn) throws Exception {
        byte[] arrA =hexStringToByteArray(hexStr);
                
        SecretKeySpec skeySpec = new SecretKeySpec(strKey.getBytes(), "AES");
        System.out.print("key=0x");
        printHexString(arrA);

        String ivString =hexStr;
        System.out.println("ivString=0x"+ivString);        
        IvParameterSpec iv = new IvParameterSpec( hexStringToByteArray(ivString) );

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
//        System.out.println( "BlockSize="+cipher.getBlockSize() );  
        byte[] encrypted = cipher.doFinal(strIn.getBytes());   

        System.out.print( "Encrypted bytes are:" );
        for(int j=0;j<encrypted.length;j++){
        	System.out.print( encrypted[j]&0x000000ff );
        	System.out.print( " " );
        }
        System.out.println( " " );
        
        return new BASE64Encoder().encode(encrypted);
    }

    public static String decrypt(String strKey, String strIn) throws Exception {
        byte[] arrA =hexStringToByteArray(hexStr);
        SecretKeySpec skeySpec = new SecretKeySpec(strKey.getBytes(), "AES");

        String ivString=hexStr;
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec( hexStringToByteArray(ivString) );
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        
        byte[] encrypted1 = new BASE64Decoder().decodeBuffer(strIn);
        byte[] original = cipher.doFinal(encrypted1);
        return new String(original);
    }


    public static void main(String[] args) throws Exception {
    	
        String Code = "1234567890ÄãºÃ";
        String key = "1234567890123456";
        String codE;
        
        codE = AESDemo.encrypt(key, Code);

        System.out.println("Plaintext:" + Code);
        System.out.println("ÃÜÔ¿£º" + key);
        System.out.println("Ciphertext:" + codE);
        System.out.println("Decrypted:" + AESDemo.decrypt(key, codE));
    }
}
