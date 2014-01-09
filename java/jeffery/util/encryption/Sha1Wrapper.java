package jeffery.util.encryption;

import java.security.*;
public class Sha1Wrapper {
    private static MessageDigest md;
    public Sha1Wrapper () throws Exception
    {
         System.out.println("Sha1Wrapper");
        md = MessageDigest.getInstance("SHA1");
    }
    public byte[] get(String input)
    {
        md.update(input.getBytes()); 
        return md.digest();
    }
}
