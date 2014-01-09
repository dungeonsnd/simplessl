
import jeffery.util.encryption.Sha1Wrapper;

public class Sha1Example {
    private static Sha1Wrapper sha1wrapper;
    public static void main(String[] a) {
      try {
         sha1wrapper =new Sha1Wrapper();
         String input = "";
         byte[] output = sha1wrapper.get(input);
         System.out.println("SHA1(\""+input+"\") =");
         System.out.println("   "+bytesToHex(output));

         input = "abc";
         output = sha1wrapper.get(input);
         System.out.println("SHA1(\""+input+"\") =");
         System.out.println("   "+bytesToHex(output));

         input = "abcdefghijklmnopqrstuvwxyz";
         output = sha1wrapper.get(input);
         System.out.println("SHA1(\""+input+"\") =");
         System.out.println("   "+bytesToHex(output));
         
      } catch (Exception e) {
         System.out.println("Exception: "+e);
      }
   }
   
   public static String bytesToHex(byte[] b) {
      char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
      StringBuffer buf = new StringBuffer();
      for (int j=0; j<b.length; j++) {
         buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
         buf.append(hexDigit[b[j] & 0x0f]);
      }
      return buf.toString();
   }
}
