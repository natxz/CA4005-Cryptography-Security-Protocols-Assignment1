import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.*;
import java.util.Random;


public class Assignment {

    public static  BigInteger randomValue(int bits){

        Random rand = new Random();
        BigInteger  result = new BigInteger(bits, rand);
        return result;

    }
     public static BigInteger mod(BigInteger sum,BigInteger p)
    {
       // BigInteger bi = sum.remainder(p);
        //return bi;
        return sum.remainder(p);

    }
public static BigInteger modExp(BigInteger base, BigInteger exp,BigInteger m)
    {
        BigInteger sum= BigInteger.ONE;
        BigInteger zero = new BigInteger("0");
        BigInteger one = new BigInteger("1");

        
        for(int dx=0; dx <exp.bitLength(); ++dx ){
            
            sum = sum.multiply(base).mod(m);
            if (exp.and(one).equals(one))
                sum =mod(sum.multiply(base),m);
                exp = exp.shiftRight(1);
                base=mod(sum.multiply(base),m);
        }
        return sum;                             
    }
   public static  byte [] encodeBigInteger(BigInteger sharedkey)
    { 
        try{
                MessageDigest md = MessageDigest.getInstance("SHA-256");

                 // generates the 256-bit AES key k
                byte [] key= sharedkey.toByteArray(); 
                md.update(key); //Updates the digest using the specified array of bytes
                byte [] digestbuf = md.digest(); 
                return digestbuf;
               
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;  
    }

    public static byte[] encrypt(BigInteger key, BigInteger plaintext) {
        BigInteger textPadded = padding(plaintext);
        try {
            BigInteger IV = new BigInteger("82d158e922104097c1617cc313eaccf8", 16);
            SecretKeySpec secretKeySpec = new SecretKeySpec(IntegerByteArray(key), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IntegerByteArray(IV));
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(IntegerByteArray(textPadded));
        } catch (Exception e) {
            e.printStackTrace();;
        }
        return null;
    }
    public static byte[] IntegerByteArray(BigInteger b) {
        byte[] a = b.toByteArray();
        if (a[0] == 0) {
            a = Arrays.copyOfRange(a, 1, a.length);
        }
        return a;
    }
    
    public static BigInteger padding(BigInteger plaintext) {
        String plainString = plaintext.toString(2);
        int r = 128 - plainString.length()%128;
        if (r == 0) {
            r = 128;
        }
        plainString += "1";
        for(int i = 1; i < r; i++) {
            plainString += "0";
        }
        return new BigInteger(plainString, 2);
    }

    
     public static void main(String[] args) {
        try {
            /*              variables to to test out modExpo, if 123^5(mod 511)== to 359 then equates succesfully
            int base =123;
            int exp =5;
            int m = 511;
            BigInteger base1 = new BigInteger(String.valueOf(base));
            BigInteger exp1 = new BigInteger(String.valueOf(exp));
            BigInteger m1 = new BigInteger(String.valueOf(m));
            BigInteger tester = modExp(base1, exp1, m1);
            System.out.println(tester); */

            String fileName = null;
             BigInteger b = randomValue(1023);
            BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
            BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
            BigInteger pubA_ = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);
            
            BigInteger pubB_ = modExp(g, b, p);
             //print out the PUBLIC KEY of B
            String BBBBB = pubB_.toString(16);
            System.out.println("YOUR PUBLIC KEY IS      " + BBBBB);
           

            BigInteger sharedkey = modExp(pubA_, b, p);
            BigInteger encodedKey = new BigInteger(1, encodeBigInteger(sharedkey));


             
            if(args.length < 1){
                fileName = "Assignment.class";
            } else {
                fileName = args[0];
            }

            BigInteger plaintext = new BigInteger(Files.readAllBytes(Paths.get(fileName)));
            BigInteger encrypted = new BigInteger(encrypt(encodedKey, plaintext));
            String s = encrypted.toString(16);
            File file = new File("Encrypted.txt");
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(s);
            fileWriter.flush();
            fileWriter.close();
            System.out.println("The File has been succesfully enncrypted into:   Encrypted.txt " );

            

        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

}