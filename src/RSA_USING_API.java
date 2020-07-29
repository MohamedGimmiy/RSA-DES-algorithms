import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
 
// Java 8 example for RSA encryption/decryption.
// Uses strong encryption with 2048 key size.
public class RSA_USING_API {
 /*
    public static void main(String[] args) throws Exception {
    	
    	
    	

    	
        //String plainText = "Hello World!";
 
        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();
 
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");
 
        String encryptedText = encryptMessage(plainText, publicKey  );
        String descryptedText = decryptMessage(encryptedText,privateKey );
 
        System.out.println("input:" + plainText);
        System.out.println("encrypted:" + encryptedText);
        System.out.println("decrypted:" + descryptedText);
 
    }
    */
    
    //----------- Generate random session key ---------------//
    public SecretKey generate_random_session_key() throws NoSuchAlgorithmException {
    	
    	//GENERATING A random session key
      	 
    	KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");

    	SecureRandom secureRandom = new SecureRandom();
    	int keyBitSize = 56;

    	keyGenerator.init(keyBitSize, secureRandom);
    	SecretKey secretKey = keyGenerator.generateKey();

    	//System.out.println("Generated Key" + secretKey.getEncoded().toString());
    	
    	return secretKey;
    	//String plainText = secretKey.getEncoded().toString();
    }
 
    // Get RSA keys. Uses key size of 2048.
    public  Map<String,Object> getRSAKeys() throws Exception {
    	
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
 
        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
 
    // Decrypt using RSA public key
    public  byte[] decryptMessage(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey );
        return cipher.doFinal(Base64.getDecoder().decode(encryptedText));
    }
 
    // Encrypt using RSA private key
    public  String encryptMessage(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
 
}