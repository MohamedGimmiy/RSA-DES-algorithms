import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
class EncryptDecryptStringWithDES {
	
String skeyString;
static byte[] raw;
String inputMessage,encryptedData,decryptedMessage;



//------------------- Decrypting DES key --------------------//

EncryptDecryptStringWithDES(byte[] ebyte, byte[] mykey) throws Exception{
	/*
	byte[] dbyte = decrypt(mykey, ebyte);
	
	String decryptedMessage = new String(dbyte);
	
	System.out.println("Decrypted message " + decryptedMessage);
	*/
}

//-------------------- Encrypting DES key --------------------//
public EncryptDecryptStringWithDES(byte [] generatedDes) {
	
	try {
	//generateSymmetricKey();
		// generateKey();
	raw = generatedDes;
	inputMessage = JOptionPane.showInputDialog("Write your Email");
	
	byte[] ibyte = inputMessage.getBytes();
	
	System.out.println("Encrypting key : " + raw);
	byte[] ebyte = encrypt(raw, ibyte);
	
	 encryptedData = ebyte.toString();
	
	System.out.println("Encrypted message "+encryptedData);
	
	
	//byte[] dbyte= decrypt(raw, ebyte);
	
	//String decryptedMessage = new String(dbyte);
	
	//System.out.println("Decrypted message "+decryptedMessage);
	
	}
	catch(Exception e) {
	System.out.println(e +" what ?!");
	}

}

//------------------- default of the class --------------------//
public EncryptDecryptStringWithDES() {
	
	try {
	//generateSymmetricKey();
		 raw= generateKey().getEncoded();
	inputMessage = JOptionPane.showInputDialog("Write your Email");
	
	byte[] ibyte = inputMessage.getBytes();
	System.out.println("sent key before function" + raw);
	byte[] ebyte = encrypt(raw, ibyte);
	
	 encryptedData = new String(ebyte);
	
	System.out.println("Encrypted message "+encryptedData);
	
	System.out.println("after function" + raw);
	byte[] dbyte = decrypt(raw, ebyte);
	
	String decryptedMessage = new String(dbyte);
	
	System.out.println("Decrypted message "+decryptedMessage);
	
	}catch(Exception e) {
		
	}
}
public SecretKey generateKey() throws NoSuchAlgorithmException {
	
	KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");

	SecureRandom secureRandom = new SecureRandom();
	int keyBitSize = 56;

	keyGenerator.init(keyBitSize, secureRandom);
	SecretKey secretKey = keyGenerator.generateKey();
	//System.out.println("key generated:" + secretKey);
	//System.out.println("key encoded" + secretKey.getEncoded());
	// converting the SecretKey into byte object
	
	return  secretKey;
	
	
}


private static byte[] encrypt(byte[] mykey, byte[] clear) throws Exception {
	System.out.println("key encryptes" + mykey);
	SecretKeySpec skeySpec = new SecretKeySpec(mykey, "DES");
	
	Cipher cipher = Cipher.getInstance("DES");
	
	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	
	byte[] encrypted = cipher.doFinal(clear);
	
	return encrypted;
}


public String bruteforce(byte[] encrypted, String plainText) {
	
	// get the key
	
	
	
	return null;
}



public static byte[] decrypt(byte[] mykey, byte[] encrypted) throws Exception {
	
	//System.out.println("raww : " + raww);
	//System.out.println("key decrypts" + mykey.toString());
	SecretKeySpec skeySpec = new SecretKeySpec(mykey, "DES");
	
	Cipher cipher = Cipher.getInstance("DES");
	
	cipher.init(Cipher.DECRYPT_MODE, skeySpec);
	
	byte[] decrypted = cipher.doFinal(encrypted);
	
	return decrypted;
}
/*
public static void main(String args[]) {
	EncryptDecryptStringWithDES des = new EncryptDecryptStringWithDES();
}
*/
}