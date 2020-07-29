import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.SecretKey;

public class EchoClient {
	
	
	// creating an object of DSE class
	
	
	
	public static PublicKey convertPublicKeyString(String pubkey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] publicBytes = Base64.getDecoder().decode(pubkey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		 return pubKey;
	}
	
	
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		System.out.println("Client started\n************This Alice************");
		
		//1. Creating RSA object
		RSA_USING_API rsa = new RSA_USING_API();
		
		// generating DES key
		SecretKey GeneratedDesKey = rsa.generate_random_session_key();
		
        System.out.println("DES generated Key:\n" + GeneratedDesKey);

		
		try {
			
			Socket soc = new Socket("localhost", 9000);
			//System.out.println("Enter a string");
			
			DataInputStream dIn = new DataInputStream(soc.getInputStream());
			
			// converting received string into publicKey
			String publicKeyReceived = dIn.readUTF();
			System.out.println("recieved Public Key:\n" + publicKeyReceived);
			PublicKey publickey = convertPublicKeyString(publicKeyReceived);
			
			System.out.println("key recived and converted successfully :D !");
			

			
			//-------------- After receiving the public key ------------------ //
			
	         
	        // 1. encrypting the random generated key
	        String encryptedKeyDES_Rsa = rsa.encryptMessage(GeneratedDesKey.toString(), publickey);
	        
	        
			//2. Encrypting the PlainText
	        System.out.println();
			EncryptDecryptStringWithDES DESObject = new EncryptDecryptStringWithDES( GeneratedDesKey.getEncoded());
			
			// getting Email encrypted
			String EmailEncrypted = DESObject.encryptedData;
			
			// setting DES key generated
			 // decryptStringWithDES.raw = GeneratedDesKey.getBytes();
			
			// 3. sending data back to server  ( encrypted key and encrypted plaintext )
			
			
	        // create a data output stream from the output stream so we can send data through it
	        DataOutputStream dataOutputStream = new DataOutputStream(soc.getOutputStream());

	        System.out.println("Sending string to the ServerSocket");

	        // write the message we want to send
	        dataOutputStream.writeByte(1);
	        System.out.println("sent encrypted key \n" + encryptedKeyDES_Rsa);
	        dataOutputStream.writeUTF(encryptedKeyDES_Rsa);
	        dataOutputStream.flush(); // send the message

	        
	        // write the message we want to send
	        dataOutputStream.writeByte(2);
	        dataOutputStream.writeUTF(EmailEncrypted);
	        dataOutputStream.flush(); // send the message
	        
	        
	        dataOutputStream.close(); // close the output stream when we're done.
	        System.out.println("Closing socket and terminating program.");
	        soc.close();
			
	        
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
