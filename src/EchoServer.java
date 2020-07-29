import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;

import javax.crypto.SecretKey;

import java.security.PublicKey;

public class EchoServer {
    public static String  recieved_encrypted_key, recieved_encrypted_email;

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		System.out.println("waiting for clients.....");
		   System.out.println("*************This is Bob*************. ");
		   
		try {
			ServerSocket ss = new ServerSocket(9000);
			Socket soc = ss.accept();
			System.out.println("Connection established...");
			
			//1. Rsa constructing public key and private key
			RSA_USING_API rsa = new RSA_USING_API();
	        Map<String, Object> keys = rsa.getRSAKeys();
	        
	        PublicKey publickey = (PublicKey)keys.get("public");
	        
	        // encoding public key
	        String publickeyString = Base64.getEncoder().encodeToString(publickey.getEncoded());
	        
	        System.out.println("Public Key sent: \n"+publickeyString);
	        //2. get the output stream from the socket.
	        // create a data output stream from the output stream so we can send data through it
	        DataOutputStream dataOutputStream = new DataOutputStream(soc.getOutputStream());

	        // write the message we want to send (sending public key)
	        
	        dataOutputStream.writeUTF(publickeyString);
	        
	        dataOutputStream.flush(); // send the message 
	        System.out.println("Public Key Sent Successfully ! :D !");
	        
	        
	        //3. Receiving encrypted key and encrypted plain text
	        
	        DataInputStream dataInputStream = new DataInputStream(soc.getInputStream());
	        
	        boolean done = false;
	        
	        while(!done) {
	        	byte messageType = dataInputStream.readByte();
	        	
	        	switch (messageType) {
				case 1:
					recieved_encrypted_key = dataInputStream.readUTF();
					System.out.println("Recived Encrypted Key 1: \n"+ recieved_encrypted_key);
					break;
				case 2:
					recieved_encrypted_email = dataInputStream.readUTF();
					System.out.println("Recived Encrypted DES EMAIL: \n"+ recieved_encrypted_email);
				default:
					done = true;
				}
	        }
	        
	        // 4
	        
	        //4.1 Decrypting the key using RSA private key
	        byte[] KEY = rsa.decryptMessage( recieved_encrypted_key, (PrivateKey)keys.get("private"));
	        System.out.println("decrypted key:\n" + KEY.toString().getBytes() + KEY.toString().length());
	        
	        
	        //4.2 Decrypting Email message and displaying it
	        EncryptDecryptStringWithDES des = 
	        		new EncryptDecryptStringWithDES(recieved_encrypted_email.getBytes(), 
	        				KEY);
	        // generate des key
	        //SecretKey s = des.generateKey()
	        
	        byte[]d = des.decrypt(KEY.toString().getBytes(), recieved_encrypted_email.getBytes());
	        
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
		}
		
	}

}
