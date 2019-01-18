package net.bplaced.javacrypto.asymmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 13.01.2019
* Funktion: verschlüsselt einen Text mittels ECIES (Asymmetrisch)
* Function: encrypts a text string using ECIES (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C05_EciesJava11 {
	public static void main(String[] args) throws Exception {
		System.out.println("C05 ECIES Verschlüsselung");

		// benötigt Bouncy Castle
		Security.addProvider(new BouncyCastleProvider());

		String plaintextString = "Das ist die geheime Nachricht";
		//String plaintextString ="1234567890123456789012345678901234567890123456789012345678901234567890";
		byte[] plaintextByte = plaintextString.getBytes("utf-8");
		byte[] ciphertextByte = null;
		byte[] decryptedtextByte = null;
		
		// erzeugung eines schlüsselpaares
		KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("ECIES", "BC");
		// name der verwendeten kurve
		String curveNameString = "secp256r1";
		//String curveNameString = "secp256k1";
		//String curveNameString = "brainpoolP256R1";
		//String curveNameString = "secp384r1";
		//String curveNameString = "secp521r1";
		ecGenerator.initialize(new ECGenParameterSpec(curveNameString)); // der name der verwendeten kurve
		KeyPair ecKeyPair = ecGenerator.generateKeyPair();
		ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
		ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();

		// verschlüsselung mit dem öffentlichen schlüssel
		ciphertextByte = EcEncrypt(plaintextByte, ecPublicKey);
		// entschlüsselung mit dem privaten schlüssel
		decryptedtextByte = EcDecrypt(ciphertextByte, ecPrivateKey);
		
		System.out.println();
		System.out.println("ECIES Schlüsselerzeugung");
		System.out.println("verwendete Elliptic Curve:" + curveNameString);
		System.out.println("ecPrivateKey (Byte) Länge:" + ecPrivateKey.getEncoded().length + " Bytes");
		System.out.println(byteArrayPrint(ecPrivateKey.getEncoded(), 33));
		System.out.println("ecPublicKey (Byte)  Länge:" + ecPublicKey.getEncoded().length + " Bytes");
		System.out.println(byteArrayPrint(ecPublicKey.getEncoded(), 33));
		System.out.println();
		System.out.println("ECIES Verschlüsselung");
		System.out.println("plaintextString    :" + plaintextString);
		System.out.println("plaintextByte      Länge:" + plaintextByte.length + " Bytes Data:"
				+ printHexBinary(plaintextByte));
		System.out.println("ciphertextByte     Länge:" + ciphertextByte.length + " Bytes");
		System.out.println(byteArrayPrint(ciphertextByte,33));
		System.out.println("decryptedtextByte  :" + printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString:" + new String(decryptedtextByte));
		System.out.println();
	}

	public static byte[] EcEncrypt(byte[] plaintextByte, ECPublicKey publicKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		byte[] ciphertextByte = null;
		Cipher encryptCipher = Cipher.getInstance("ECIES", "BC");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		ciphertextByte = encryptCipher.doFinal(plaintextByte);
		return ciphertextByte;
	}

	public static byte[] EcDecrypt(byte[] ciphertextByte, ECPrivateKey privateKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		byte[] decryptedtextByte = null;
		Cipher decryptCipher = Cipher.getInstance("ECIES", "BC");
		decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
		decryptedtextByte = decryptCipher.doFinal(ciphertextByte);
		return decryptedtextByte;
	}
	
	public static String byteArrayPrint(byte[] byteData, int numberPerRow) {
		String returnString = "";
		String rawString = printHexBinary(byteData);
		int rawLength = rawString.length();
		int i = 0;
		int j = 1;
		int z = 0;
		for (i = 0; i < rawLength; i++) {
			z++;
			returnString = returnString + rawString.charAt(i);
			if (j == 2) {
				returnString = returnString + " ";
				j = 0;
			}
			j++;
			if (z == (numberPerRow * 2)) {
				returnString = returnString + "\n";
				z = 0;
			}
		}
		return returnString;
	}
	public static String printHexBinary(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}