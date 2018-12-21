package net.bplaced.javacrypto.asymmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 21.12.2018 
* Funktion: verschl�sselt einen Text mittels RSA (Asymmetrisch)
* Function: encrypts a text string using RSA (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Pr�fen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class C01_Rsa {

	public static void main(String[] args)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("C01 RSA Verschl�sselung mit einem String");

		String plaintextString = "Das ist die geheime Nachricht.";
		byte[] plaintextByte = plaintextString.getBytes("utf-8");
		byte[] ciphertextByte = null;
		byte[] decryptedtextByte = null;

		// erzeugung eines schl�sselpaares
		KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		// schl�ssell�nge von 512 bit ist unsicher * BITTE NICHT VERWENDEN *
		// keylength of 512 bit is not secure * DO NOT USE *
		rsaGenerator.initialize(512, random);
		KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
		PublicKey rsaPublicKey = rsaKeyPair.getPublic();
		PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();

		// verschl�sselung mit dem �ffentlichen schl�ssel
		ciphertextByte = RsaEncrypt(plaintextByte, rsaPublicKey);
		// entschl�sselung mit dem privaten schl�ssel
		decryptedtextByte = RsaDecrypt(ciphertextByte, rsaPrivateKey);

		System.out.println();
		System.out.println("RSA Schl�sselerzeugung");
		System.out.println("rsaPrivateKey (Byte) L�nge:" + rsaPrivateKey.getEncoded().length + " Bytes");
		System.out.println(byteArrayPrint(rsaPrivateKey.getEncoded(), 33));
		System.out.println("rsaPublicKey (Byte)  L�nge:" + rsaPublicKey.getEncoded().length + " Bytes");
		System.out.println(byteArrayPrint(rsaPublicKey.getEncoded(), 33));
		System.out.println();
		System.out.println("RSA Verschl�sselung");
		System.out.println("plaintextString    :" + plaintextString);
		System.out.println("plaintextByte      :" + DatatypeConverter.printHexBinary(plaintextByte));
		System.out.println("ciphertextByte     :");
		System.out.println(byteArrayPrint(ciphertextByte,33));
		System.out.println("decryptedtextByte  :" + DatatypeConverter.printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString:" + new String(decryptedtextByte));
		System.out.println();
	}

	public static byte[] RsaEncrypt(byte[] plaintextByte, PublicKey publicKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] ciphertextByte = null;
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		ciphertextByte = encryptCipher.doFinal(plaintextByte);
		return ciphertextByte;
	}

	public static byte[] RsaDecrypt(byte[] ciphertextByte, PrivateKey privateKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] decryptedtextByte = null;
		Cipher decryptCipher = Cipher.getInstance("RSA");
		decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
		decryptedtextByte = decryptCipher.doFinal(ciphertextByte);
		return decryptedtextByte;
	}

	public static String byteArrayPrint(byte[] byteData, int numberPerRow) {
		String returnString = "";
		String rawString = DatatypeConverter.printHexBinary(byteData);
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
}
