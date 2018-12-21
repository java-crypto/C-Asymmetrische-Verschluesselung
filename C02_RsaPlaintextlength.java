package net.bplaced.javacrypto.asymmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 21.12.2018 
* Funktion: testet die maximale Klartextlänge beim RSA-Verfahren (Asymmetrisch)
* Function: checks for maximal allowed plaintextlength with RSA encryption (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
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
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class C02_RsaPlaintextlength {

	public static void main(String[] args)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("C02 RSA-Verschlüsselung mit Test der maximalen Klartextlänge");

		// erzeugung eines schlüsselpaares
		KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		// schlüssellänge von 512 bit ist unsicher * BITTE NICHT VERWENDEN *
		// keylength of 512 bit is not secure * DO NOT USE *
		rsaGenerator.initialize(512, random);
		KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
		PublicKey rsaPublicKey = rsaKeyPair.getPublic();
		PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
		System.out.println();
		System.out.println("Private und Public Key erzeugt");
		System.out.println("Private Key Länge:" + rsaPrivateKey.getEncoded().length);
		System.out.println("Public Key Länge :" + rsaPublicKey.getEncoded().length);

		// test mit einem 53 byte langen plaintext
		int plaintextLengthInt = 53;
		byte[] plaintextByte = generateRandomString(plaintextLengthInt).getBytes("utf-8");

		// verschlüsselung mit dem öffentlichen schlüssel
		System.out.println("\nVerschlüsselung mit einem Text der Länge " + plaintextLengthInt + " Zeichen");
		byte[] ciphertextByte = RsaEncrypt(plaintextByte, rsaPublicKey);
		// hier keine entschlüsselung

		// test mit einem 54 byte langen plaintext
		plaintextLengthInt = 54;
		plaintextByte = generateRandomString(plaintextLengthInt).getBytes("utf-8");
		// verschlüsselung mit dem öffentlichen schlüssel
		System.out.println("\nVerschlüsselung mit einem Text der Länge " + plaintextLengthInt + " Zeichen");
		ciphertextByte = RsaEncrypt(plaintextByte, rsaPublicKey);
		// an dieser stelle wird ein fehler erzeugt

		// übersicht über maximale schlüssellängen
		// bei 512 bit: Data must not be longer than 53 bytes
		// bei 1024 bit: Data must not be longer than 117 bytes
		// bei 2048 bit: Data must not be longer than 245 bytes
		// bei 4096 bit: Data must not be longer than 495 bytes
		// bei 9096 bit: Data must not be longer than 1126 bytes
	}

	public static byte[] RsaEncrypt(byte[] plaintextByte, PublicKey publicKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] ciphertextByte = null;
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		ciphertextByte = encryptCipher.doFinal(plaintextByte);
		return ciphertextByte;
	}

	public static String generateRandomString(int lengthInt) {
		int leftLimit = 97; // letter 'a'
		int rightLimit = 122; // letter 'z'
		int targetStringLength = lengthInt;
		Random random = new Random();
		StringBuilder buffer = new StringBuilder(targetStringLength);
		for (int i = 0; i < targetStringLength; i++) {
			int randomLimitedInt = leftLimit + (int) (random.nextFloat() * (rightLimit - leftLimit + 1));
			buffer.append((char) randomLimitedInt);
		}
		String generatedString = buffer.toString();
		return generatedString;
	}
}
