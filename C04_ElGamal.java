package net.bplaced.javacrypto.asymmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 26.12.2018 
* Funktion: verschlüsselt einen Text mittels El Gamal (Asymmetrisch)
* Function: encrypts a text string using El Gamal (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C04_ElGamal {
	public static void main(String[] args) throws Exception {
		System.out.println("C04 El Gamal Verschlüsselung");

		// benötigt Bouncy Castle
		Security.addProvider(new BouncyCastleProvider());

		String plaintextString = "Das ist die geheime Nachricht";
		// String plaintextString ="12345678901234567890123456789012"; // max 32 byte
		byte[] plaintextByte = plaintextString.getBytes("utf-8");
		byte[] ciphertextByte = null;
		byte[] decryptedtextByte = null;

		// erzeugung eines schlüsselpaares
		KeyPairGenerator egGenerator = KeyPairGenerator.getInstance("ElGamal", "BC");
		SecureRandom random = new SecureRandom();
		egGenerator.initialize(2048, random);
		KeyPair egKeyPair = egGenerator.generateKeyPair();
		ElGamalPublicKey egPublicKey = (ElGamalPublicKey) egKeyPair.getPublic();
		ElGamalPrivateKey egPrivateKey = (ElGamalPrivateKey) egKeyPair.getPrivate();

		// verschlüsselung mit dem öffentlichen schlüssel
		ciphertextByte = EgEncrypt(plaintextByte, egPublicKey);
		// entschlüsselung mit dem privaten schlüssel
		decryptedtextByte = EgDecrypt(ciphertextByte, egPrivateKey);

		System.out.println();
		System.out.println("El Gamal Schlüsselerzeugung");
		System.out.println("egPrivateKey (Byte) Länge:" + egPrivateKey.getEncoded().length + " Bytes");
		System.out.println(byteArrayPrint(egPrivateKey.getEncoded(), 33));
		System.out.println("\negPublicKey (Byte)  Länge:" + egPublicKey.getEncoded().length + " Bytes");
		System.out.println(byteArrayPrint(egPublicKey.getEncoded(), 33));
		System.out.println();
		System.out.println("El Gamal Verschlüsselung");
		System.out.println("plaintextString    :" + plaintextString);
		System.out.println("plaintextByte      Länge:" + plaintextByte.length + " Bytes Data:"
				+ DatatypeConverter.printHexBinary(plaintextByte));
		System.out.println("ciphertextByte     Länge:" + ciphertextByte.length + " Bytes");
		System.out.println(byteArrayPrint(ciphertextByte, 33));
		System.out.println("decryptedtextByte  :" + DatatypeConverter.printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString:" + new String(decryptedtextByte));
		System.out.println();
	}

	public static byte[] EgEncrypt(byte[] plaintextByte, ElGamalPublicKey publicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		byte[] ciphertextByte = null;
		Cipher encryptCipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		ciphertextByte = encryptCipher.doFinal(plaintextByte);
		return ciphertextByte;
	}

	public static byte[] EgDecrypt(byte[] ciphertextByte, ElGamalPrivateKey privateKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException {
		byte[] decryptedtextByte = null;
		Cipher decryptCipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
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