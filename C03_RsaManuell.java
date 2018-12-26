package net.bplaced.javacrypto.asymmetricencryption;

/* Basis dieses Programms ist eine Facharbeit, in der das Public Key-Verschlüsselungsverfahren RSA erläutert wird.
Leider ist die Seite im Internet nicht mehr verfügbar, auf meiner Webseite finden Sie den Scan der Arbeit.
Städtische Fachoberschule 1, Facharbeit aus der Mathematik
Thema: Das Public Key-Verschlüsselungsverfahren RSA am Beispiel PGP
Fachlehrer: Herr Gregor
Verfasser: Alexander Lignow
Klasse: 12 G
Abgabetermin: 24.02.1997
*/

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 26.12.2018 
* Funktion: manuelle RSA-Verschlüsselung (Asymmetrisch)
* Function: manual RSA-encryption (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;

public class C03_RsaManuell {

	// hinweis: die benennung der variablen erfolgt so nahe wie möglich an der
	// benennung in der facharbeit
	// diese variablen werden auch in den methoden benötigt
	static BigInteger zBig; // ergebnis von p*q
	static int divisorCountInt = 0; // anzahl der teiler in den methoden findDivisors und foundDivisors
	static BigInteger[] divisorBig = new BigInteger[10]; // gefundene teiler in den methoden findDivisors und
	static boolean verboseBool = true; // schalter für die ausgaben des programms:
	// true = nur sehr wenige ausgaben, false = sehr viele ausgaben

	public static void main(String[] args) {
		System.out.println("C03 RSA-Verfahren manuell mit Signatur");

		// kapitel 2.2
		System.out.println("\nKapitel 2.2 Erstellung von 3 Schlüsselpaaren");
		// erzeugung von 3 schlüsselpaaren für alice, bob und charlie, kurz A, B und C
		// schlüsselpaar für A alice
		int pInt = 3;
		int qInt = 11;
		// ab hier wird das schlüsselpaar berechnet
		int createRsaPairResultInt = 1; // 0 = exakt 2 teiler gefunden, 1 = ergebnis darf nicht verwendet werden
		createRsaPairResultInt = createRsaPair(pInt, qInt);
		if (createRsaPairResultInt == 1) {
			System.out.println("Die angegebenen Werte für p:" + pInt + " und q:" + qInt
					+ " ergeben keinen gültigen Schlüssel, das Programm wird beendet");
			System.exit(0);
		}
		// übernahme der werte aus der methode createRsaPair
		BigInteger publicAliceBig = divisorBig[3]; // d = öffentlicher schlüssel von a alice
		BigInteger privateAliceBig = divisorBig[2]; // e = privater schlüssel von a alice
		BigInteger zAliceBig = zBig; // z = modulus der schlüssel von a alice
		// ausgabe der werte
		System.out.println("Erzeuge ein Schlüsselpaar für A Alice   private:" + privateAliceBig + " public:"
				+ publicAliceBig + " z:" + zAliceBig);

		// schlüsselpaar für b bob
		pInt = 17;
		qInt = 3;
		// ab hier wird das schlüsselpaar berechnet
		createRsaPairResultInt = 1; // 0 = exakt 2 teiler gefunden, 1 = ergebnis darf nicht verwendet werden
		createRsaPairResultInt = createRsaPair(pInt, qInt);
		if (createRsaPairResultInt == 1) {
			System.out.println("Die angegebenen Werte für p:" + pInt + " und q:" + qInt
					+ " ergeben keinen gültigen Schlüssel, das Programm wird beendet");
			System.exit(0);
		}
		// übernahme der werte aus der methode createRsaPair
		BigInteger publicBobBig = divisorBig[3]; // d = öffentlicher schlüssel von b bob
		BigInteger privateBobBig = divisorBig[2]; // e = privater schlüssel von b bob
		BigInteger zBobBig = zBig; // z = modulus der schlüssel von b bob
		// ausgabe der werte
		System.out.println("Erzeuge ein Schlüsselpaar für B Bob     private:" + privateBobBig + " public:"
				+ publicBobBig + " z:" + zBobBig);

		// schlüsselpaar für c charlie
		pInt = 5;
		qInt = 17;
		// ab hier wird das schlüsselpaar berechnet
		createRsaPairResultInt = 1; // 0 = exakt 2 teiler gefunden, 1 = ergebnis darf nicht verwendet werden
		createRsaPairResultInt = createRsaPair(pInt, qInt);
		if (createRsaPairResultInt == 1) {
			System.out.println("Die angegebenen Werte für p:" + pInt + " und q:" + qInt
					+ " ergeben keinen gültigen Schlüssel, das Programm wird beendet");
			System.exit(0);
		}
		// übernahme der werte aus der methode createRsaPair
		BigInteger publicCharlieBig = divisorBig[3]; // d = öffentlicher schlüssel von b bob
		BigInteger privateCharlieBig = divisorBig[2]; // e = privater schlüssel von b bob
		BigInteger zCharlieBig = zBig; // z = modulus der schlüssel von b bob
		// ausgabe der werte
		System.out.println("Erzeuge ein Schlüsselpaar für C Charlie private:" + privateCharlieBig + " public:"
				+ publicCharlieBig + " z:" + zCharlieBig);

		// kapitel 3.1
		System.out.println("\nKapitel 3.1 Verschlüsselung einer Nachricht");
		// da die mathematischen routinen nicht mit sehr großen zahlen umgehen können
		// ersetzen wir die werte
		// tabelle mit werten
		// a = asc97 = 2
		// b = asc98 = 3
		// c = asc99 = 4
		// - = asc45 = 5
		// beispiel a - b = 2 5 3

		// variablen für die routinen
		byte[] plaintextByte = { 2, 5, 3 }; // unsere nachricht zur verschlüsselung
		// verschlüsselte nachricht
		BigInteger[] ciphertextBig = new BigInteger[3];
		// entschlüsselte nachricht
		BigInteger[] decryptedtextBig = new BigInteger[3];

		// senden der nachricht von alice an bob
		// alice verschlüsselt die nachricht mit dem public key von bob
		for (int i = 0; i < plaintextByte.length; i++) {
			ciphertextBig[i] = rsaEncryption(plaintextByte[i], publicBobBig, zBobBig);
		}
		System.out.println("Verschlüsselung des Textes a-b mit dem PublicKey von Bob");
		System.out.println("Klartext      :" + DatatypeConverter.printByte(plaintextByte[0]) + "  "
				+ DatatypeConverter.printByte(plaintextByte[1]) + "  " + DatatypeConverter.printByte(plaintextByte[2]));
		System.out.println("Verschlüsselt :" + DatatypeConverter.printInteger(ciphertextBig[0]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig[1]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig[2]));
		// die verschlüsselte nachricht wird an bob gesendet
		// bob entschlüsselt die nachricht mit seinem private key
		for (int i = 0; i < ciphertextBig.length; i++) {
			BigInteger ciphertextSingleBig = ciphertextBig[i];
			BigInteger decryptedtextSingleBig = rsaDecryption(ciphertextSingleBig, privateBobBig, zBobBig);
			decryptedtextBig[i] = decryptedtextSingleBig;
		}
		System.out.println("\nEntschlüsselung des Textes a-b mit dem PrivateKey von Bob");
		System.out.println("Verschlüsselt :" + DatatypeConverter.printInteger(ciphertextBig[0]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig[1]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig[2]));
		System.out.println("Entschlüsselt :" + DatatypeConverter.printInteger(decryptedtextBig[0]) + "  "
				+ DatatypeConverter.printInteger(decryptedtextBig[1]) + "  "
				+ DatatypeConverter.printInteger(decryptedtextBig[2]));

		// kapitel 3.3
		System.out.println("\nKapitel 3.3 Verschlüsselung mit Signatur eines Klartextes");
		// nun wird eine nachricht von b bob an a alice geschickt
		// zusätzlich wird ein unterschriftswert mitgeschickt
		// beispiel b - a = 3 5 2 6
		// variablen für die routinen
		byte[] plaintextByte2 = { 3, 5, 2, 6 }; // unsere nachricht zur verschlüsselung
		// verschlüsselte nachricht
		BigInteger[] ciphertextBig2 = new BigInteger[4];
		// entschlüsselte nachricht
		BigInteger[] decryptedtextBig2 = new BigInteger[4];
		// senden der nachricht von bob an alice
		// bob verschlüsselt die nachricht mit dem public key von alice
		for (int i = 0; i < plaintextByte2.length; i++) {
			ciphertextBig2[i] = rsaEncryption(plaintextByte2[i], publicAliceBig, zAliceBig);
		}
		System.out.println("Verschlüsselung des Textes b-a mit dem PublicKey von Alice");
		System.out.println("Klartext      :" + DatatypeConverter.printByte(plaintextByte2[0]) + "  "
				+ DatatypeConverter.printByte(plaintextByte2[1]) + "  " + DatatypeConverter.printByte(plaintextByte2[2])
				+ "  " + DatatypeConverter.printByte(plaintextByte2[3]));
		System.out.println("Verschlüsselt :" + DatatypeConverter.printInteger(ciphertextBig2[0]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig2[1]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig2[2]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig2[3]));
		// die verschlüsselte nachricht wird an alice gesendet
		// alice entschlüsselt die nachricht mit ihrem private key
		for (int i = 0; i < ciphertextBig2.length; i++) {
			BigInteger ciphertextSingleBig2 = ciphertextBig2[i];
			BigInteger decryptedtextSingleBig2 = rsaDecryption(ciphertextSingleBig2, privateAliceBig, zAliceBig);
			decryptedtextBig2[i] = decryptedtextSingleBig2;
		}
		System.out.println("\nEntschlüsselung des Textes b-a mit dem PrivateKey von Alice");
		System.out.println("Verschlüsselt :" + DatatypeConverter.printInteger(ciphertextBig2[0]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig2[1]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig2[2]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig2[3]));
		System.out.println("Entschlüsselt :" + DatatypeConverter.printInteger(decryptedtextBig2[0]) + "  "
				+ DatatypeConverter.printInteger(decryptedtextBig2[1]) + "  "
				+ DatatypeConverter.printInteger(decryptedtextBig2[2]) + "  "
				+ DatatypeConverter.printInteger(decryptedtextBig2[3]));

		// kapitel 3.4
		System.out.println("\nKapitel 3.4 Eine dritte Person fängt eine verschlüsselte Nachricht ab");
		// nun wird eine nachricht von b bob an a alice geschickt
		// zusätzlich wird ein unterschriftswert mitgeschickt
		// beispiel b - a = 3 5 2 6
		// variablen für die routinen
		byte[] plaintextByte3 = { 3, 5, 2, 6 }; // unsere nachricht zur verschlüsselung
		// verschlüsselte nachricht
		BigInteger[] ciphertextBig3 = new BigInteger[4];
		// entschlüsselte nachricht
		BigInteger[] decryptedtextBig3 = new BigInteger[4];
		// senden der nachricht von bob an alice
		// bob verschlüsselt die nachricht mit dem public key von alice
		for (int i = 0; i < plaintextByte3.length; i++) {
			ciphertextBig3[i] = rsaEncryption(plaintextByte3[i], publicAliceBig, zAliceBig);
		}
		System.out.println("Verschlüsselung des Textes b-a mit dem PublicKey von Alice");
		System.out.println("Klartext      :" + DatatypeConverter.printByte(plaintextByte3[0]) + "  "
				+ DatatypeConverter.printByte(plaintextByte3[1]) + "  " + DatatypeConverter.printByte(plaintextByte3[2])
				+ "  " + DatatypeConverter.printByte(plaintextByte3[3]));
		System.out.println("Verschlüsselt :" + DatatypeConverter.printInteger(ciphertextBig3[0]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig3[1]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig3[2]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig3[3]));
		// die verschlüsselte nachricht wird an alice gesendet, aber von charlie
		// abgefangen
		// charlie entschlüsselt die nachricht mit seinem private key
		for (int i = 0; i < ciphertextBig3.length; i++) {
			BigInteger ciphertextSingleBig3 = ciphertextBig3[i];
			BigInteger decryptedtextSingleBig3 = rsaDecryption(ciphertextSingleBig3, privateCharlieBig, zCharlieBig);
			decryptedtextBig3[i] = decryptedtextSingleBig3;
		}
		System.out.println("\nEntschlüsselung des Textes b-a mit dem PrivateKey von Charlie");
		System.out.println("Verschlüsselt :" + DatatypeConverter.printInteger(ciphertextBig3[0]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig3[1]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig3[2]) + " "
				+ DatatypeConverter.printInteger(ciphertextBig3[3]));
		System.out.println("Entschlüsselt:" + DatatypeConverter.printInteger(decryptedtextBig3[0]) + " "
				+ DatatypeConverter.printInteger(decryptedtextBig3[1]) + " "
				+ DatatypeConverter.printInteger(decryptedtextBig3[2]) + " "
				+ DatatypeConverter.printInteger(decryptedtextBig3[3]));
		System.out.println("Hinweis: hier kommt es zu einer Abweichung zur Facharbeit !");

		System.out.println("\nC03 RSA-Verfahren manuell mit Signatur beendet");
	}

	public static void findDivisors(BigInteger num) {
		BigInteger limit = num;
		BigInteger counter = BigInteger.ONE;
		while (counter.compareTo(limit) < 0) {
			if (num.mod(counter).compareTo(BigInteger.ZERO) == 0) {
				foundDivisors(counter);
				BigInteger partner = num.divide(counter);
				foundDivisors(partner);
				limit = partner; // shorten the loop
			}
			counter = counter.add(BigInteger.ONE);
		}
	}

	public static void foundDivisors(BigInteger divisor) {
		divisorBig[divisorCountInt] = divisor;
		// ein treffer erhöht den zähler
		divisorCountInt++;
		if (verboseBool == false) {
			System.out.println("Teiler:" + divisor);
		}
	}

	public static int createRsaPair(int pInt, int qInt) {
		int resultInt = 1; // 0 = genau 2 teiler gefunden 1 = mehr oder weniger teiler gefunden, falsch
		if (verboseBool == false) {
			System.out.println("createRSA Keypair p:" + pInt + " q:" + qInt);
		}
		BigInteger pBig = BigInteger.valueOf(pInt);
		BigInteger qBig = BigInteger.valueOf(qInt);
		// z ermitteln als p * q
		BigInteger zInternBig = pBig.multiply(qBig);
		zBig = zInternBig; // übergabe an die Hauptroutine
		if (verboseBool == false) {
			System.out.println("zInternBig:" + zInternBig);
		}
		// phi(z) ermitteln als (p-1) * (q-1)
		// phizA = (pA - 1) * (qA - 1);
		BigInteger einsBig = new BigInteger("1");
		BigInteger phizBig = pBig.subtract(einsBig).multiply(qBig.subtract(einsBig));
		if (verboseBool == false) {
			System.out.println("phi(z):" + phizBig);
		}
		// phi(z) + 1 errechnen
		BigInteger phizPeBig = phizBig.add(einsBig);
		if (verboseBool == false) {
			System.out.println("phi(z)+1:" + phizPeBig);
		}
		// suche nach dem teiler von phizPeAbig
		if (verboseBool == false) {
			System.out.print("Teiler von " + phizPeBig + ": ");
		}
		if (verboseBool == false) {
			System.out.println();
		}
		// anzahl teiler auf null setzen
		divisorCountInt = 0;
		findDivisors(phizPeBig);
		if (verboseBool == false) {
			System.out.println("Anzahl Teiler (gewünscht: exakt 4):" + divisorCountInt);
		}
		if (divisorCountInt == 4) {
			// es ist die richtige anzahl teiler, aber sind sie auch unterschiedlich ?
			if ((divisorBig[2]) != (divisorBig[3])) {
				resultInt = 0;
				if (verboseBool == false) {
					System.out.println("gefundene Teiler ohne Start und Ende:" + divisorBig[2] + "+" + divisorBig[3]);
				}
			}
		}
		if (verboseBool == false) {
			System.out.println("= = = fertig = = =");
		}
		return resultInt;
	}

	public static BigInteger rsaEncryption(int plaintextInt, BigInteger publicKeyBig, BigInteger zBig) {
		BigInteger ThochPublicKeyModZBig = BigInteger.valueOf(plaintextInt).modPow(publicKeyBig, zBig);
		if (verboseBool == false) {
			System.out.println("ThochPublicKeyModZBig(" + plaintextInt + "):" + ThochPublicKeyModZBig);
		}
		return ThochPublicKeyModZBig;
	}

	public static BigInteger rsaDecryption(BigInteger ciphertextBig, BigInteger privateKeyBig, BigInteger zBig) {
		BigInteger ThochPrivateKeyModZBig = ciphertextBig.modPow(privateKeyBig, zBig);
		if (verboseBool == false) {
			System.out.println("ThochPrivateKeyModZBig(" + ciphertextBig + "):" + ThochPrivateKeyModZBig);
		}
		return ThochPrivateKeyModZBig;
	}

	public static BigInteger rsaSignature(int plaintextInt, BigInteger privateKeyBig, BigInteger zBig) {
		BigInteger ThochPrivateKeyModZBig = BigInteger.valueOf(plaintextInt).modPow(privateKeyBig, zBig);
		if (verboseBool == false) {
			System.out.println("ThochPrivateKeyModZBig(" + plaintextInt + "):" + ThochPrivateKeyModZBig);
		}
		return ThochPrivateKeyModZBig;
	}

	public static BigInteger rsaVerification(BigInteger signatureBig, BigInteger publicKeyBig, BigInteger zBig) {
		BigInteger ThochPublicKeyModZBig = signatureBig.modPow(publicKeyBig, zBig);
		if (verboseBool == false) {
			System.out.println("ThochublicKeyModZBig(" + signatureBig + "):" + ThochPublicKeyModZBig);
		}
		return ThochPublicKeyModZBig;
	}

	public static Boolean rsaVerificationCheck(BigInteger[] decryptedtextBig, BigInteger[] verificationBig) {
		// rückgabe true = arrays sind gleich, false = arrays sind nicht gleich
		boolean arraysGleich = false;
		int arrayDecryptedtextLengthInt = decryptedtextBig.length;
		int arrayVerificationLengthInt = verificationBig.length;
		if (arrayDecryptedtextLengthInt == arrayVerificationLengthInt) {
			boolean arraysSingleGleich = true;
			if (verboseBool == false) {
				System.out.println("Decryption + Verification Länge gleich");
			}
			int res; // für späteren BigInteger-Vergleich
			for (int i = 0; i < arrayDecryptedtextLengthInt; i++) {
				if (verboseBool == false) {
					System.out.println("i:" + i + " decryptedtextBig[i]" + decryptedtextBig[i] + " verificationBig[i]:"
							+ verificationBig[i]);
				}
				res = decryptedtextBig[i].compareTo(verificationBig[i]);
				if (res != 0) {
					arraysSingleGleich = false;
				}
				arraysGleich = arraysSingleGleich;
			}
		}
		return arraysGleich;
	}
}
