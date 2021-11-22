package encriptar_arxius;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class encriptacio {
	/*Declaració variabes*/
	static Scanner write = new Scanner(System.in);
	static int resposta;
	static String fichero;
	static File fitxer;
	static SecretKey key;
	static FileWriter fic;
	static FileReader fiR;

	public static void main(String[] args) throws IOException {
		
		/*Menú amb do-while perquè el repeteixi en cas d'error*/
		do {
			System.out.println("*****Aplicació ENCRIPTACIÓ FITXERS*****");
			System.out.println("");
			System.out.println("Elegeixi l'opció que desitja realitzar:");
			System.out.println("1. -Encriptar un document.");
			System.out.println("2. -Desencriptar un document.");
			System.out.println("3. -Salir");
			System.out.println("");
			System.out.print("Opció: ");
			
			resposta = write.nextInt();
			
			if (resposta<1 || resposta>3) {
				System.out.println("La opció seleccionada no es troba disponible, marqui un opció correcte.");
			}
		
		}while (resposta<1 || resposta>3);
		/*Switch per realitzar funcions segons l'opcio elegida*/
		switch (resposta) {
		
			case 1:
				
				/*Creem una contraseya amb la longitud desitjada*/
				key = keygenKeyGeneration(256);
				
				/*Passem la contrasenya a base64*/
				String clau = Base64.getEncoder().encodeToString(key.getEncoded());
				
				System.out.println("Ha seleccionat encriptar fitxer.");
				System.out.println("Quin  fitxer vol encriptar? (Escriu la ruta absoluta).");
				System.out.print("Fitxer: ");
				fichero = write.next();
				fitxer = new File(fichero);
				
				if (!fitxer.exists()) {
					System.out.println("ERROR: El fitxer seleccionat no existeix.");
					System.exit(0);
				}else {
					if (!fitxer.isFile()) {
						System.out.println("ERROR: El fitxer seleccionat correspon a un directori.");
						System.exit(0);
					}else {
				
						/*obtenim el nom del fitxer sense el (.) i extensio*/
						String nom = fitxer.getName();
						String [] parts = nom.split("\\.");
						String nombre = parts[0];
						
						/*Passem el fitxer a un array de bytes*/
						byte[] fitxer_bytes = Files.readAllBytes(fitxer.toPath());
						/*Xifrem el text*/
						byte[] textXifrat = encryptData(key, fitxer_bytes);
						/*Passem el text xifrat a un string en base64*/
						String text_xifrat = Base64.getEncoder().encodeToString(textXifrat);
						
						/*Creem la carpeta on guardarem la contrasenya i el text xifrat*/
						fitxer = new File ("Encriptacio_Desencriptacio\\encriptats\\"+nombre);
						
						if (!fitxer.exists()) {
							fitxer.mkdirs();
							
							/*Crearem un arxiu txt on guardarem la contrasenya*/
							File contrasenya = new File(fitxer+"\\contrasenya.txt");
							
							if (contrasenya.createNewFile()) {
								fic = new FileWriter(contrasenya);
								fic.write(clau);
								fic.close();
							}
							
							/*Crearem un arxiu txt on guardarem el fitxer xifrat*/
							File fitxer_xifrat = new File(fitxer+"\\fitxerXifrat.txt");
							
							if (fitxer_xifrat.createNewFile()) {
								fic = new FileWriter(fitxer_xifrat);
								fic.write(text_xifrat);
								fic.close();
							}
							System.out.println("");
							System.out.println("Fitxer encriptat correctament.");
						}else {
							System.out.println("");
							System.out.println("Aquest arxiu ja ha estat encriptat anteriorment.");
							System.exit(0);	
						}	
					}
				}
			break;
			case 2:
				
				System.out.println("Ha seleccionat desencriptar fitxer.");
				System.out.println("Quin  fitxer vol desencriptar? (Escriu la ruta absoluta).");
				System.out.print("Fitxer: ");
				fichero = write.next();
				fitxer = new File(fichero);
				
				if (!fitxer.exists()) {
					System.out.println("ERROR: El fitxer seleccionat no existeix.");
					System.exit(0);
				}else {
					if (!fitxer.isFile()) {
						System.out.println("ERROR: El fitxer seleccionat correspon a un directori.");
						System.exit(0);
					}else {
						
						/*obtenim el nom del fitxer sense el (.) i extensio*/
						String nom = fitxer.getName();
						String [] parts = nom.split("\\.");
						String nombre = parts[0];
						
						/*Posem la carpeta al servidor on guardem els textos xifrats*/
						fitxer = new File ("Encriptacio_Desencriptacio\\encriptats\\"+nombre);
						
						if (fitxer.exists()) {
							File contrasenya = new File(fitxer+"\\contrasenya.txt");
							File fitxer_xifrat = new File(fitxer+"\\fitxerXifrat.txt");
							
							/*Comprovem si existeixen fitxers per recuperar les dades*/
							if (contrasenya.exists() && fitxer_xifrat.exists()) {
								int i;
								String recuperar_contrasenya = "";
								String recuperar_xifrat = "";
								/*Recuperem la contrasenya*/
								fiR = new FileReader(contrasenya);
								while ((i = fiR.read()) != -1) {
									recuperar_contrasenya += (char)i;
								}
								/*Recuperem el text xifrat*/
								fiR = new FileReader(fitxer_xifrat);
								while ((i = fiR.read()) != -1) {
									recuperar_xifrat += (char)i;
								}
								
								/*Recuperem la contrasenya de String a tipus Key*/
								byte[] contra = Base64.getDecoder().decode((recuperar_contrasenya.getBytes()));
								SecretKey originalKey = new SecretKeySpec(contra, 0, contra.length, "AES");
								
								/*Recuperem el text xifrat de String a array de bytes*/
								byte[] texte_xifrat = Base64.getDecoder().decode((recuperar_xifrat.getBytes()));
								
								/*Desxifrar text*/
								byte[] textDesxifrat = desencryptData(originalKey, texte_xifrat);
								String text_desxifrat = new String (textDesxifrat);
								
								/*Crearem la carpeta on guardarem els fitxers desxifrats*/
								File desencriptats = new File("Encriptacio_Desencriptacio\\desencriptats\\"+nombre);
								
								if (!desencriptats.exists()) {
									desencriptats.mkdirs();
								}
								
								/*Crearem un arxiu txt on guardarem la clau publica d'aquest document*/
								File carpeta_des = new File(desencriptats+"\\txt_desxifrat.txt");
								
								if (!carpeta_des.exists()) {
									if (carpeta_des.createNewFile()) {
										fic = new FileWriter(carpeta_des);
										fic.write(text_desxifrat);
										fic.close();
									}
								}
								System.out.println("");
								System.out.println("Fitxer desencriptat correctament");
							}else {
								System.out.println("Aquest fitxer mai ha sigut encriptat, primer ha d'encriptar el fitxer.");
								System.exit(0);
							}
						}else {
							System.out.println("Aquest fitxer mai ha sigut encriptat, primer ha d'encriptar el fitxer.");
							System.exit(0);
						}
					}
				}
			break;
			case 3:
				System.out.println("Ha elegit sortir. Fins una altra");
				System.exit(0);
			break;
		}
	}
	//Metode generar clau encriptada des del tamany desitjat
	public static SecretKey keygenKeyGeneration(int keySize) {
		SecretKey sKey = null;
		if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
			try {
				KeyGenerator kgen = KeyGenerator.getInstance("AES");
				kgen.init(keySize);
				sKey = kgen.generateKey();

			} catch (NoSuchAlgorithmException ex) {
				System.err.println("Generador no disponible.");
			}
		}
		return sKey;
	}
	
	/*Metode XIFRAR fixer*/
	public static byte[] encryptData(SecretKey sKey, byte[] data) {
		byte[] encryptedData = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sKey);
			encryptedData = cipher.doFinal(data);
		} catch (Exception ex) {
			System.err.println("Error xifrant les dades: " + ex);
		}
		return encryptedData;
	}
	
	/*Metode DESXIFRAR fitxer*/
	public static byte[] desencryptData(SecretKey sKey, byte[] data) {
		byte[] decryptedData = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sKey);
			decryptedData = cipher.doFinal(data);
		} catch (Exception ex) {
			System.err.println("Error xifrant les dades: " + ex);
		}
		return decryptedData;
	}
}
