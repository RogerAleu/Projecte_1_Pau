package M9_firma_digital;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class firmar_documents {
	
	static Scanner write = new Scanner(System.in);
	static FileWriter fic;
	static FileReader ficR;

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		File fitxer = new File("");
		int resposta;
		String fichero;
		
		do {
			System.out.println("*****Aplicació FIRMA DIGITAL*****");
			System.out.println("");
			System.out.println("Elegeixi l'opció que desitja realitzar:");
			System.out.println("1. -Firmar digitalment el document.");
			System.out.println("2. -Confirmar firma digital.");
			System.out.println("3. -Salir");
			System.out.println("");
			System.out.print("Opció: ");
			
			resposta = write.nextInt();
			
			if (resposta<1 || resposta>3) {
				System.out.println("La opció seleccionada no es troba disponible, marqui un opció correcte.");
			}
		
		}while (resposta<1 || resposta>3);
		
		switch (resposta) {
		
			case 1:
				
				KeyPair claus;
				// Genera dos claus en una mateixa variables
				claus = randomGenerate(2048);
				
				//Guardem les claus pública/privada en una PrivateKey
				PrivateKey privada = claus.getPrivate();
				PublicKey publica = claus.getPublic();
				
				/*Guardem la clau publica en Base64 per guardarla i utilitzarla despres*/
				String clau_publica = Base64.getEncoder().encodeToString(publica.getEncoded());
				
				System.out.println("");
				System.out.println("Quin document desitja firmar? (Escriu la ruta absoluta).");
				System.out.print("Fitxer: ");
				fichero = write.next();
				fitxer = new File(fichero);
				
				String nom = fitxer.getName();
				String [] parts = nom.split("\\.");
				String nombre = parts[0];
				
				if (!fitxer.exists()) {
					System.out.println("ERROR: El fitxer seleccionat no existeix.");
					System.exit(0);
				}else {
					if (!fitxer.isFile()) {
						System.out.println("ERROR: El fitxer seleccionat correspon a un directori.");
						System.exit(0);
					}else {
						
						/*Creem la carpeta on guaardarem la clau publica del fitxer*/
						File carpeta = new File("Firmes_digitals\\"+nombre);
						if (!carpeta.exists()) {
							carpeta.mkdirs();
							
							/*Crearem un arxiu txt on guardarem la clau publica d'aquest document*/
							File clau_pub = new File(carpeta+"\\clau_publica.txt");
							
							if (clau_pub.createNewFile()) {
								fic = new FileWriter(clau_pub);
								fic.write(clau_publica);
								fic.close();
							}	
							
							/*Passem el fitxer a un array de bytes*/
							byte[] fitxer_bytes = Files.readAllBytes(fitxer.toPath());
							/*Realitzem la firma del document*/
							byte [] firmaDocument = signData(fitxer_bytes, privada);
							/*Passem la firma del document de array de bytes a String*/
							String firma_document = Base64.getEncoder().encodeToString(firmaDocument);
							
							/*Creem un fitxer de text on guardem la firma digital del document*/
							File document_firmat = new File(carpeta+"\\firma_document.txt");
							
							if (document_firmat.createNewFile()) {
								fic = new FileWriter(document_firmat);
								fic.write(firma_document);
								fic.close();
							}	
							System.out.println("");
							System.out.println("Document firmat correctament.");
							
						}else {
							System.out.println("");
							System.out.println("Aquest arxiu ja ha sigut signat digitalment, ja que la carpeta ja existeix.");
						}		
					}
				}
				
			break;
			case 2:
				System.out.println("Quin document vol confirmar que està firamt correctament? (Escriu la ruta absoluta).");
				System.out.print("Fitxer: ");
				fichero = write.next();
				fitxer = new File(fichero);
				
				String nom_arxiu = fitxer.getName();
				String [] parts_arxiu = nom_arxiu.split("\\.");
				String nombre_arxiu = parts_arxiu[0];
				
				if (!fitxer.exists()) {
					System.out.println("ERROR: El fitxer seleccionat no existeix.");
					System.exit(0);
				}else {
					if (!fitxer.isFile()) {
						System.out.println("ERROR: El fitxer seleccionat correspon a un directori.");
						System.exit(0);
					}else {
						
						/*Busquem la carpeta creada del document amb la seva firma i signatura*/
						File clau_pub = new File("Firmes_digitals\\"+nombre_arxiu+"\\clau_publica.txt");
						File document_firmat = new File("Firmes_digitals\\"+nombre_arxiu+"\\firma_document.txt");
						
						if (!clau_pub.exists() || !document_firmat.exists()) {
							System.out.println("ERROR: El fitxer seleccionat no ha estat firmat en cap moment.");
							System.exit(0);
						} else {
							
							/*Passem el fitxer a un array de bytes*/
							byte[] fitxer_bytes = Files.readAllBytes(fitxer.toPath());
							
							String recuperar_clau = "";
							String signatura = "";
							int i;
							
							/*Recuperar la clau pública*/
							ficR = new FileReader(clau_pub);
							while ((i = ficR.read()) != -1) {
								recuperar_clau += (char)i;
							}
							/*Generar la clua publica a partir del Strin guardat*/
							byte[] publicBytes = Base64.getDecoder().decode((recuperar_clau.getBytes()));
							X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
							KeyFactory keyFactory = KeyFactory.getInstance("RSA");
							PublicKey pubKey = keyFactory.generatePublic(keySpec);
							
							/*Recuperar la signatura del document*/
							ficR = new FileReader(document_firmat);
							while ((i = ficR.read()) != -1) {
								signatura += (char)i;
							}
							/*Recuperem la signatura de String a array de bytes*/
							byte[] sign_document = Base64.getDecoder().decode((signatura.getBytes()));
							
							//validem que el document estigui firmat correctament
							boolean firmaCorrecta = validateSignature(fitxer_bytes, sign_document, pubKey);
							
							if(firmaCorrecta) {
								System.out.println("");
								System.out.println("El document ha estat firmat correctament.");
								System.exit(0);
							}else {
								System.out.println("");
								System.out.println("ERROR: no s'ha pogut verificar si el document ha estat firmat correctament.");
								System.exit(0);
							}
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
	
	//Generar les dos claus, PUBLICA i PRIVADA per poder firmar el document
	public static KeyPair randomGenerate(int len) {
		 KeyPair keys = null;
		 try {
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		 keyGen.initialize(len);
		 keys = keyGen.genKeyPair();
		 } catch (Exception ex) {
		 System.err.println("Generador no disponible.");
		 }
		 return keys;
	}

	
	//Metode generacio de firma digital a partir de la clau privada
	public static byte[] signData(byte[] data, PrivateKey priv) {
		byte[] signature = null;

		try {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(priv);
			signer.update(data);
			signature = signer.sign();
		} catch (Exception ex) {
			System.err.println("Error signant les dades: " + ex);
		}
		return signature;
	}
	
	//Metode de validacio firma digital a partir de la clau publica
	public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub)
	{
		boolean isValid = false;
		try {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initVerify(pub);
			signer.update(data);
			isValid = signer.verify(signature);
		} catch (Exception ex) {
			System.err.println("Error validant les dades: " + ex);
		}
		return isValid;
	}

}